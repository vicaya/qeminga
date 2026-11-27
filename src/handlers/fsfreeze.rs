//! `guest-fsfreeze-freeze`, `guest-fsfreeze-freeze-list`,
//! `guest-fsfreeze-thaw`, `guest-fsfreeze-status` (design §3, §4.2, §4.4;
//! AC2, AC9, AC10, AC17; OQ-3; C-12).
//!
//! # Freeze
//!
//! 1. Claim `Thawed → Freezing` (a token proves ownership).
//! 2. [`FreezeHooks::on_freezing`] (T3.6 switches audit output to the
//!    freeze-safe ring here; synchronous, no I/O).
//! 3. Start a freeze *operation* (`crate::freeze_op`), which owns the walk
//!    independently of the request: it builds the plan from `mountinfo`
//!    and creates the recovery marker (`O_EXCL` + `fsync`) on a tracked
//!    blocking task (marker failure → no ioctl at all), then for each
//!    target in reverse mount order opens it on its planned device (the
//!    first of its mount points that still leads there; the kernel shim
//!    verifies the descriptor) and issues `FIFREEZE` on a tracked blocking
//!    task of its own, publishing the handle to the [`Context`] before the
//!    next target is authorised.
//!    - `EOPNOTSUPP`: skipped, not counted, not rolled back.
//!    - `EBUSY`: not counted, but its handle is kept for rollback/thaw.
//!    - any other errno, or no mount point leading to the target: hard
//!      error → every published handle is drained in forward order, then
//!      the marker is removed.
//!    - the operation deadline expires, or a thaw is requested, while a
//!      `FIFREEZE` is in flight: the abort commits once (`Freezing →
//!      Thawing`), the request gets its one error reply, the published
//!      handles are drained on independent capacity, and the operation
//!      settles only once the in-flight call has returned and its result
//!      (a late success is drained too) is accounted for (§4.4).
//!
//!    The handles of the frozen targets are held in the [`Context`] until
//!    their drain completes: a handle names the filesystem it was opened
//!    on, whatever its pathnames lead to later.
//! 4. Success: `Freezing → Frozen`, [`FreezeHooks::on_frozen`] (T3.5 arms
//!    the watchdog). Failure: `Freezing → Thawed`,
//!    [`FreezeHooks::on_thawed`]. Nothing frozen and nothing held (an
//!    empty or entirely skipped plan): the marker is removed and the
//!    operation settles `Freezing → Thawed` with the reply `0`; there is
//!    nothing to recover, so no watchdog and no closed gate (#43 §2). An aborted operation ends in `Thawed`
//!    (everything drained, marker removed) or `Frozen` (a drain incomplete
//!    or the marker retained; the watchdog is armed).
//!
//! # Thaw
//!
//! `claim_thaw` (from `Frozen`, or from `Thawed` as a recovery drain;
//! during an unresolved freeze operation the thaw joins that operation
//! instead, see [`thaw`]), [`FreezeHooks::on_thaw_claimed`] (T3.5 cancels
//! the watchdog), then on
//! the blocking pool: rebuild the plan and, for every target in forward
//! order, issue `FITHAW` until it fails, counting the target once when at
//! least one call succeeded; the marker is removed only after every
//! drain. A target is drained through the handle its freeze opened when
//! this process holds one, otherwise (recovery after a restart) through
//! the first of its mount points that still opens on its device. The
//! held handles are drained even when the mount table cannot be read
//! (`EMFILE`, possibly caused by those very handles): discovery is not a
//! prerequisite of the drain, only of a complete recovery. Any drain
//! that does not end on the kernel's "not frozen" answer, a target that
//! cannot be reached, a mount table that could not be read, or a marker
//! removal failure is unrecoverable (OQ-3): `Thawing → Frozen`, marker
//! kept. Otherwise `Thawing → Thawed` and [`FreezeHooks::on_thawed`]
//! (T3.6 flushes the ring).
//!
//! The state mutex is never held across an `.await`; all ioctls run under
//! `spawn_blocking`.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dispatch::{Context, HeldMount, ThawScope};
use crate::freeze_plan::{FreezePlan, Target, filter_freeze_selection};
use crate::handlers::NoArgs;
use crate::kernel::{KernelError, KernelOps, Mount};
use crate::marker::{Marker, MarkerError};
use crate::mountinfo::MountSource;
use crate::ownership::{OwnershipError, OwnershipSnapshot, OwnershipStore, TargetOwnership};
use crate::proto::{Error, Request, arguments};
use crate::state::{FreezeState, ThawToken};
use crate::watchdog::{ThawFn, Watchdog, WatchdogConfig};

/// Defensive upper bound on `FITHAW` calls per mountpoint in one drain.
pub const MAX_THAW_ITERATIONS: u32 = 1024;

/// Lifecycle callbacks around the freeze state transitions. The default
/// implementation does nothing; later tasks plug in the audit ring (T3.6)
/// and the watchdog (T3.5).
pub trait FreezeHooks: Send + Sync {
    /// After `Thawed → Freezing`, before the marker and the first ioctl.
    /// Must be synchronous and free of I/O.
    fn on_freezing(&self, _ctx: &Arc<Context>) {}
    /// After `Freezing → Frozen`.
    fn on_frozen(&self, _ctx: &Arc<Context>) {}
    /// After a successful `claim_thaw`, before the drain starts.
    fn on_thaw_claimed(&self, _ctx: &Arc<Context>) {}
    /// After the drain (thaw success or freeze rollback) and *before* the
    /// state is published as `Thawed`: it runs in `Thawing` (or
    /// `Freezing`), while the gate still refuses a new freeze. A
    /// finalisation such as the audit flush therefore can never overlap,
    /// or undo, the setup of a newer freeze window.
    fn on_thawed(&self, _ctx: &Arc<Context>) {}
    /// A `guest-fsfreeze-status` heartbeat received while `Frozen`.
    fn on_heartbeat(&self, _ctx: &Arc<Context>) {}
}

/// Hooks that do nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHooks;

impl FreezeHooks for NoHooks {}

/// The production hooks: switch audit output to the freeze-safe ring on
/// `Freezing` and flush it back on `Thawed` (§9.1, AC13); arm the watchdog
/// on `Frozen`, cancel it when a thaw is claimed, refresh it on heartbeats
/// (§4.4).
#[derive(Debug, Default, Clone, Copy)]
pub struct LifecycleHooks;

impl FreezeHooks for LifecycleHooks {
    fn on_freezing(&self, ctx: &Arc<Context>) {
        // Synchronous and free of I/O: from here until `on_thawed` no
        // descriptor that might reach a frozen filesystem is written.
        ctx.audit.enter_ring();
    }

    fn on_thawed(&self, ctx: &Arc<Context>) {
        let lost = ctx.audit.flush_to_normal();
        if lost > 0 {
            tracing::warn!(
                event = "audit_ring_overflowed",
                lost,
                "audit records were dropped during the freeze window"
            );
        }
    }

    fn on_frozen(&self, ctx: &Arc<Context>) {
        let cfg = WatchdogConfig::from(&ctx.config.agent);
        let weak = Arc::downgrade(ctx);
        let thaw: ThawFn = Arc::new(move |token: ThawToken| {
            let weak = weak.clone();
            Box::pin(async move {
                // The context is gone only at shutdown; there is nothing
                // left to drain on behalf of.
                if let Some(ctx) = weak.upgrade() {
                    let _ = run_thaw(&ctx, token).await;
                }
            })
        });
        let handle = Watchdog::arm(cfg, Arc::clone(&ctx.state), thaw);
        if let Some(previous) = ctx.watchdog_slot().replace(handle) {
            previous.cancel();
        }
    }

    fn on_thaw_claimed(&self, ctx: &Arc<Context>) {
        if let Some(handle) = ctx.watchdog_slot().take() {
            handle.cancel();
        }
    }

    fn on_heartbeat(&self, ctx: &Arc<Context>) {
        if let Some(handle) = ctx.watchdog_slot().as_ref() {
            handle.refresh();
        }
    }
}

/// Recovery-mode startup (§4.4, C-14): called by `main` when the recovery
/// marker is present. The state machine must already be `Frozen`; audit
/// output goes to the ring until a thaw succeeds, and the watchdog is
/// armed immediately so an abandoned freeze is still bounded after a
/// crash. Returns an error if the state is not `Frozen`.
pub fn start_recovery(ctx: &Arc<Context>) -> Result<(), Error> {
    if ctx.state.current() != FreezeState::Frozen {
        return Err(Error::Internal(format!(
            "recovery startup requires the Frozen state, found {}",
            ctx.state.current()
        )));
    }
    ctx.hooks.on_freezing(ctx);
    ctx.hooks.on_frozen(ctx);
    tracing::warn!(
        event = "recovery_mode",
        marker = %ctx.marker.path().display(),
        "recovery marker present; starting frozen until a thaw succeeds"
    );
    Ok(())
}

/// Arguments of `guest-fsfreeze-freeze-list`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreezeListArgs {
    /// Mount points to restrict the plan to; absent means the whole plan.
    #[serde(default)]
    pub mountpoints: Option<Vec<String>>,
}

/// `guest-fsfreeze-status`: `"frozen"` whenever the state is not `Thawed`
/// (C-7); refreshes the watchdog only while `Frozen`.
pub async fn status(ctx: &Arc<Context>, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    let state = ctx.state.current();
    if state == FreezeState::Frozen {
        ctx.hooks.on_heartbeat(ctx);
    }
    Ok(json!(if state.is_frozen_for_gate() {
        "frozen"
    } else {
        "thawed"
    }))
}

/// `guest-fsfreeze-freeze`: freezes the whole plan.
pub async fn freeze(ctx: &Arc<Context>, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    run_freeze(ctx, None).await
}

/// `guest-fsfreeze-freeze-list`: freezes the plan restricted to the
/// requested mount points (C-12).
pub async fn freeze_list(ctx: &Arc<Context>, req: &Request) -> Result<Value, Error> {
    let args: FreezeListArgs = arguments(req)?;
    run_freeze(ctx, args.mountpoints).await
}

/// `guest-fsfreeze-thaw`: drains every planned filesystem. While a freeze
/// operation is unresolved (`Freezing`, or the recovery of an aborted one),
/// the thaw joins it instead of starting a drain of its own: it requests
/// the abort, waits for the recovery pass over the targets frozen so far,
/// and reports the operation's outcome (§4.4). No target is ever drained
/// by two owners.
pub async fn thaw(ctx: &Arc<Context>, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    let token = match ctx.state.claim_thaw() {
        Ok(token) => token,
        Err(err) => match ctx.freeze_op() {
            Some(op) => return join_operation(ctx, &op).await,
            // The operation may have settled between the claim and the
            // look-up: one more claim before refusing.
            None => ctx
                .state
                .claim_thaw()
                .map_err(|_| Error::Internal(format!("cannot thaw: {err}")))?,
        },
    };
    let count = run_thaw(ctx, token).await?;
    Ok(json!(count))
}

/// A thaw that joins the freeze operation in progress: it requests the
/// abort and is answered at once, conservatively, from the operation's
/// current progress. It never waits for the recovery (a blocked `FITHAW`
/// would hold the session with it) and never reports a complete thaw
/// while the operation can still freeze a target: the host learns the
/// outcome from `guest-fsfreeze-status`, which answers `frozen` until the
/// operation has settled `Thawed`.
///
/// The request and the operation's own commit compete on one transition:
/// when the operation had already committed (a freeze that succeeded a
/// moment ago, or a settlement of its own), nothing is aborted, the
/// operation's settlement is awaited (the driver is past every blocking
/// call by then) and the thaw takes the ordinary path from the published
/// state, so a thaw is never told "recovery pending" by an operation that
/// then publishes a successful `Frozen`.
async fn join_operation(
    ctx: &Arc<Context>,
    op: &crate::freeze_op::FreezeOp,
) -> Result<Value, Error> {
    if op.request_abort() == crate::freeze_op::AbortRequest::Committed {
        op.wait_for_settlement().await;
        let token = ctx
            .state
            .claim_thaw()
            .map_err(|err| Error::Internal(format!("cannot thaw: {err}")))?;
        let count = run_thaw(ctx, token).await?;
        return Ok(json!(count));
    }
    let progress = op.progress();
    match progress.settled {
        Some(FreezeState::Thawed) => Ok(json!(progress.recovered)),
        Some(state) => {
            let reason = progress
                .unrecoverable_reason
                .map(RecoveryReason::host_reason)
                .unwrap_or("recovery incomplete");
            Err(Error::Internal(format!(
                "thaw joined the aborted freeze: {} target(s) thawed; {reason}; state {state}, marker retained",
                progress.recovered,
            )))
        }
        None => Err(Error::Internal(format_joining_pending(&progress))),
    }
}

/// Host-facing reply for a `guest-fsfreeze-thaw` joining an unsettled
/// freeze operation (design §4.4, §5.9, AC27). Across the unsettled window —
/// preparation, transition in `commit_abort`, recovery draining, and
/// finalisation after marker removal — the reply uses the fixed
/// `"abort accepted, recovery pending"` wording together with the observed
/// thawed count and in-flight activity, avoiding stale state or marker claims.
fn format_joining_pending(progress: &crate::freeze_op::Progress) -> String {
    if progress.in_flight.as_deref() == Some(crate::freeze_op::PREPARING) {
        return "thaw requested: abort accepted, recovery pending (preparation still in flight)"
            .to_owned();
    }
    let activity = if progress.in_flight.is_some() {
        ", a FIFREEZE is still in flight"
    } else {
        ""
    };
    format!(
        "thaw requested: abort accepted, recovery pending ({} target(s) thawed so far{activity})",
        progress.recovered,
    )
}

/// The freeze algorithm shared by `freeze` and `freeze-list`: claim
/// `Thawed → Freezing`, start the operation (`freeze_op`), and relay its
/// single reply. The operation outlives this request: a deadline or a
/// thaw request aborts it and the reply is the error, while the recovery
/// of the targets frozen so far continues on the coordinator.
async fn run_freeze(ctx: &Arc<Context>, restrict: Option<Vec<String>>) -> Result<Value, Error> {
    let effective =
        filter_freeze_selection(restrict.as_deref(), ctx.config.freeze_allowed_mountpoints());
    let token = ctx
        .state
        .begin_freeze()
        .map_err(|err| Error::Internal(format!("cannot freeze: {err}")))?;
    // A definitively empty selection (explicit `mountpoints: []` or an
    // allowlist that admits zero targets) has zero authorized work: settle
    // immediately back to `Thawed` with `0` without reading
    // `/proc/self/mountinfo` or creating a recovery marker (#63). Admission
    // (`begin_freeze`) ran above so an already-frozen or in-flight state still
    // returns an error.
    if effective.as_deref() == Some(&[]) {
        ctx.state.freeze_failed(token);
        tracing::info!(
            event = "fsfreeze_empty_selection",
            "freeze selection admitted zero targets; settled thawed without I/O"
        );
        return Ok(json!(0));
    }
    ctx.hooks.on_freezing(ctx);
    let reply = crate::freeze_op::start(Arc::clone(ctx), token, effective);
    match reply.await {
        Ok(Ok(frozen)) => Ok(json!(frozen)),
        Ok(Err(failure)) => Err(Error::Internal(failure.host_description())),
        Err(_) => Err(Error::Internal(
            "freeze operation ended without a result".to_owned(),
        )),
    }
}

/// The thaw drain shared by the handler and the watchdog: the caller has
/// already won `claim_thaw` and passes the token.
pub async fn run_thaw(ctx: &Arc<Context>, token: ThawToken) -> Result<u64, Error> {
    ctx.hooks.on_thaw_claimed(ctx);
    let kernel = Arc::clone(&ctx.kernel);
    let mounts = Arc::clone(&ctx.mounts);
    let marker = ctx.marker.clone();
    let ownership = ctx.ownership.clone();
    let audit = ctx.audit.clone();
    let allowed = ctx.config.agent.freeze_allowed_mountpoints.clone();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    // The scope (§4.2 "Thaw scope"): a tracked operation's thaw drains
    // the descriptors it published and nothing else; a recovery drain
    // (from `Thawed`, after a restart, or after an operation with an
    // uncertain target) discovers every planned superblock (scoped to the
    // guest's freeze allowlist when configured and marker absence is confirmed
    // via ENOENT in sole-freezer mode, #63, or strictly to superblocks owned
    // by qeminga when cooperative ownership is configured, #69) and also drains
    // any deferred cleanup obligations left behind by an earlier clean-`Thawed`
    // recovery drain.
    let discover = token.is_recovery_drain() || ctx.thaw_scope() == ThawScope::Discovery;
    let from_thawed = token.is_recovery_drain();
    let has_ownership = ownership.is_some();
    let mut held = ctx.take_frozen_mounts();
    if discover {
        held.extend(ctx.take_deferred_recovery_mounts());
    }
    let clean_thawed_confirmed = Arc::new(AtomicBool::new(false));
    let clean_thawed_worker = Arc::clone(&clean_thawed_confirmed);
    let (outcome, held, clean_thawed, need_discovery, marker_retained) =
        tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                let mut held = held;
                let mut need_discovery = false;
                let mut marker_retained = true;
                let mut clean_thawed = false;
                let outcome = match ownership.as_deref() {
                    Some(store) if discover => {
                        let snapshot = store.inspect_all();
                        // Only ENOENT (`Ok(false)`) confirms marker absence (#63);
                        // an indeterminate `fstatat` error escalates into recovery
                        // instead of taking the idle `Ok(0)` fast path (#63 + #69).
                        let marker_probe = marker.probe();
                        let marker_confirmed_absent = matches!(marker_probe, Ok(false));
                        if let Err(err) = &marker_probe {
                            tracing::error!(
                                event = "marker_probe_indeterminate",
                                error = %err,
                                "cannot confirm recovery marker absence during cooperative thaw; escalating to recovery"
                            );
                        }
                        if from_thawed
                            && marker_confirmed_absent
                            && held.is_empty()
                            && matches!(
                                &snapshot,
                                Ok(s) if s.owned_by_self.is_empty() && s.ambiguous.is_empty()
                            )
                        {
                            Ok(0)
                        } else {
                            if from_thawed {
                                audit.enter_ring();
                            }
                            if !matches!(marker_probe, Ok(true)) {
                                match marker.create() {
                                    Ok(()) | Err(MarkerError::AlreadyPresent { .. }) => {}
                                    Err(err) => {
                                        tracing::error!(
                                            event = "fsfreeze_recovery_marker_create_failed",
                                            error = %err,
                                            "cannot create recovery marker when escalating cooperative thaw to recovery; continuing drain"
                                        );
                                        marker_retained = false;
                                    }
                                }
                            }
                            thaw_blocking_cooperative(
                                kernel.as_ref(),
                                mounts.as_ref(),
                                &marker,
                                store,
                                snapshot,
                                allowed.as_deref(),
                                &mut held,
                                &mut need_discovery,
                            )
                        }
                    }
                    maybe_store => {
                        // Only ENOENT (`Ok(false)`) confirms the marker is absent so a
                        // `Thawed` drain can narrow to the guest allowlist and finish
                        // without touching the marker (#63). If a marker is present or
                        // its probe is indeterminate, escalate to full marker recovery and
                        // switch the audit router to the freeze-safe ring before any
                        // recovery I/O (`on_thawed` flushes back to normal on settlement).
                        clean_thawed =
                            maybe_store.is_none() && from_thawed && matches!(marker.probe(), Ok(false));
                        if clean_thawed {
                            clean_thawed_worker.store(true, Ordering::Release);
                        } else if from_thawed {
                            audit.enter_ring();
                        }
                        // Discovery and drain are separate: the handles this process
                        // holds are drained whether or not the mount table can be
                        // read (`thaw_blocking`), and a tracked thaw reads none.
                        let plan = discover.then(|| {
                            build_recovery_plan(mounts.as_ref(), allowed.as_deref(), clean_thawed)
                        });
                        thaw_blocking(
                            kernel.as_ref(),
                            maybe_store,
                            &marker,
                            plan,
                            &mut held,
                            !clean_thawed,
                            allowed.is_some(),
                            &mut need_discovery,
                        )
                    }
                };
                (outcome, held, clean_thawed, need_discovery, marker_retained)
            })
        })
        .await
        .unwrap_or_else(|err| {
            // The task is lost with the descriptors it took: they are no
            // longer evidence of complete ownership, so the next thaw must
            // discover its targets (§4.2 "Thaw scope"), as after a lost
            // recovery drain in the coordinator. Preserve the marker-probe
            // decision (defaulting conservatively to `false` if ENOENT was
            // never confirmed) so an escalated recovery fails closed to
            // `Frozen` and re-arms the watchdog.
            tracing::error!(event = "fsfreeze_thaw_lost", error = %err, "thaw drain lost; targets uncertain");
            ctx.set_thaw_scope(ThawScope::Discovery);
            let marker_retained = if has_ownership {
                matches!(ctx.marker.probe(), Ok(true))
            } else {
                true
            };
            (
                Err(ThawFailure::Task(err.to_string())),
                Vec::new(),
                !has_ownership && clean_thawed_confirmed.load(Ordering::Acquire),
                true,
                marker_retained,
            )
        });
    if need_discovery {
        ctx.set_thaw_scope(ThawScope::Discovery);
    }

    match outcome {
        Ok(thawed) => {
            // Finalise (audit flush) while still `Thawing`, then publish
            // `Thawed`: a freeze accepted after the publication can never
            // have its logging mode changed by this thaw's completion.
            ctx.hooks.on_thawed(ctx);
            ctx.set_thaw_scope(ThawScope::Discovery);
            ctx.state.thaw_succeeded(token);
            tracing::info!(event = "fsfreeze_thawed", thawed, "filesystems thawed");
            Ok(thawed)
        }
        Err(failure) if !has_ownership && clean_thawed => {
            // Nothing was frozen by this agent (the drain started from
            // `Thawed` and `marker.probe()` confirmed no marker existed),
            // so there is no frozen state to retain: keep undrained handles
            // in the deferred recovery bucket so a later freeze cycle's
            // tracked thaw, rollback, abort, and zero-work settlement see
            // only its own descriptors (#63), return to `Thawed`, and
            // report the error (OQ-3).
            ctx.hold_deferred_recovery_mounts(held);
            ctx.hooks.on_thawed(ctx);
            ctx.set_thaw_scope(ThawScope::Discovery);
            ctx.state.thaw_succeeded(token);
            tracing::warn!(event = "fsfreeze_recovery_drain_failed", error = %failure, "recovery drain failed; still thawed");
            Err(Error::Internal(
                failure.host_description(FreezeState::Thawed),
            ))
        }
        Err(failure) => {
            // Whatever could not be drained keeps its handle for the next
            // frozen recovery attempt.
            ctx.hold_frozen_mounts(held);
            // `Thawing → Frozen` (§4.2): the state is `Frozen` again, so
            // the watchdog is re-armed like on any entry into `Frozen`
            // (§4.4); without it a failed thaw would be unbounded.
            ctx.state.thaw_failed(token);
            ctx.hooks.on_frozen(ctx);
            if marker_retained {
                tracing::error!(event = "fsfreeze_thaw_failed", error = %failure, "thaw failed; marker retained");
            } else {
                tracing::error!(event = "fsfreeze_thaw_failed", error = %failure, "thaw failed; recovery marker unavailable");
            }
            Err(Error::Internal(failure.host_description_with_marker(
                FreezeState::Frozen,
                marker_retained,
            )))
        }
    }
}

/// Host-safe classification of why a thaw or recovery drain did not
/// complete (design §5.9, AC27). Guest-local diagnostics keep mount
/// points, alternate paths, device numbers and kernel errnos; wire
/// replies carry only [`RecoveryReason::host_reason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    /// None of the target's mount points opened on its planned superblock;
    /// no `FITHAW` was issued.
    TargetUnreachable,
    /// Opening the target failed before `FITHAW`; no `FITHAW` was issued.
    TargetOpenFailed,
    /// Opening the target was denied (`EPERM`/`EACCES`); no `FITHAW` issued.
    TargetOpenPermissionDenied,
    /// `FITHAW` was denied (`EPERM`/`EACCES`).
    PermissionDenied,
    /// `FITHAW` failed with another kernel error; filesystem may remain frozen.
    IoctlFailed,
    /// `FITHAW` kept succeeding up to [`MAX_THAW_ITERATIONS`].
    DrainDidNotConverge,
    /// One or more superblocks outside the guest's host-visible mount
    /// policy did not finish recovering; target-specific failure classes stay
    /// in guest-local audit logs (#63).
    RecoveryIncomplete,
    /// A freeze worker was lost; target outcome is unknown.
    WorkerLost,
    /// A recovery drain worker was lost; targets remain uncertain.
    DrainLost,
    /// The recovery marker could not be removed after the drain.
    MarkerRetained,
    /// Cooperative per-superblock freeze ownership is ambiguous (corrupt,
    /// spoofed, non-regular, stray, or replaced entry; OQ-11, #69).
    OwnershipAmbiguous,
    /// Cooperative per-superblock freeze ownership could not be updated or
    /// inspected due to an I/O error (OQ-11, #69).
    OwnershipError,
}

impl RecoveryReason {
    /// Fixed host-facing reason without guest paths, device numbers or
    /// marker paths.
    pub const fn host_reason(self) -> &'static str {
        match self {
            RecoveryReason::TargetUnreachable => "target unreachable; no FITHAW issued",
            RecoveryReason::TargetOpenFailed => "target open failed; no FITHAW issued",
            RecoveryReason::TargetOpenPermissionDenied => {
                "target open permission denied; no FITHAW issued"
            }
            RecoveryReason::PermissionDenied => "FITHAW permission denied",
            RecoveryReason::IoctlFailed => "FITHAW failed; filesystem may still be frozen",
            RecoveryReason::DrainDidNotConverge => {
                "drain did not converge; filesystem may still be frozen"
            }
            RecoveryReason::RecoveryIncomplete => {
                "recovery did not complete; filesystem may still be frozen"
            }
            RecoveryReason::WorkerLost => "freeze worker lost; target outcome unknown",
            RecoveryReason::DrainLost => "recovery drain lost; targets uncertain",
            RecoveryReason::MarkerRetained => "cannot remove recovery marker",
            RecoveryReason::OwnershipAmbiguous => {
                "freeze ownership is ambiguous; cannot confirm complete recovery"
            }
            RecoveryReason::OwnershipError => "cannot update freeze ownership state",
        }
    }
}

/// Maps an [`OwnershipError`] to its fixed host-safe [`RecoveryReason`].
pub(crate) fn recovery_reason_for_ownership_error(err: &OwnershipError) -> RecoveryReason {
    match err {
        OwnershipError::OpenDir { .. } | OwnershipError::Io { .. } => {
            RecoveryReason::OwnershipError
        }
        OwnershipError::TooManyEntries { .. } | OwnershipError::NotOwnedBySelf { .. } => {
            RecoveryReason::OwnershipAmbiguous
        }
    }
}

/// Which blocking stage of a freeze operation failed to join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeTaskStage {
    /// Plan/marker preparation before any ioctl; settles `Thawed`.
    Preparation,
    /// Rollback after a hard error; settles `Frozen`, marker retained.
    Rollback,
    /// Marker removal after a zero-work freeze; settles `Frozen`, marker retained.
    MarkerRemoval,
}

/// What stopped a freeze at a target: the kernel's answer to `FIFREEZE`,
/// no pathname of the target leading to its superblock, or a cooperative
/// ownership failure (OQ-11, #69).
#[derive(Debug)]
pub enum FreezeStop {
    /// `FIFREEZE` failed with this error.
    Ioctl(KernelError),
    /// None of the target's mount points opens on its planned device (the
    /// attempts, in order, for guest-local diagnostics); no ioctl was issued.
    Unreachable {
        /// Diagnostic attempt log (`path: err; ...`).
        attempts: String,
        /// `true` when every attempt failed with `EPERM`/`EACCES`.
        permission_denied: bool,
    },
    /// An ambiguous ownership entry prevented claiming this superblock; no
    /// ioctl was issued.
    OwnershipAmbiguous(String),
    /// Claiming this superblock failed with an ownership store error; no
    /// ioctl was issued.
    OwnershipError(OwnershipError),
    /// Releasing a freshly acquired ownership claim failed after a non-freeze
    /// outcome; the claim may remain on disk so the frozen state is retained.
    OwnershipReleaseFailed {
        /// Host-safe classification.
        kind: RecoveryReason,
        /// Guest-local diagnostic detail.
        detail: String,
    },
}

impl FreezeStop {
    /// Fixed host-facing reason without guest paths or device numbers
    /// (design §5.9, AC27).
    pub fn host_reason(&self) -> &'static str {
        match self {
            FreezeStop::Ioctl(err) if err.is_permission() => "FIFREEZE permission denied",
            FreezeStop::Ioctl(err) if err.is_open_failure() => {
                "target open failed; no FIFREEZE issued"
            }
            FreezeStop::Ioctl(err) if err.is_wrong_filesystem() => {
                "target unreachable; no FIFREEZE issued"
            }
            FreezeStop::Ioctl(_) => "FIFREEZE failed",
            FreezeStop::Unreachable {
                permission_denied: true,
                ..
            } => "target open permission denied; no FIFREEZE issued",
            FreezeStop::Unreachable {
                permission_denied: false,
                ..
            } => "target unreachable; no FIFREEZE issued",
            FreezeStop::OwnershipAmbiguous(_) => {
                "freeze ownership is ambiguous; cannot claim target"
            }
            FreezeStop::OwnershipError(err) => err.host_reason(),
            FreezeStop::OwnershipReleaseFailed { kind, .. } => kind.host_reason(),
        }
    }

    /// Returns the host-safe [`RecoveryReason`] and guest-local diagnostic when
    /// a freeze stopped on unresolved cooperative ownership ambiguity or an
    /// ownership store failure, requiring recovery state (`Frozen` +
    /// `ThawScope::Discovery`, recovery marker retained, watchdog armed) rather
    /// than settling `Thawed` (§4.2, OQ-11, #69).
    pub(crate) fn ownership_recovery(&self) -> Option<(RecoveryReason, String)> {
        match self {
            FreezeStop::OwnershipAmbiguous(detail) => {
                Some((RecoveryReason::OwnershipAmbiguous, detail.clone()))
            }
            FreezeStop::OwnershipError(err) => {
                Some((recovery_reason_for_ownership_error(err), err.to_string()))
            }
            FreezeStop::OwnershipReleaseFailed { kind, detail } => Some((*kind, detail.clone())),
            FreezeStop::Ioctl(_) | FreezeStop::Unreachable { .. } => None,
        }
    }
}

impl std::fmt::Display for FreezeStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FreezeStop::Ioctl(err) => write!(f, "{err}"),
            FreezeStop::Unreachable { attempts, .. } => {
                write!(
                    f,
                    "no mount point leads to it ({attempts}); no FIFREEZE issued"
                )
            }
            FreezeStop::OwnershipAmbiguous(reason) => {
                write!(
                    f,
                    "freeze ownership is ambiguous ({reason}); no FIFREEZE issued"
                )
            }
            FreezeStop::OwnershipError(err) => write!(f, "{err}; no FIFREEZE issued"),
            FreezeStop::OwnershipReleaseFailed { detail, .. } => {
                write!(f, "cannot release freeze ownership claim ({detail})")
            }
        }
    }
}

/// Why a freeze failed; `Display` is for guest-local diagnostics, and
/// [`FreezeFailure::host_description`] produces the wire description
/// (design §5.9, AC27).
#[derive(Debug, thiserror::Error)]
pub enum FreezeFailure {
    /// The mount table could not be read.
    #[error("cannot build freeze plan: {0}")]
    Plan(String),
    /// The recovery marker could not be created; no ioctl was issued.
    #[error("cannot create recovery marker: {0}")]
    Marker(#[from] MarkerError),
    /// A target stopped the freeze with a hard error (or could not be
    /// reached); processed targets were rolled back.
    #[error("freeze of {mountpoint} failed: {cause}; rolled back ({rolled_back} target(s) thawed)")]
    Hard {
        /// The target that failed.
        mountpoint: String,
        /// What stopped it.
        cause: FreezeStop,
        /// Targets thawed during rollback.
        rolled_back: u64,
    },
    /// A target stopped the freeze and the rollback could not thaw
    /// `mountpoint` (its drain did not end on the kernel's "not frozen"
    /// answer): the filesystem may still be frozen, so the state stays
    /// `Frozen` and the marker is retained.
    #[error(
        "freeze of {failed} failed: {cause}; rollback of {mountpoint} incomplete ({reason}); marker retained"
    )]
    RollbackIncomplete {
        /// The target that stopped the freeze.
        failed: String,
        /// What stopped it.
        cause: FreezeStop,
        /// The processed target that could not be thawed.
        mountpoint: String,
        /// Host-safe classification of the incomplete rollback.
        recovery_reason: RecoveryReason,
        /// Detailed guest-local diagnostic for why the drain did not complete.
        reason: String,
        /// Targets thawed during rollback.
        rolled_back: u64,
    },
    /// The rollback thawed every processed target but the marker could not
    /// be removed: the state stays `Frozen` and the marker is retained.
    #[error(
        "freeze of {failed} failed: {cause}; rolled back ({rolled_back} target(s) thawed) but cannot remove recovery marker: {marker}"
    )]
    MarkerRetained {
        /// The target that stopped the freeze.
        failed: String,
        /// What stopped it.
        cause: FreezeStop,
        /// The removal error.
        marker: MarkerError,
        /// Targets thawed during rollback.
        rolled_back: u64,
    },
    /// Preparation failed (task lost) and cleanup could not remove the
    /// recovery marker: the state stays `Frozen` and the marker is retained.
    #[error("freeze preparation failed ({cause}); cannot remove recovery marker: {marker}")]
    PreparationMarkerRetained {
        /// Guest-local preparation failure detail.
        cause: String,
        /// The removal error.
        marker: MarkerError,
    },
    /// A blocking task could not be joined.
    #[error("freeze task failed: {detail}")]
    Task {
        /// Which stage failed to join.
        stage: FreezeTaskStage,
        /// Guest-local join error detail.
        detail: String,
    },
    /// Nothing was frozen and nothing is held (an empty or entirely
    /// skipped plan, #43 §2), but the marker could not be removed: the
    /// state stays `Frozen` and the marker is retained, so the reply is
    /// never a `0` that reads as a clean settlement.
    #[error("nothing was frozen but cannot remove recovery marker: {0}; marker retained")]
    NothingFrozenMarkerRetained(MarkerError),
    /// The operation was aborted (§4.4): its deadline expired or a thaw was
    /// requested while a `FIFREEZE` was still in flight. The targets frozen
    /// so far are being thawed by the coordinator; the marker and the
    /// frozen gate stay until the in-flight call returns.
    #[error(
        "freeze aborted: {}{}; {frozen} target(s) frozen so far are being thawed; marker retained",
        cause.describe(*timeout_secs),
        in_flight.as_deref().map(|mp| if mp == crate::freeze_op::PREPARING { " while preparing".to_owned() } else { format!(" with FIFREEZE of {mp} in flight") }).unwrap_or_default()
    )]
    Aborted {
        /// What aborted it.
        cause: crate::freeze_op::AbortCause,
        /// The operation deadline in seconds.
        timeout_secs: u64,
        /// Successful `FIFREEZE` calls before the abort.
        frozen: u64,
        /// The target whose call was in flight, if any (guest-local diagnostic).
        in_flight: Option<String>,
    },
}

impl FreezeFailure {
    /// `true` when the failure leaves a filesystem possibly frozen or the
    /// marker in place, so the agent must stay `Frozen` (design §4.2).
    pub fn retains_frozen_state(&self) -> bool {
        matches!(
            self,
            FreezeFailure::RollbackIncomplete { .. }
                | FreezeFailure::MarkerRetained { .. }
                | FreezeFailure::PreparationMarkerRetained { .. }
                | FreezeFailure::NothingFrozenMarkerRetained(_)
                | FreezeFailure::Task {
                    stage: FreezeTaskStage::Rollback | FreezeTaskStage::MarkerRemoval,
                    ..
                }
        )
    }

    /// Host-facing wire description (design §5.9, AC27): preserves a fixed
    /// reason, recovery state and counts while keeping guest mount names,
    /// alternate paths, device numbers and marker paths in guest-local
    /// diagnostics.
    pub fn host_description(&self) -> String {
        match self {
            FreezeFailure::Plan(_) => "cannot build freeze plan; state thawed".to_owned(),
            FreezeFailure::Marker(err) => format!(
                "cannot create recovery marker: {}; state thawed",
                err.host_reason()
            ),
            FreezeFailure::Hard {
                cause, rolled_back, ..
            } => format!(
                "freeze failed: {}; rolled back ({rolled_back} target(s) thawed); state thawed",
                cause.host_reason()
            ),
            FreezeFailure::RollbackIncomplete {
                cause,
                recovery_reason,
                rolled_back,
                ..
            } => format!(
                "freeze failed: {}; rollback incomplete ({}, {rolled_back} target(s) thawed); state frozen, marker retained",
                cause.host_reason(),
                recovery_reason.host_reason()
            ),
            FreezeFailure::MarkerRetained {
                cause,
                marker,
                rolled_back,
                ..
            } => format!(
                "freeze failed: {}; rolled back ({rolled_back} target(s) thawed) but cannot remove recovery marker: {}; state frozen, marker retained",
                cause.host_reason(),
                marker.host_reason()
            ),
            FreezeFailure::PreparationMarkerRetained { marker, .. } => format!(
                "freeze preparation failed; cannot remove recovery marker: {}; state frozen, marker retained",
                marker.host_reason()
            ),
            FreezeFailure::Task { stage, .. } => match stage {
                FreezeTaskStage::Preparation => {
                    "freeze preparation failed; state thawed".to_owned()
                }
                FreezeTaskStage::Rollback => {
                    "freeze rollback failed; state frozen, marker retained".to_owned()
                }
                FreezeTaskStage::MarkerRemoval => {
                    "nothing was frozen (0 target(s) frozen) and marker removal failed; state frozen, marker retained".to_owned()
                }
            },
            FreezeFailure::NothingFrozenMarkerRetained(err) => format!(
                "nothing was frozen (0 target(s) frozen) but cannot remove recovery marker: {}; state frozen, marker retained",
                err.host_reason()
            ),
            FreezeFailure::Aborted {
                cause,
                frozen,
                in_flight,
                ..
            } => {
                if in_flight.as_deref() == Some(crate::freeze_op::PREPARING) {
                    format!(
                        "freeze aborted: {} while preparing; abort accepted, recovery pending",
                        cause.host_reason(),
                    )
                } else {
                    let activity = if in_flight.is_some() {
                        " with a FIFREEZE in flight"
                    } else {
                        ""
                    };
                    format!(
                        "freeze aborted: {}{activity}; {frozen} target(s) frozen so far are being thawed; state thawing, marker retained",
                        cause.host_reason(),
                    )
                }
            }
        }
    }
}

/// Why a thaw failed unrecoverably (the state returns to `Frozen` unless
/// started as a recovery drain from `Thawed`). `Display` is for
/// guest-local diagnostics; [`ThawFailure::host_description`] produces the
/// wire description (design §5.9, AC27).
#[derive(Debug, thiserror::Error)]
pub enum ThawFailure {
    /// The mount table could not be read.
    #[error("cannot build thaw plan: {detail}")]
    Plan {
        /// Guest-local mount-table read error.
        detail: String,
        /// Targets thawed through held handles before reporting the failure.
        thawed: u64,
    },
    /// A target may still be frozen after its drain (OQ-3): a denied or
    /// failed `FITHAW`, a superblock none of whose mount points opens on
    /// it any more (no `FITHAW` issued), or a drain that never converged.
    /// The marker and the frozen gate are retained.
    #[error("thaw of {mountpoint} incomplete: {reason}; marker retained")]
    Incomplete {
        /// The target that may still be frozen.
        mountpoint: String,
        /// Host-safe classification of the incomplete drain.
        kind: RecoveryReason,
        /// Detailed guest-local diagnostic for why the drain did not complete.
        reason: String,
        /// Targets thawed during this attempt.
        thawed: u64,
    },
    /// The marker could not be removed after the drain.
    #[error("drain complete but cannot remove recovery marker: {err}")]
    Marker {
        /// The removal error.
        err: MarkerError,
        /// Targets thawed during this attempt.
        thawed: u64,
    },
    /// The blocking task could not be joined.
    #[error("thaw task failed: {0}")]
    Task(String),
}

impl ThawFailure {
    /// Records the total number of targets thawed during this attempt.
    fn with_thawed(mut self, count: u64) -> Self {
        match &mut self {
            ThawFailure::Plan { thawed, .. }
            | ThawFailure::Incomplete { thawed, .. }
            | ThawFailure::Marker { thawed, .. } => *thawed = count,
            ThawFailure::Task(_) => {}
        }
        self
    }

    /// Host-facing wire description (design §5.9, AC27): preserves a fixed
    /// reason, recovery state and counts while keeping guest mount names,
    /// alternate paths, device numbers and marker paths in guest-local
    /// diagnostics.
    pub fn host_description(&self, final_state: FreezeState) -> String {
        self.host_description_with_marker(final_state, true)
    }

    /// Like [`ThawFailure::host_description`], distinguishing whether the
    /// recovery marker is actually retained on disk when `final_state` is
    /// `Frozen` (for example when escalating a marker-absent cooperative thaw
    /// into recovery cannot create `/run/qeminga/frozen`).
    pub fn host_description_with_marker(
        &self,
        final_state: FreezeState,
        marker_retained: bool,
    ) -> String {
        let state_suffix = match (final_state, marker_retained) {
            (FreezeState::Thawed, _) => "state thawed",
            (_, true) => "state frozen, marker retained",
            (_, false) => "state frozen, marker unavailable",
        };
        match self {
            ThawFailure::Plan { thawed, .. } => {
                format!("cannot build thaw plan ({thawed} target(s) thawed); {state_suffix}")
            }
            ThawFailure::Incomplete { kind, thawed, .. } => format!(
                "thaw incomplete: {} ({thawed} target(s) thawed); {state_suffix}",
                kind.host_reason()
            ),
            ThawFailure::Marker { err, thawed } => format!(
                "drain complete ({thawed} target(s) thawed) but cannot remove recovery marker: {}; {state_suffix}",
                err.host_reason()
            ),
            ThawFailure::Task(_) => format!("thaw task failed; {state_suffix}"),
        }
    }
}

pub(crate) fn build_plan<E: From<String>>(
    mounts: &dyn MountSource,
    restrict: Option<&[String]>,
) -> Result<FreezePlan, E> {
    let entries = mounts.mounts().map_err(|err| E::from(err.to_string()))?;
    let plan = FreezePlan::build(&entries);
    Ok(match restrict {
        Some(mountpoints) => plan.restrict_to(mountpoints),
        None => plan,
    })
}

/// A discovery recovery plan plus an optional wire-count filter (#63).
///
/// - When thawing from `Thawed` (`from_thawed == true`, no marker and no prior
///   crash obligation) with `freeze_allowed_mountpoints` configured, `plan` is
///   strictly narrowed via [`FreezePlan::restrict_for_recovery`] so
///   unprovisioned superblocks are neither opened nor thawed.
/// - During marker / uncertain-worker recovery (`from_thawed == false`), the
///   v1 marker carries no target identities or policy version, so guest config
///   may have narrowed `freeze_allowed_mountpoints` between the freeze and the
///   restart. Under v1's sole-freezer assumption (§4.2), `plan` drains every
///   eligible superblock before removing the marker so no earlier freeze can
///   be stranded, while `countable_devs` restricts the count reported on the
///   wire (in both success and failure replies) to superblocks authorized by
///   the current guest policy.
pub(crate) struct RecoveryPlan {
    plan: FreezePlan,
    countable_devs: Option<std::collections::HashSet<(u32, u32)>>,
}

pub(crate) fn build_recovery_plan(
    mounts: &dyn MountSource,
    allowed: Option<&[String]>,
    from_thawed: bool,
) -> Result<RecoveryPlan, ThawFailure> {
    let entries = mounts
        .mounts()
        .map_err(|err| ThawFailure::from(err.to_string()))?;
    let full = FreezePlan::build(&entries);
    match allowed {
        None => Ok(RecoveryPlan {
            plan: full,
            countable_devs: None,
        }),
        Some(mountpoints) => {
            let visible_allowed = full.restrict_for_recovery(mountpoints);
            let countable_devs = visible_allowed.targets().iter().map(|t| t.dev).collect();
            let plan = if from_thawed { visible_allowed } else { full };
            Ok(RecoveryPlan {
                plan,
                countable_devs: Some(countable_devs),
            })
        }
    }
}

impl From<String> for FreezeFailure {
    fn from(message: String) -> Self {
        FreezeFailure::Plan(message)
    }
}

impl From<String> for ThawFailure {
    fn from(detail: String) -> Self {
        ThawFailure::Plan { detail, thawed: 0 }
    }
}

/// Why none of a target's mount points could be opened on its planned
/// superblock: `detail` carries paths, device numbers and errnos for
/// guest-local diagnostics; `permission_denied` distinguishes a pure
/// permission denial for host-facing classification.
#[derive(Debug, Clone)]
pub(crate) struct OpenTargetError {
    pub(crate) detail: String,
    pub(crate) permission_denied: bool,
}

/// Opens `target` on its planned device. A target a request selected
/// ([`Target::requested`]) is opened on the requested name and on nothing
/// else: the kernel shim verifies the opened directory, so a name that
/// does not lead to the selected superblock is a failure of this target,
/// never an alias standing in for it (a controller's coverage must not be
/// rescued by reaching another name of a wrongly selected superblock).
/// Otherwise, through the first of its mount points that still leads
/// there (a mount placed over a pathname is seen, not frozen or thawed by
/// mistake). When none does, the attempts are recorded in order for
/// guest-local diagnostics: `/data: mountpoint is on 8:3, not on the
/// planned 8:2; /data-alias: cannot open mountpoint: ENOENT`.
pub(crate) fn open_target(
    kernel: &dyn KernelOps,
    target: &Target,
) -> Result<Mount, OpenTargetError> {
    if let Some(requested) = &target.requested {
        return kernel
            .open_mount(requested, target.dev)
            .map_err(|err| OpenTargetError {
                detail: format!("{}: {err}", lossy(requested)),
                permission_denied: err.is_permission(),
            });
    }
    let mut attempts = Vec::new();
    let mut all_permission_denied = true;
    for path in target.mountpoints() {
        match kernel.open_mount(path, target.dev) {
            Ok(mount) => {
                if !attempts.is_empty() {
                    tracing::warn!(
                        event = "fsfreeze_alias",
                        mountpoint = %target.mountpoint.display(),
                        alias = %path.display(),
                        "mount point no longer leads to its superblock; reached through an alias"
                    );
                }
                return Ok(mount);
            }
            Err(err) => {
                if !err.is_permission() {
                    all_permission_denied = false;
                }
                attempts.push(format!("{}: {err}", lossy(path)));
            }
        }
    }
    Err(OpenTargetError {
        permission_denied: !attempts.is_empty() && all_permission_denied,
        detail: attempts.join("; "),
    })
}

/// First target whose drain did not complete, carrying both the
/// guest-local diagnostic and the host-safe [`RecoveryReason`].
#[derive(Debug, Clone)]
pub(crate) struct IncompleteDrain {
    pub(crate) mountpoint: String,
    pub(crate) kind: RecoveryReason,
    pub(crate) detail: String,
}

/// Result of draining a set of held handles through [`drain_held`].
pub(crate) struct DrainHeldResult {
    /// Policy-authorized targets on which at least one `FITHAW` succeeded.
    pub(crate) recovered: u64,
    /// Handles whose drain did not complete (kept for a later attempt).
    pub(crate) keep: Vec<HeldMount>,
    /// First incomplete drain or claim-release failure, if any.
    pub(crate) incomplete: Option<IncompleteDrain>,
    /// `true` when releasing a cooperative ownership claim failed after a
    /// complete drain, so subsequent recovery must discover from the ownership
    /// store rather than blindly re-issuing `FITHAW` on a retained handle.
    pub(crate) uncertain: bool,
}

/// Drains every processed target through the handle its freeze opened, in
/// forward mount order, then removes the marker; `held` keeps the handles
/// whose drain did not complete. Every processed target gets its drain,
/// as in [`thaw_blocking`]: one that cannot be thawed is remembered and
/// reported afterwards, and must not leave the later ones frozen until a
/// recovery. Returns `(failure, uncertain)`.
pub(crate) fn rollback(
    kernel: &dyn KernelOps,
    ownership: Option<&dyn OwnershipStore>,
    marker: &Marker,
    held: &mut Vec<HeldMount>,
    failed: &Path,
    cause: FreezeStop,
) -> (FreezeFailure, bool) {
    let DrainHeldResult {
        recovered: rolled_back,
        keep,
        incomplete,
        uncertain,
    } = drain_held(kernel, ownership, std::mem::take(held));
    *held = keep;
    let failed = lossy(failed);
    if let Some(IncompleteDrain {
        mountpoint,
        kind,
        detail,
    }) = incomplete
    {
        return (
            FreezeFailure::RollbackIncomplete {
                failed,
                cause,
                mountpoint,
                recovery_reason: kind,
                reason: detail,
                rolled_back,
            },
            uncertain,
        );
    }
    if let Some((kind, detail)) = cause.ownership_recovery() {
        return (
            FreezeFailure::RollbackIncomplete {
                failed: failed.clone(),
                mountpoint: failed,
                recovery_reason: kind,
                reason: detail,
                cause,
                rolled_back,
            },
            true,
        );
    }
    let failure = match marker.remove() {
        Ok(()) | Err(MarkerError::Absent { .. }) => FreezeFailure::Hard {
            mountpoint: failed,
            cause,
            rolled_back,
        },
        Err(marker) => FreezeFailure::MarkerRetained {
            failed,
            cause,
            marker,
            rolled_back,
        },
    };
    (failure, uncertain)
}

/// Result of verifying current cooperative freeze ownership immediately before
/// issuing `FITHAW` on a retained or discovered mount descriptor (OQ-11, #69).
enum PreThawOwnership {
    /// Ownership is verified as `qeminga` (or cooperative mode is disabled);
    /// safe to issue `FITHAW`.
    Proceed,
    /// Ownership could not be confirmed as `qeminga`; `FITHAW` must not run.
    Refused {
        kind: RecoveryReason,
        detail: String,
        /// `true` when current ownership is uncertain (`Ambiguous` or `Err`),
        /// so the handle must stay retained for retry; `false` when ownership
        /// is confirmed no longer held by `qeminga` (`OwnedByOther` or `Unclaimed`).
        keep_handle: bool,
    },
}

/// Shared read-only ownership check run once immediately before starting each
/// target's `FITHAW` drain across tracked thaw, rollback, abort recovery, and
/// discovery drains (OQ-11, #69). Under the cooperative protocol a valid claim
/// remains exclusively held by its owner until the drain reaches a terminal
/// ioctl (`EINVAL`/`EOPNOTSUPP`) and releases it.
fn verify_ownership_before_thaw(
    ownership: Option<&dyn OwnershipStore>,
    mount: &Mount,
) -> PreThawOwnership {
    let Some(store) = ownership else {
        return PreThawOwnership::Proceed;
    };
    match store.inspect(mount.dev()) {
        Ok(TargetOwnership::OwnedBySelf) => PreThawOwnership::Proceed,
        Ok(TargetOwnership::OwnedByOther { owner }) => {
            tracing::error!(
                event = "fsfreeze_retained_ownership_lost",
                mountpoint = %mount.mountpoint().display(),
                owner = %owner,
                "retained handle is now owned by another guest freezer; refusing FITHAW"
            );
            PreThawOwnership::Refused {
                kind: RecoveryReason::OwnershipAmbiguous,
                detail: format!("retained handle is owned by {owner}, not qeminga"),
                keep_handle: false,
            }
        }
        Ok(TargetOwnership::Unclaimed) => {
            tracing::error!(
                event = "fsfreeze_retained_ownership_lost",
                mountpoint = %mount.mountpoint().display(),
                "retained handle has no qeminga ownership claim; refusing FITHAW"
            );
            PreThawOwnership::Refused {
                kind: RecoveryReason::OwnershipAmbiguous,
                detail: "retained handle is no longer owned by qeminga".to_owned(),
                keep_handle: false,
            }
        }
        Ok(TargetOwnership::Ambiguous { reason }) => {
            tracing::error!(
                event = "fsfreeze_retained_ownership_uncertain",
                mountpoint = %mount.mountpoint().display(),
                reason = %reason,
                "cannot verify freeze ownership before FITHAW; retaining handle for retry"
            );
            PreThawOwnership::Refused {
                kind: RecoveryReason::OwnershipAmbiguous,
                detail: format!("cannot verify ownership before FITHAW: {reason}"),
                keep_handle: true,
            }
        }
        Err(err) => {
            tracing::error!(
                event = "fsfreeze_retained_ownership_uncertain",
                mountpoint = %mount.mountpoint().display(),
                error = %err,
                "cannot read freeze ownership before FITHAW; retaining handle for retry"
            );
            PreThawOwnership::Refused {
                kind: recovery_reason_for_ownership_error(&err),
                detail: err.to_string(),
                keep_handle: true,
            }
        }
    }
}

/// Merges a new incomplete drain into `slot`, keeping the first failure while
/// allowing a policy-authorized failure to upgrade a collapsed generic
/// [`RecoveryReason::RecoveryIncomplete`] from an excluded handle (#63).
pub(crate) fn merge_incomplete(slot: &mut Option<IncompleteDrain>, next: IncompleteDrain) {
    match slot {
        None => *slot = Some(next),
        Some(IncompleteDrain {
            kind: RecoveryReason::RecoveryIncomplete,
            ..
        }) if next.kind != RecoveryReason::RecoveryIncomplete => *slot = Some(next),
        Some(_) => {}
    }
}

/// Drains handles a freeze published, in forward mount order (they were
/// pushed deepest-first), verifying cooperative ownership immediately before
/// `FITHAW` and releasing each `qeminga` ownership claim only after its drain
/// completes cleanly. Returns the number of policy-authorized targets on which
/// at least one `FITHAW` succeeded, the handles whose drain did not complete
/// (kept for a later attempt), the first such target with its reason
/// (collapsing excluded handles to [`RecoveryReason::RecoveryIncomplete`] while
/// letting an authorized failure take precedence, #63), and whether ownership
/// became uncertain (#69).
pub(crate) fn drain_held(
    kernel: &dyn KernelOps,
    ownership: Option<&dyn OwnershipStore>,
    held: Vec<HeldMount>,
) -> DrainHeldResult {
    let mut recovered = 0;
    let mut incomplete: Option<IncompleteDrain> = None;
    let mut keep = Vec::new();
    let mut uncertain = false;
    for entry in held.into_iter().rev() {
        if let PreThawOwnership::Refused {
            kind,
            detail,
            keep_handle,
        } = verify_ownership_before_thaw(ownership, &entry.mount)
        {
            let wire_kind = if entry.countable {
                kind
            } else {
                RecoveryReason::RecoveryIncomplete
            };
            merge_incomplete(
                &mut incomplete,
                IncompleteDrain {
                    mountpoint: lossy(entry.mount.mountpoint()),
                    kind: wire_kind,
                    detail,
                },
            );
            uncertain = true;
            if keep_handle {
                keep.push(entry);
            }
            continue;
        }
        let drained = drain(kernel, &entry.mount);
        if drained.successes > 0 && entry.countable {
            recovered += 1;
        }
        tracing::warn!(
            event = "fsfreeze_rollback",
            mountpoint = %entry.mount.mountpoint().display(),
            successes = drained.successes,
            "rolled back"
        );
        if let Some(DrainIncomplete { kind, detail }) = drained.incomplete() {
            tracing::error!(
                event = "fsfreeze_rollback_incomplete",
                mountpoint = %entry.mount.mountpoint().display(),
                reason = %detail,
                "rollback target may still be frozen"
            );
            merge_incomplete(
                &mut incomplete,
                IncompleteDrain {
                    mountpoint: lossy(entry.mount.mountpoint()),
                    kind: if entry.countable {
                        kind
                    } else {
                        RecoveryReason::RecoveryIncomplete
                    },
                    detail,
                },
            );
            keep.push(entry);
        } else if let Some(store) = ownership
            && let Err(err) = store.release(entry.mount.dev())
        {
            tracing::error!(
                event = "fsfreeze_ownership_release_failed",
                mountpoint = %entry.mount.mountpoint().display(),
                error = %err,
                "cannot release freeze ownership claim after rollback drain"
            );
            merge_incomplete(
                &mut incomplete,
                IncompleteDrain {
                    mountpoint: lossy(entry.mount.mountpoint()),
                    kind: if entry.countable {
                        recovery_reason_for_ownership_error(&err)
                    } else {
                        RecoveryReason::RecoveryIncomplete
                    },
                    detail: err.to_string(),
                },
            );
            uncertain = true;
        }
    }
    DrainHeldResult {
        recovered,
        keep,
        incomplete,
        uncertain,
    }
}

/// Drains every target in forward order, then removes the marker. Returns
/// the number of policy-authorized targets on which at least one `FITHAW`
/// succeeded.
///
/// With a `plan` (a discovery drain, §4.2 "Thaw scope") a target is
/// drained through the handle its freeze opened when `held` has one for
/// its device (that handle names the frozen filesystem whatever its
/// pathnames lead to now), otherwise through the first of its mount
/// points that still opens on its device. Handles for devices the plan
/// no longer lists are drained too: this process froze them. Without a
/// plan (a tracked thaw: every obligation is a held descriptor) the held
/// handles are all there is to drain, and no pathname is consulted. On
/// return `held` keeps the handles whose drain did not complete, along
/// with whether each handle is countable on the wire under the guest's
/// mount policy.
///
/// Discovery is not a prerequisite of the drain: when the mount table
/// could not be read (`plan` is the failure; `EMFILE`, which the held
/// handles themselves may have caused, is the typical case), every held
/// handle is still drained and released, and the read failure is then
/// reported as unrecoverable, since targets frozen by an earlier
/// instance could not be discovered: the marker is retained and the next
/// attempt (the watchdog, the host, or a restart) completes the recovery.
///
/// An unrecoverable failure on one target (OQ-3: anything but the
/// kernel's "not frozen" answer, see [`Drained::incomplete`], or a
/// superblock that cannot be reached at all) does not stop the drain of
/// the later targets: everything that can be thawed is thawed first
/// (§4.2), then the first such failure is reported and the marker is
/// retained.
#[allow(clippy::too_many_arguments)]
fn thaw_blocking(
    kernel: &dyn KernelOps,
    ownership: Option<&dyn OwnershipStore>,
    marker: &Marker,
    plan: Option<Result<RecoveryPlan, ThawFailure>>,
    held: &mut Vec<HeldMount>,
    remove_marker: bool,
    restricted: bool,
    need_discovery: &mut bool,
) -> Result<u64, ThawFailure> {
    let mut state = ThawState::default();
    let mut retained = std::mem::take(held);
    let planned = matches!(plan, Some(Ok(_)));
    // Under a configured `freeze_allowed_mountpoints` policy, any discovery
    // drain (`plan.is_some()`) credits wire counts and specific error classes
    // strictly for targets whose current visibility at an allowlisted path is
    // verified by a readable mount table. Leftovers in `retained` were either
    // absent from the fresh plan (`Some(Ok(_))`) or could not be verified
    // because `/proc/self/mountinfo` was unreadable (`Some(Err(_))`); in both
    // cases they are still drained for guest recovery while suppressing wire
    // credit and collapsing errors to `RecoveryIncomplete` (#63). Tracked
    // thaws (`plan.is_none()`) and unrestricted discovery (`!restricted`)
    // preserve each descriptor's recorded countability.
    let suppress_leftovers = restricted && plan.is_some();
    let discovery = match plan {
        None => {
            tracing::info!(
                event = "fsfreeze_thaw_tracked",
                held = retained.len(),
                "draining the descriptors the operation published; nothing to discover"
            );
            None
        }
        Some(Ok(RecoveryPlan {
            plan,
            countable_devs,
        })) => {
            for target in plan.thaw_order() {
                let countable = countable_devs
                    .as_ref()
                    .is_none_or(|devs| devs.contains(&target.dev));
                let mount = match retained.iter().position(|h| h.mount.dev() == target.dev) {
                    Some(index) => retained.remove(index).mount,
                    None => match open_target(kernel, target) {
                        Ok(mount) => mount,
                        Err(err) => {
                            record_unreachable(&mut state, target, err, countable);
                            continue;
                        }
                    },
                };
                state.drain(kernel, ownership, mount, countable);
            }
            None
        }
        Some(Err(failure)) => {
            tracing::error!(
                event = "fsfreeze_thaw_plan_failed",
                error = %failure,
                held = retained.len(),
                "cannot read the mount table; draining the handles this process holds"
            );
            Some(failure)
        }
    };
    // `held` was filled in reverse mount order (deepest first): drain the
    // leftovers forward, as the plan and the rollback do.
    for entry in retained.into_iter().rev() {
        if planned {
            tracing::warn!(
                event = "fsfreeze_unplanned_drain",
                mountpoint = %entry.mount.mountpoint().display(),
                "frozen by this process but no longer in the plan; drained"
            );
        }
        let countable = if suppress_leftovers {
            false
        } else {
            entry.countable
        };
        state.drain(kernel, ownership, entry.mount, countable);
    }
    *need_discovery = state.ownership_uncertain;
    finish_thaw_state(state, discovery, marker, held, remove_marker)
}

/// Discovery / recovery drain under cooperative per-superblock ownership
/// (OQ-11, #69), composed with optional `freeze_allowed_mountpoints` wire
/// count/error disclosure suppression (#63).
///
/// Drains ONLY superblocks verified as owned by `qeminga`, leaves foreign-owned
/// and unclaimed superblocks untouched, drains and releases `qeminga`-owned
/// superblocks even if they lie outside the current `freeze_allowed_mountpoints`
/// list (without crediting wire counts or leaking target-specific failure
/// classes), and retains the recovery marker whenever ownership is ambiguous,
/// unreadable, or an owned superblock cannot be reached or released.
#[allow(clippy::too_many_arguments)]
fn thaw_blocking_cooperative(
    kernel: &dyn KernelOps,
    mounts: &dyn MountSource,
    marker: &Marker,
    store: &dyn OwnershipStore,
    snapshot: Result<OwnershipSnapshot, OwnershipError>,
    allowed: Option<&[String]>,
    held: &mut Vec<HeldMount>,
    need_discovery: &mut bool,
) -> Result<u64, ThawFailure> {
    let mut state = ThawState::default();
    let mut retained = std::mem::take(held);
    let restricted = allowed.is_some();
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(err) => {
            tracing::error!(
                event = "fsfreeze_ownership_inspect_failed",
                error = %err,
                held = retained.len(),
                "cannot scan freeze ownership directory; verifying mounted targets individually and draining held handles"
            );
            match build_recovery_plan(mounts, allowed, false) {
                Ok(RecoveryPlan {
                    plan,
                    countable_devs,
                }) => {
                    for target in plan.thaw_order() {
                        let countable = countable_devs
                            .as_ref()
                            .is_none_or(|devs| devs.contains(&target.dev));
                        match store.inspect(target.dev) {
                            Ok(TargetOwnership::OwnedBySelf) => {
                                drain_planned_target(
                                    kernel,
                                    store,
                                    &mut state,
                                    &mut retained,
                                    target,
                                    countable,
                                );
                            }
                            Ok(
                                TargetOwnership::OwnedByOther { .. } | TargetOwnership::Unclaimed,
                            ) => {}
                            Ok(TargetOwnership::Ambiguous { reason }) => {
                                tracing::error!(
                                    event = "fsfreeze_ownership_ambiguous",
                                    major = target.dev.0,
                                    minor = target.dev.1,
                                    reason = %reason,
                                    "ambiguous freeze ownership entry during fallback target scan; skipping FITHAW"
                                );
                            }
                            Err(inspect_err) => {
                                tracing::error!(
                                    event = "fsfreeze_ownership_inspect_target_failed",
                                    major = target.dev.0,
                                    minor = target.dev.1,
                                    error = %inspect_err,
                                    "cannot inspect freeze ownership for mounted target during fallback scan; skipping FITHAW"
                                );
                            }
                        }
                    }
                }
                Err(failure) => {
                    tracing::error!(
                        event = "fsfreeze_thaw_plan_failed",
                        error = %failure,
                        held = retained.len(),
                        "cannot read the mount table during ownership scan fallback; draining the handles this process holds"
                    );
                }
            }
            for entry in retained.into_iter().rev() {
                let countable = if restricted { false } else { entry.countable };
                state.drain(kernel, Some(store), entry.mount, countable);
            }
            state.record_failure(
                ThawFailure::Incomplete {
                    mountpoint: "(ownership)".to_owned(),
                    kind: recovery_reason_for_ownership_error(&err),
                    reason: err.to_string(),
                    thawed: 0,
                },
                true,
            );
            *need_discovery = true;
            return finish_thaw_state(state, None, marker, held, true);
        }
    };

    for reason in &snapshot.ambiguous {
        tracing::error!(
            event = "fsfreeze_ownership_ambiguous",
            reason = %reason,
            "ambiguous freeze ownership entry; draining reachable qeminga targets and retaining marker"
        );
    }

    let mut pending_self: BTreeSet<(u32, u32)> = snapshot.owned_by_self.iter().copied().collect();
    let (discovery, verified_countable) =
        if !pending_self.is_empty() || (restricted && !retained.is_empty()) {
            match build_recovery_plan(mounts, allowed, false) {
                Ok(RecoveryPlan {
                    plan,
                    countable_devs,
                }) => {
                    for target in plan.thaw_order() {
                        if !pending_self.remove(&target.dev) {
                            continue;
                        }
                        let countable = countable_devs
                            .as_ref()
                            .is_none_or(|devs| devs.contains(&target.dev));
                        drain_planned_target(
                            kernel,
                            store,
                            &mut state,
                            &mut retained,
                            target,
                            countable,
                        );
                    }
                    (None, countable_devs)
                }
                Err(failure) => {
                    tracing::error!(
                        event = "fsfreeze_thaw_plan_failed",
                        error = %failure,
                        held = retained.len(),
                        "cannot read the mount table; draining the handles this process holds"
                    );
                    (Some(failure), None)
                }
            }
        } else {
            (None, None)
        };

    for entry in retained.into_iter().rev() {
        pending_self.remove(&entry.mount.dev());
        let countable = if restricted {
            verified_countable
                .as_ref()
                .is_some_and(|devs| devs.contains(&entry.mount.dev()))
        } else {
            entry.countable
        };
        state.drain(kernel, Some(store), entry.mount, countable);
    }

    if discovery.is_none() {
        for dev in pending_self {
            let dev_label = format!("{}:{}", dev.0, dev.1);
            tracing::error!(
                event = "fsfreeze_owned_target_missing",
                major = dev.0,
                minor = dev.1,
                "qeminga-owned superblock is missing from mountinfo; retaining claim and marker"
            );
            let countable = !restricted;
            let kind = if countable {
                RecoveryReason::TargetUnreachable
            } else {
                RecoveryReason::RecoveryIncomplete
            };
            state.record_failure(
                ThawFailure::Incomplete {
                    mountpoint: dev_label.clone(),
                    kind,
                    reason: format!(
                        "qeminga-owned superblock {dev_label} not present in mount table; no FITHAW issued"
                    ),
                    thawed: 0,
                },
                countable,
            );
        }
    }

    if !snapshot.ambiguous.is_empty() {
        state.record_failure(
            ThawFailure::Incomplete {
                mountpoint: "(ownership)".to_owned(),
                kind: RecoveryReason::OwnershipAmbiguous,
                reason: snapshot.ambiguous.join("; "),
                thawed: 0,
            },
            true,
        );
    }

    *need_discovery = state.ownership_uncertain;
    finish_thaw_state(state, discovery, marker, held, true)
}

fn drain_planned_target(
    kernel: &dyn KernelOps,
    store: &dyn OwnershipStore,
    state: &mut ThawState,
    retained: &mut Vec<HeldMount>,
    target: &Target,
    countable: bool,
) {
    let mount = match retained.iter().position(|h| h.mount.dev() == target.dev) {
        Some(index) => retained.remove(index).mount,
        None => match open_target(kernel, target) {
            Ok(mount) => mount,
            Err(err) => {
                record_unreachable(state, target, err, countable);
                return;
            }
        },
    };
    state.drain(kernel, Some(store), mount, countable);
}

fn record_unreachable(
    state: &mut ThawState,
    target: &Target,
    err: OpenTargetError,
    countable: bool,
) {
    let kind = if countable {
        if err.permission_denied {
            RecoveryReason::TargetOpenPermissionDenied
        } else {
            RecoveryReason::TargetUnreachable
        }
    } else {
        RecoveryReason::RecoveryIncomplete
    };
    let failure = ThawFailure::Incomplete {
        mountpoint: lossy(&target.mountpoint),
        kind,
        reason: format!(
            "no mount point leads to {}:{} ({}); no FITHAW issued",
            target.dev.0, target.dev.1, err.detail
        ),
        thawed: 0,
    };
    tracing::error!(
        event = "fsfreeze_thaw_target_failed",
        mountpoint = %target.mountpoint.display(),
        error = %failure,
        "target cannot be reached; draining the remaining targets"
    );
    state.record_failure(failure, countable);
}

fn finish_thaw_state(
    state: ThawState,
    discovery: Option<ThawFailure>,
    marker: &Marker,
    held: &mut Vec<HeldMount>,
    remove_marker: bool,
) -> Result<u64, ThawFailure> {
    let ThawState {
        thawed,
        unrecoverable,
        keep,
        ..
    } = state;
    *held = keep;
    if let Some(failure) = unrecoverable {
        return Err(failure.with_thawed(thawed));
    }
    if let Some(failure) = discovery {
        return Err(failure.with_thawed(thawed));
    }
    if !remove_marker {
        return Ok(thawed);
    }
    match marker.remove() {
        Ok(()) | Err(MarkerError::Absent { .. }) => Ok(thawed),
        Err(err) => Err(ThawFailure::Marker { err, thawed }),
    }
}

/// The running result of a thaw drain over several targets.
#[derive(Default)]
struct ThawState {
    /// Policy-authorized targets on which at least one `FITHAW` succeeded
    /// (reported on the wire).
    thawed: u64,
    /// The first failure to report, if any.
    unrecoverable: Option<ThawFailure>,
    /// Handles whose drain did not complete or whose ownership was uncertain.
    keep: Vec<HeldMount>,
    /// `true` when cooperative ownership could not be verified before `FITHAW`
    /// or releasing a claim failed after drain, requiring `ThawScope::Discovery`
    /// on retry.
    ownership_uncertain: bool,
}

impl ThawState {
    /// Records an unrecoverable target failure. A failure on a policy-authorized
    /// (`countable`) target upgrades an earlier excluded-only placeholder so
    /// authorized failure classes are never masked by an excluded target (#63).
    fn record_failure(&mut self, failure: ThawFailure, countable: bool) {
        match &self.unrecoverable {
            None => self.unrecoverable = Some(failure),
            Some(ThawFailure::Incomplete {
                kind: RecoveryReason::RecoveryIncomplete,
                ..
            }) if countable => {
                self.unrecoverable = Some(failure);
            }
            Some(_) => {}
        }
    }

    /// Verifies cooperative ownership once immediately before starting a
    /// target's `FITHAW` drain, keeps its handle when uncertain or incomplete,
    /// and releases its cooperative ownership claim only after a complete drain.
    fn drain(
        &mut self,
        kernel: &dyn KernelOps,
        ownership: Option<&dyn OwnershipStore>,
        mount: Mount,
        countable: bool,
    ) {
        if let PreThawOwnership::Refused {
            kind,
            detail,
            keep_handle,
        } = verify_ownership_before_thaw(ownership, &mount)
        {
            let wire_kind = if countable {
                kind
            } else {
                RecoveryReason::RecoveryIncomplete
            };
            self.record_failure(
                ThawFailure::Incomplete {
                    mountpoint: lossy(mount.mountpoint()),
                    kind: wire_kind,
                    reason: detail,
                    thawed: 0,
                },
                countable,
            );
            self.ownership_uncertain = true;
            if keep_handle {
                self.keep.push(HeldMount { mount, countable });
            }
            return;
        }
        let drained = drain(kernel, &mount);
        if drained.successes > 0 && countable {
            self.thawed += 1;
        }
        if let Some(DrainIncomplete { kind, detail }) = drained.incomplete() {
            let wire_kind = if countable {
                kind
            } else {
                RecoveryReason::RecoveryIncomplete
            };
            let failure = ThawFailure::Incomplete {
                mountpoint: lossy(mount.mountpoint()),
                kind: wire_kind,
                reason: detail,
                thawed: 0,
            };
            tracing::error!(
                event = "fsfreeze_thaw_target_failed",
                mountpoint = %mount.mountpoint().display(),
                error = %failure,
                "target could not be thawed; draining the remaining targets"
            );
            self.record_failure(failure, countable);
            self.keep.push(HeldMount { mount, countable });
        } else if let Some(store) = ownership
            && let Err(err) = store.release(mount.dev())
        {
            let wire_kind = if countable {
                recovery_reason_for_ownership_error(&err)
            } else {
                RecoveryReason::RecoveryIncomplete
            };
            let failure = ThawFailure::Incomplete {
                mountpoint: lossy(mount.mountpoint()),
                kind: wire_kind,
                reason: err.to_string(),
                thawed: 0,
            };
            tracing::error!(
                event = "fsfreeze_ownership_release_failed",
                mountpoint = %mount.mountpoint().display(),
                error = %failure,
                "drain complete but cannot release freeze ownership claim"
            );
            self.record_failure(failure, countable);
            self.ownership_uncertain = true;
        }
    }
}

/// A mount point for guest-local error diagnostics.
fn lossy(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `FITHAW` until the first error or the iteration bound. Returns the
/// number of successes and the error that ended the drain, if any.
fn drain(kernel: &dyn KernelOps, mount: &Mount) -> Drained {
    let mut successes = 0;
    for _ in 0..MAX_THAW_ITERATIONS {
        match kernel.fithaw(mount) {
            Ok(()) => successes += 1,
            Err(err) => {
                return Drained {
                    successes,
                    first_error: Some(err),
                    capped: false,
                };
            }
        }
    }
    tracing::error!(
        event = "fsfreeze_drain_capped",
        mountpoint = %mount.mountpoint().display(),
        iterations = MAX_THAW_ITERATIONS,
        "FITHAW kept succeeding; drain stopped at the defensive bound"
    );
    Drained {
        successes,
        first_error: None,
        capped: true,
    }
}

/// Result of draining one target with repeated `FITHAW`.
#[derive(Debug)]
struct Drained {
    /// Successful `FITHAW` calls.
    successes: u32,
    /// The error that ended the drain, if any.
    first_error: Option<KernelError>,
    /// The drain hit [`MAX_THAW_ITERATIONS`] without an error.
    capped: bool,
}

/// Both the host-safe classification and the guest-local diagnostic for
/// an incomplete drain.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DrainIncomplete {
    kind: RecoveryReason,
    detail: String,
}

impl Drained {
    /// Why the target may still be frozen, if it may.
    ///
    /// A drain is complete only when the kernel's answer to `FITHAW` is
    /// one of the documented ends: `EINVAL` (the filesystem is not frozen)
    /// or the filesystem does not support freezing at all. Anything else
    /// is uncertain and keeps the marker and the frozen gate (OQ-3): an
    /// error from before the ioctl (nothing was asked of the filesystem,
    /// whatever its errno), a denied `FITHAW`, any other errno (Linux
    /// keeps a filesystem frozen when its unfreeze fails), or a drain
    /// that never converged.
    fn incomplete(&self) -> Option<DrainIncomplete> {
        if self.capped {
            return Some(DrainIncomplete {
                kind: RecoveryReason::DrainDidNotConverge,
                detail: format!(
                    "drain did not converge after {MAX_THAW_ITERATIONS} FITHAW calls (still succeeding)"
                ),
            });
        }
        let err = self.first_error.as_ref()?;
        if !err.is_ioctl_answer() {
            let kind = if err.is_permission() {
                RecoveryReason::TargetOpenPermissionDenied
            } else if err.is_wrong_filesystem() {
                RecoveryReason::TargetUnreachable
            } else {
                RecoveryReason::TargetOpenFailed
            };
            return Some(DrainIncomplete {
                kind,
                detail: format!("{err}: no FITHAW issued"),
            });
        }
        if err.is_invalid() || err.is_not_supported() {
            return None;
        }
        Some(if err.is_permission() && self.successes == 0 {
            DrainIncomplete {
                kind: RecoveryReason::PermissionDenied,
                detail: format!("first FITHAW denied: {err}"),
            }
        } else if err.is_permission() {
            DrainIncomplete {
                kind: RecoveryReason::PermissionDenied,
                detail: format!("FITHAW denied after {} successes: {err}", self.successes),
            }
        } else {
            DrainIncomplete {
                kind: RecoveryReason::IoctlFailed,
                detail: format!("FITHAW failed: {err}; the filesystem may still be frozen"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Router;
    use crate::config::Config;
    use crate::freeze_op::ManualClock;
    use crate::kernel::fake::{Call, FakeKernel, Gate, ReleaseOnDrop};
    use crate::mountinfo::StaticMounts;
    use crate::proto::{ErrorClass, parse_request};
    use crate::state::FreezeStateMachine;
    use nix::errno::Errno;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::Duration;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mountinfo")
                .join(name),
        )
        .unwrap()
    }

    /// Records every hook with the state the machine was in when the hook
    /// ran (the hook contract fixes that state).
    #[derive(Default)]
    struct Recorder(Mutex<Vec<(&'static str, FreezeState)>>);

    impl Recorder {
        fn events(&self) -> Vec<&'static str> {
            self.0.lock().unwrap().iter().map(|(e, _)| *e).collect()
        }
        /// The states seen by every occurrence of hook `event`.
        fn states_at(&self, event: &str) -> Vec<FreezeState> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(e, _)| *e == event)
                .map(|(_, s)| *s)
                .collect()
        }
        fn push(&self, ctx: &Arc<Context>, e: &'static str) {
            self.0.lock().unwrap().push((e, ctx.state.current()));
        }
    }

    impl FreezeHooks for Recorder {
        fn on_freezing(&self, ctx: &Arc<Context>) {
            self.push(ctx, "freezing");
        }
        fn on_frozen(&self, ctx: &Arc<Context>) {
            self.push(ctx, "frozen");
        }
        fn on_thaw_claimed(&self, ctx: &Arc<Context>) {
            self.push(ctx, "thaw_claimed");
        }
        fn on_thawed(&self, ctx: &Arc<Context>) {
            self.push(ctx, "thawed");
        }
        fn on_heartbeat(&self, ctx: &Arc<Context>) {
            self.push(ctx, "heartbeat");
        }
    }

    struct Rig {
        ctx: Arc<Context>,
        kernel: Arc<FakeKernel>,
        hooks: Arc<Recorder>,
        /// The operation deadline's clock: it moves only when a test
        /// moves it, so no unit test here ever expires by real time.
        clock: ManualClock,
        _dir: tempfile::TempDir,
    }

    /// A mount table whose contents can be replaced mid-test and whose reads
    /// can be made to fail (`EMFILE`, as when the retained handles exhausted
    /// the descriptors) and to work again.
    struct SwitchableMounts {
        table: std::sync::Mutex<String>,
        fail: std::sync::atomic::AtomicBool,
    }

    impl SwitchableMounts {
        fn new(table: impl Into<String>) -> Self {
            SwitchableMounts {
                table: std::sync::Mutex::new(table.into()),
                fail: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn set_table(&self, table: impl Into<String>) {
            *self.table.lock().unwrap() = table.into();
        }

        fn fail_reads(&self, fail: bool) {
            self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl MountSource for SwitchableMounts {
        fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::Internal(
                    "cannot read /proc/self/mountinfo: Too many open files (os error 24)".into(),
                ));
            }
            Ok(self.table.lock().unwrap().as_bytes().to_vec())
        }
    }

    impl Rig {
        fn new(state: FreezeState, mountinfo: &str) -> Self {
            Self::with_mounts(state, Arc::new(StaticMounts(fixture(mountinfo))))
        }

        fn with_mounts(state: FreezeState, mounts: Arc<dyn MountSource>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let kernel = Arc::new(FakeKernel::new());
            let hooks = Arc::new(Recorder::default());
            let clock = ManualClock::new();
            let ctx = Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(state)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(mounts)
            .with_hooks(hooks.clone())
            .with_freeze_clock(Arc::new(clock.clone()));
            Rig {
                ctx: Arc::new(ctx),
                kernel,
                hooks,
                clock,
                _dir: dir,
            }
        }

        fn nested() -> Self {
            Self::new(FreezeState::Thawed, "nested.txt")
        }

        /// A rig whose freeze operation deadline is `timeout` on the
        /// manual clock.
        fn with_operation_timeout(self, timeout: Duration) -> Self {
            let ctx = Arc::try_unwrap(self.ctx)
                .unwrap_or_else(|_| panic!("unshared"))
                .with_freeze_operation_timeout(timeout);
            Rig {
                ctx: Arc::new(ctx),
                ..self
            }
        }

        /// Moves the clock past the operation deadline.
        fn expire(&self) {
            self.clock
                .advance(self.ctx.freeze_operation_timeout() + Duration::from_millis(1));
        }

        /// Starts a freeze on the runtime so the test can act while its
        /// reply is pending.
        fn spawn_freeze(&self) -> tokio::task::JoinHandle<Result<Value, Error>> {
            let ctx = Arc::clone(&self.ctx);
            tokio::spawn(async move {
                freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#)).await
            })
        }

        /// Polls until `done` (yielding, so the driver runs). The bound is
        /// only a guard against a hung test; the tests order their events
        /// with gates and the manual clock, never with this loop.
        async fn wait_for(&self, what: &str, mut done: impl FnMut(&Rig) -> bool) {
            let start = std::time::Instant::now();
            while !done(self) {
                assert!(
                    start.elapsed() < Duration::from_secs(30),
                    "timed out: {what}"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        fn marker(&self) -> &Marker {
            &self.ctx.marker
        }

        fn state(&self) -> FreezeState {
            self.ctx.state.current()
        }

        fn fifreezes(&self) -> Vec<PathBuf> {
            self.kernel
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Fifreeze(p) => Some(p),
                    _ => None,
                })
                .collect()
        }

        fn fithaws(&self) -> Vec<PathBuf> {
            self.kernel
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Fithaw(p) => Some(p),
                    _ => None,
                })
                .collect()
        }

        fn opens(&self) -> Vec<PathBuf> {
            self.kernel
                .calls()
                .into_iter()
                .filter_map(|c| match c {
                    Call::Open(p, _) => Some(p),
                    _ => None,
                })
                .collect()
        }

        fn held(&self) -> usize {
            self.ctx.frozen_mount_count()
        }
    }

    fn req(json: &str) -> Request {
        parse_request(json.as_bytes()).unwrap()
    }

    fn paths(list: &[&str]) -> Vec<PathBuf> {
        list.iter().map(PathBuf::from).collect()
    }

    /// Runs `f` under a WARN-level JSON subscriber and returns what it logged.
    fn capture_warnings(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Sink::default();
        let router = Router::new(Box::new(sink.clone()));
        tracing::subscriber::with_default(
            crate::audit::subscriber(tracing::Level::WARN, router.clone()),
            f,
        );
        assert!(
            router.settle(Duration::from_secs(1)),
            "audit writer did not settle"
        );
        String::from_utf8(sink.0.lock().unwrap().clone()).unwrap()
    }

    /// A context whose audit router has a tiny ring, plus a writer into it.
    fn ring_ctx(capacity: usize) -> (Arc<Context>, Router) {
        let router = Router::with_ring_capacity(Box::new(std::io::sink()), capacity);
        let ctx = Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            Marker::for_tests(),
        );
        (Arc::new(ctx), router)
    }

    #[test]
    fn lifecycle_hooks_enter_ring_on_freezing_and_flush_on_thawed() {
        use tracing_subscriber::fmt::MakeWriter;
        let (ctx, router) = ring_ctx(64);
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Normal);
        LifecycleHooks.on_freezing(&ctx);
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Ring);
        // Nothing lost: the thaw flushes silently.
        let text = capture_warnings(|| LifecycleHooks.on_thawed(&ctx));
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Normal);
        assert!(!text.contains("audit_ring_overflowed"), "{text}");
        // Overflow the ring during a second window: the thaw reports the loss.
        LifecycleHooks.on_freezing(&ctx);
        for _ in 0..8 {
            std::io::Write::write_all(&mut router.make_writer(), &[b'x'; 30]).unwrap();
        }
        assert!(router.lost() > 0);
        let text = capture_warnings(|| LifecycleHooks.on_thawed(&ctx));
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Normal);
        assert!(
            text.contains("\"event\":\"audit_ring_overflowed\""),
            "{text}"
        );
        assert!(text.contains("\"lost\":"), "{text}");
    }

    #[tokio::test]
    async fn start_recovery_requires_the_frozen_state() {
        let rig = Rig::new(FreezeState::Thawed, "nested.txt");
        let err = start_recovery(&rig.ctx).unwrap_err();
        assert!(
            err.to_string().contains("requires the Frozen state"),
            "{err}"
        );
        assert!(rig.hooks.events().is_empty());

        let rig = Rig::new(FreezeState::Frozen, "nested.txt");
        start_recovery(&rig.ctx).unwrap();
        assert_eq!(rig.hooks.events(), vec!["freezing", "frozen"]);
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[test]
    fn rollback_tolerates_a_marker_removed_meanwhile() {
        // A hard error on the second target rolls back the first; if the
        // marker vanished during the freeze, its absence is not an error.
        let rig = Rig::nested();
        let marker_path = rig.marker().path().to_path_buf();
        rig.kernel.script_freeze_error("/home/data", Errno::EIO);
        rig.kernel.set_hook(Box::new(move |call| {
            if matches!(call, Call::Fifreeze(p) if p == Path::new("/home/data")) {
                let _ = std::fs::remove_file(&marker_path);
            }
        }));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut result = None;
        let text = capture_warnings(|| {
            result = Some(runtime.block_on(freeze(
                &rig.ctx,
                &req(r#"{"execute":"guest-fsfreeze-freeze"}"#),
            )));
        });
        let err = result.unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "freeze failed: FIFREEZE failed; rolled back (1 target(s) thawed); state thawed"
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert!(text.contains("\"event\":\"fsfreeze_rollback\""), "{text}");
        assert!(text.contains("/home/data"), "local log keeps path: {text}");
        assert!(!text.contains("marker_remove_failed"), "{text}");
    }

    #[test]
    fn an_alias_in_use_is_logged_and_a_first_pathname_that_works_is_not() {
        // bind_mounts.txt: /data (8:2) has the alias /srv/exports. The
        // `fsfreeze_alias` record is the operator's only sign that a
        // pathname no longer leads to its superblock, so it must fire
        // exactly when an alias was needed.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        let quiet = capture_warnings(|| {
            runtime
                .block_on(freeze(
                    &rig.ctx,
                    &req(r#"{"execute":"guest-fsfreeze-freeze"}"#),
                ))
                .unwrap();
        });
        assert!(!quiet.contains("fsfreeze_alias"), "{quiet}");
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        rig.kernel.script_mount_device("/data", (8, 9));
        let text = capture_warnings(|| {
            runtime
                .block_on(freeze(
                    &rig.ctx,
                    &req(r#"{"execute":"guest-fsfreeze-freeze"}"#),
                ))
                .unwrap();
        });
        assert!(text.contains("\"event\":\"fsfreeze_alias\""), "{text}");
        assert!(text.contains("\"alias\":\"/srv/exports\""), "{text}");
        assert_eq!(rig.fifreezes(), paths(&["/srv/exports", "/"]));
    }

    #[tokio::test]
    async fn status_reports_thawed_or_frozen() {
        for (state, expected, heartbeats) in [
            (FreezeState::Thawed, "thawed", 0),
            (FreezeState::Freezing, "frozen", 0),
            (FreezeState::Frozen, "frozen", 1),
            (FreezeState::Thawing, "frozen", 0),
        ] {
            let rig = Rig::new(state, "nested.txt");
            let value = status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
                .await
                .unwrap();
            assert_eq!(value, json!(expected), "{state}");
            assert_eq!(
                rig.hooks
                    .events()
                    .iter()
                    .filter(|e| **e == "heartbeat")
                    .count(),
                heartbeats,
                "{state}: heartbeat only while Frozen"
            );
            assert!(rig.kernel.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn freeze_calls_fifreeze_in_reverse_mount_order_and_counts_successes() {
        let rig = Rig::nested();
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4));
        assert_eq!(
            rig.fifreezes(),
            paths(&["/home/data/deep", "/home/data", "/home", "/"])
        );
        assert!(rig.fithaws().is_empty());
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
    }

    #[tokio::test]
    async fn freeze_creates_marker_before_first_fifreeze() {
        let rig = Rig::nested();
        let marker = rig.marker().clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        rig.kernel.set_hook(Box::new(move |call| {
            if let Call::Fifreeze(_) = call {
                seen2.lock().unwrap().push(marker.exists());
            }
        }));
        assert!(!rig.marker().exists());
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(*seen.lock().unwrap(), [true, true, true, true]);
    }

    #[tokio::test]
    async fn freeze_without_marker_performs_no_ioctl() {
        let rig = Rig::nested();
        // The marker's directory vanishes after it was pinned: creation
        // fails (ENOENT on the dead directory) and no ioctl follows.
        let gone = tempfile::tempdir().unwrap();
        let marker = Marker::open(gone.path().join("frozen")).unwrap();
        drop(gone);
        let ctx = Arc::new(
            Context::new(
                rig.ctx.config.clone(),
                rig.ctx.state.clone(),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(rig.kernel.clone())
            .with_mounts(rig.ctx.mounts.clone())
            .with_hooks(rig.hooks.clone()),
        );
        let err = freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        assert!(err.to_string().contains("recovery marker"), "{err}");
        assert!(rig.kernel.calls().is_empty(), "no ioctl at all");
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert_eq!(rig.hooks.events(), ["freezing", "thawed"]);
    }

    #[tokio::test]
    async fn eopnotsupp_is_skipped_not_counted_and_not_rolled_back() {
        let rig = Rig::nested();
        rig.kernel
            .script_freeze_error("/home/data", Errno::EOPNOTSUPP);
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(3), "skipped target is not counted");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.fithaws().is_empty());

        // A later hard error must not thaw the unsupported target.
        let rig = Rig::nested();
        rig.kernel
            .script_freeze_error("/home/data", Errno::EOPNOTSUPP);
        rig.kernel.script_freeze_error("/", Errno::EIO);
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("rolled back"), "{err}");
        assert_eq!(
            rig.fithaws(),
            paths(&["/home", "/home", "/home/data/deep", "/home/data/deep"]),
            "each processed target is drained (success + EINVAL); /home/data is not"
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn ebusy_is_not_counted_but_is_retained_in_thaw_plan() {
        let rig = Rig::nested();
        rig.kernel.script_freeze_error("/home", Errno::EBUSY);
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(3), "EBUSY does not inflate the count (AC17)");
        assert_eq!(rig.state(), FreezeState::Frozen);

        // On rollback the EBUSY target is drained like the others.
        let rig = Rig::nested();
        rig.kernel.script_freeze_error("/home", Errno::EBUSY);
        rig.kernel.script_freeze_error("/", Errno::EIO);
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        let mut drained = rig.fithaws();
        drained.dedup();
        assert_eq!(
            drained,
            paths(&["/home", "/home/data", "/home/data/deep"]),
            "forward order, EBUSY target included"
        );
    }

    #[tokio::test]
    async fn hard_error_rolls_back_processed_in_forward_order_and_reports_error() {
        let rig = Rig::nested();
        // Freeze order: deep, data, home, /. Fail on the second (data).
        rig.kernel.script_freeze_error("/home/data", Errno::EIO);
        let marker = rig.marker().clone();
        let marker_during_drain = Arc::new(Mutex::new(Vec::new()));
        let seen = marker_during_drain.clone();
        rig.kernel.set_hook(Box::new(move |call| {
            if let Call::Fithaw(_) = call {
                seen.lock().unwrap().push(marker.exists());
            }
        }));
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        assert_eq!(
            err.to_string(),
            "freeze failed: FIFREEZE failed; rolled back (1 target(s) thawed); state thawed"
        );
        assert_eq!(rig.fifreezes(), paths(&["/home/data/deep", "/home/data"]));
        // Only the processed target is drained (once, then EINVAL).
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data/deep", "/home/data/deep"])
        );
        assert_eq!(
            *marker_during_drain.lock().unwrap(),
            [true, true],
            "marker removed only after the drain"
        );
        assert!(!rig.marker().exists());
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert_eq!(rig.hooks.events(), ["freezing", "thawed"]);
    }

    #[tokio::test]
    async fn rollback_of_a_retained_target_already_thawed_by_its_freezer_completes() {
        // `deep` is frozen by another freezer (EBUSY, retained for thaw);
        // the freeze then fails hard on `data`. By the time the rollback
        // drains `deep`, the other freezer has thawed it: its first FITHAW
        // answers EINVAL with no success. That is the ordinary end of a
        // drain, not a denial: the rollback completes, the marker goes,
        // and the agent is Thawed rather than wedged Frozen.
        let rig = Rig::nested();
        rig.kernel
            .script_freeze_error("/home/data/deep", Errno::EBUSY);
        rig.kernel.script_freeze_error("/home/data", Errno::EIO);
        rig.kernel.script_thaw_successes("/home/data/deep", 0);
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "freeze failed: FIFREEZE failed; rolled back (0 target(s) thawed); state thawed"
        );
        assert_eq!(rig.fithaws(), paths(&["/home/data/deep"]));
        assert!(!rig.marker().exists(), "nothing is frozen: the marker goes");
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert_eq!(rig.hooks.events(), ["freezing", "thawed"]);
    }

    #[test]
    fn a_drain_is_complete_only_when_the_kernel_says_not_frozen_or_unsupported() {
        let drained = |successes, err: Option<KernelError>, capped| Drained {
            successes,
            first_error: err,
            capped,
        };
        let e = |errno| Some(KernelError::Errno(errno));
        // The documented ends of a drain: EINVAL (not frozen), after any
        // number of successes, or a filesystem that cannot freeze at all.
        assert_eq!(drained(3, e(Errno::EINVAL), false).incomplete(), None);
        assert_eq!(drained(0, e(Errno::EINVAL), false).incomplete(), None);
        assert_eq!(drained(0, e(Errno::EOPNOTSUPP), false).incomplete(), None);
        assert_eq!(drained(0, e(Errno::ENOTTY), false).incomplete(), None);
        // A denied FITHAW leaves the target frozen (OQ-3), whether first...
        let denied = drained(0, e(Errno::EPERM), false).incomplete().unwrap();
        assert_eq!(denied.kind, RecoveryReason::PermissionDenied);
        assert!(
            denied.detail.starts_with("first FITHAW denied: EPERM"),
            "{denied:?}"
        );
        // ...or after successes: the remaining depth is unknown.
        let denied = drained(2, e(Errno::EACCES), false).incomplete().unwrap();
        assert_eq!(denied.kind, RecoveryReason::PermissionDenied);
        assert!(
            denied.detail.contains("denied after 2 successes"),
            "{denied:?}"
        );
        // Any other errno is uncertain: Linux keeps a filesystem frozen
        // when its unfreeze fails.
        let failed = drained(0, e(Errno::EIO), false).incomplete().unwrap();
        assert_eq!(failed.kind, RecoveryReason::IoctlFailed);
        assert!(failed.detail.contains("FITHAW failed: EIO"), "{failed:?}");
        assert!(drained(1, e(Errno::ENOSPC), false).incomplete().is_some());
        // An error from before the ioctl means no FITHAW was issued, so
        // nothing is known about the filesystem: incomplete, whatever the
        // errno, even one that would end a drain as the ioctl's answer.
        let unopened = drained(0, Some(KernelError::Open(Errno::EMFILE)), false)
            .incomplete()
            .unwrap();
        assert_eq!(unopened.kind, RecoveryReason::TargetOpenFailed);
        assert!(
            unopened.detail.contains("cannot open mountpoint: EMFILE"),
            "{unopened:?}"
        );
        assert!(unopened.detail.contains("no FITHAW issued"), "{unopened:?}");
        let denied_open = drained(0, Some(KernelError::Open(Errno::EACCES)), false)
            .incomplete()
            .unwrap();
        assert_eq!(denied_open.kind, RecoveryReason::TargetOpenPermissionDenied);
        for errno in [
            Errno::EINVAL,
            Errno::EOPNOTSUPP,
            Errno::ENOTTY,
            Errno::ENOSYS,
        ] {
            let reason = drained(0, Some(KernelError::Open(errno)), false)
                .incomplete()
                .unwrap_or_else(|| panic!("Open({errno}) must not complete a drain"));
            assert_eq!(reason.kind, RecoveryReason::TargetOpenFailed);
            assert!(reason.detail.contains("no FITHAW issued"), "{reason:?}");
            let reason = drained(2, Some(KernelError::Open(errno)), false)
                .incomplete()
                .unwrap_or_else(|| {
                    panic!("Open({errno}) after successes must not complete a drain")
                });
            assert_eq!(reason.kind, RecoveryReason::TargetOpenFailed);
            assert!(reason.detail.contains("no FITHAW issued"), "{reason:?}");
        }
        let elsewhere = drained(
            0,
            Some(KernelError::WrongFilesystem {
                expected: (8, 2),
                found: (8, 3),
            }),
            false,
        )
        .incomplete()
        .unwrap();
        assert_eq!(elsewhere.kind, RecoveryReason::TargetUnreachable);
        assert!(
            elsewhere.detail.contains("not on the planned 8:2"),
            "{elsewhere:?}"
        );
        assert!(
            elsewhere.detail.contains("no FITHAW issued"),
            "{elsewhere:?}"
        );
        // A drain that never converged is incomplete whatever else happened.
        let capped = drained(u32::MAX, None, true).incomplete().unwrap();
        assert_eq!(capped.kind, RecoveryReason::DrainDidNotConverge);
        assert!(capped.detail.contains("did not converge"), "{capped:?}");
        assert!(capped.detail.contains("still succeeding"), "{capped:?}");
    }

    #[tokio::test]
    async fn rollback_with_an_uncertain_thaw_error_keeps_the_frozen_state_and_marker() {
        // deep and data were frozen, home fails hard; the rollback's
        // FITHAW on data fails with EIO. That is not the kernel's "not
        // frozen" answer: data may still be frozen, so the marker and the
        // frozen gate stay, and deep is still drained.
        let rig = Rig::nested();
        rig.kernel.script_freeze_error("/home", Errno::EIO);
        rig.kernel.script_thaw_error("/home/data", Errno::EIO);
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze failed: FIFREEZE failed; rollback incomplete (FITHAW failed; filesystem may still be frozen, 1 target(s) thawed); state frozen, marker retained"
        );
        assert!(
            !text.contains("/home/data"),
            "wire error must hide mounts: {text}"
        );
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data", "/home/data/deep", "/home/data/deep"])
        );
        assert!(rig.marker().exists(), "marker retained");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
    }

    #[tokio::test]
    async fn freeze_while_not_thawed_is_generic_error() {
        for state in [
            FreezeState::Freezing,
            FreezeState::Frozen,
            FreezeState::Thawing,
        ] {
            let rig = Rig::new(state, "nested.txt");
            let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
                .await
                .unwrap_err();
            assert_eq!(err.class(), ErrorClass::GenericError, "{state}");
            assert!(rig.kernel.calls().is_empty());
            assert_eq!(rig.state(), state);
            assert!(rig.hooks.events().is_empty());
        }
    }

    #[tokio::test]
    async fn freeze_list_restricts_to_requested_mountpoints() {
        let rig = Rig::nested();
        let value = freeze_list(
            &rig.ctx,
            &req(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/home","/home/data/deep","/proc","/nope"]}}"#),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(2));
        assert_eq!(rig.fifreezes(), paths(&["/home/data/deep", "/home"]));
        assert_eq!(rig.state(), FreezeState::Frozen);
        // Without `mountpoints` it behaves like a full freeze.
        let rig = Rig::nested();
        let value = freeze_list(
            &rig.ctx,
            &req(r#"{"execute":"guest-fsfreeze-freeze-list"}"#),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(4));
        // Unknown keys are rejected.
        let rig = Rig::nested();
        let err = freeze_list(
            &rig.ctx,
            &req(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"paths":["/"]}}"#),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::InvalidArguments(_)));
        assert_eq!(rig.state(), FreezeState::Thawed);
    }

    #[tokio::test]
    async fn freeze_list_over_an_overmount_counts_the_visible_superblock_only() {
        // #43 §1, the coverage contract: /data is 8:3 mounted over 8:2,
        // whose first name /data is hidden (it stays reachable as
        // /data-alias). A controller requesting /data and an unsupported
        // /required must see a count of 1, not 2: the hidden name cannot
        // contribute 8:2 to the count of a request that never named it.
        let rig = Rig::new(FreezeState::Thawed, "hidden_mount.txt");
        let value = freeze_list(
            &rig.ctx,
            &req(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/data","/required"]}}"#),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(1));
        let opened: Vec<(PathBuf, (u32, u32))> = rig
            .kernel
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Open(p, dev) => Some((p, dev)),
                _ => None,
            })
            .collect();
        assert_eq!(opened, [(PathBuf::from("/data"), (8, 3))]);
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[tokio::test]
    async fn freeze_list_freezes_what_the_requested_pathname_leads_to_not_a_later_row() {
        // The external review's moved-mount arrangement: A (8:5) moved over
        // B (8:2) at /data keeps its earlier row. A request for /data must
        // freeze A, opened on /data, and leave B alone; the count is 1.
        let rig = Rig::new(FreezeState::Thawed, "moved_mount.txt");
        let value = freeze_list(
            &rig.ctx,
            &req(
                r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/data"]}}"#,
            ),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(1));
        let opened: Vec<(PathBuf, (u32, u32))> = rig
            .kernel
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Open(p, dev) => Some((p, dev)),
                _ => None,
            })
            .collect();
        assert_eq!(opened, [(PathBuf::from("/data"), (8, 5))]);
        assert_eq!(rig.fifreezes(), paths(&["/data"]));
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[tokio::test]
    async fn freeze_list_freezes_the_mount_over_a_directory_not_the_one_it_hides() {
        // A (8:2) at /data/nested is hidden by B (8:3) mounted at /data, a
        // plain directory until then; C (8:4) is at the /data/nested B
        // provides. A request for /data/nested freezes C through that
        // name, A untouched; the count is 1.
        let rig = Rig::new(FreezeState::Thawed, "directory_overmount.txt");
        let value = freeze_list(
            &rig.ctx,
            &req(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/data/nested"]}}"#),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(1));
        let opened: Vec<(PathBuf, (u32, u32))> = rig
            .kernel
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Open(p, dev) => Some((p, dev)),
                _ => None,
            })
            .collect();
        assert_eq!(opened, [(PathBuf::from("/data/nested"), (8, 4))]);
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[tokio::test]
    async fn a_thaw_of_a_completed_operation_is_not_held_by_a_superblock_it_never_froze() {
        // The external review's lifecycle over directory_overmount.txt: A
        // (8:2) is hidden under B at /data and reachable by no name; the
        // request freezes C (8:4) through /data/nested. The thaw of that
        // operation drains what the operation published (C, through its
        // held descriptor) and nothing else: A was never its obligation,
        // so A being unreachable cannot hold the thaw. The marker goes,
        // the state is `Thawed`, and the next cycle is admitted.
        let rig = Rig::new(FreezeState::Thawed, "directory_overmount.txt");
        rig.kernel.script_mount_device("/data/nested", (8, 4));
        let freeze_req = req(
            r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/data/nested"]}}"#,
        );
        for cycle in 0..2 {
            // The fake's thaw budget is per path and consumed by a drain:
            // C is frozen once per cycle.
            rig.kernel.script_thaw_successes("/data/nested", 1);
            let value = freeze_list(&rig.ctx, &freeze_req).await.unwrap();
            assert_eq!(value, json!(1), "cycle {cycle}");
            assert_eq!(rig.state(), FreezeState::Frozen);
            assert!(rig.marker().exists());
            rig.kernel.clear_calls();
            let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
                .await
                .unwrap();
            assert_eq!(value, json!(1), "cycle {cycle}");
            assert!(
                rig.opens().is_empty(),
                "no pathname consulted: {:?}",
                rig.opens()
            );
            assert_eq!(rig.fithaws(), paths(&["/data/nested", "/data/nested"]));
            assert_eq!(rig.state(), FreezeState::Thawed);
            assert!(!rig.marker().exists(), "marker removed after cycle {cycle}");
            assert_eq!(rig.held(), 0);
            rig.kernel.clear_calls();
        }
    }

    #[tokio::test]
    async fn a_recovery_drain_over_the_same_topology_still_reports_the_hidden_superblock() {
        // After a restart nothing is held and nothing is known: the drain
        // discovers every planned superblock, and A, reachable by no
        // name, is reported unreachable with the marker retained (§4.2),
        // the conservative rule the tracked thaw above does not need.
        let rig = Rig::new(FreezeState::Frozen, "directory_overmount.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_mount_device("/data/nested", (8, 4));
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "thaw incomplete: target unreachable; no FITHAW issued (3 target(s) thawed); state frozen, marker retained"
        );
        for forbidden in ["8:2", "/data"] {
            assert!(!text.contains(forbidden), "leaked {forbidden} in {text}");
        }
        assert_eq!(
            rig.fithaws(),
            paths(&["/", "/", "/data", "/data", "/data/nested", "/data/nested"]),
            "B and C are drained; A cannot be reached"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
    }

    #[tokio::test]
    async fn freeze_list_under_a_self_parented_root_freezes_the_requested_target() {
        // The namespace root carries its own id as its parent id (valid
        // per proc_pid_mountinfo(5)): /data is still resolved from it,
        // selected and frozen through the requested name; the count is 1.
        let rig = Rig::new(FreezeState::Thawed, "self_parented_root.txt");
        let value = freeze_list(
            &rig.ctx,
            &req(
                r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/data"]}}"#,
            ),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(1));
        assert_eq!(rig.fifreezes(), paths(&["/data"]));
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[tokio::test]
    async fn a_requested_pathname_that_does_not_lead_to_the_selected_superblock_fails_the_operation()
     {
        // Belt and braces for the selection: if what the kernel opens at
        // the requested name is not the selected superblock, the target
        // fails and the operation with it; an alias of the selected
        // superblock never stands in, since that would turn a wrong
        // selection into a count.
        let rig = Rig::new(FreezeState::Thawed, "moved_mount.txt");
        rig.kernel.script_mount_device("/data", (8, 2));
        let err = freeze_list(
            &rig.ctx,
            &req(
                r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/data"]}}"#,
            ),
        )
        .await
        .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze failed: target unreachable; no FIFREEZE issued; rolled back (0 target(s) thawed); state thawed"
        );
        for forbidden in ["/data", "8:2", "8:5"] {
            assert!(!text.contains(forbidden), "leaked {forbidden} in {text}");
        }
        assert!(
            rig.fifreezes().is_empty(),
            "nothing frozen through an alias"
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn freeze_list_with_unknown_paths_freezes_nothing_and_returns_0() {
        let rig = Rig::nested();
        let value = freeze_list(
            &rig.ctx,
            &req(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/nope","/proc"]}}"#),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(0));
        assert!(rig.fifreezes().is_empty());
        // Zero targets is a zero-work operation (#43 §2): nothing to
        // recover, so it settles Thawed with the marker removed.
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn an_operation_that_freezes_nothing_settles_thawed_with_the_marker_removed() {
        // #43 §2: an empty plan leaves no frozen, busy, uncertain or
        // outstanding target, so there is nothing to recover: the reply
        // is 0, the marker is gone, the state is Thawed, no `frozen`
        // hook (no watchdog), and the next freeze is admitted.
        let rig = Rig::new(FreezeState::Thawed, "no_freezable.txt");
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(0));
        assert!(rig.fifreezes().is_empty());
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists(), "nothing to recover: no marker");
        assert_eq!(rig.hooks.events(), ["freezing", "thawed"]);
        assert!(rig.ctx.freeze_op().is_none());
        let value = status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!("thawed"));
        // A freeze-list that matches nothing is the same case (C-12).
        let rig = Rig::nested();
        let value = freeze_list(
            &rig.ctx,
            &req(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/nope","/proc"]}}"#),
        )
        .await
        .unwrap();
        assert_eq!(value, json!(0));
        assert!(rig.fifreezes().is_empty());
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        // And the next freeze is admitted at once.
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4));
    }

    #[tokio::test]
    async fn a_freeze_list_count_is_the_number_of_requested_superblocks_this_operation_froze() {
        // The coverage contract (#43 §2, C-24): the reply counts the
        // distinct superblocks among the requested mount points on which
        // this operation's FIFREEZE succeeded, and nothing else. A
        // controller that requests one mount point per required
        // superblock and demands `count == requested` therefore fails
        // closed on a missing, unsupported, unmatched or busy target, and
        // an alias of an already requested superblock never inflates it.
        let list = |mountpoints: &[&str]| {
            let json = json!({"execute": "guest-fsfreeze-freeze-list", "arguments": {"mountpoints": mountpoints}});
            parse_request(json.to_string().as_bytes()).unwrap()
        };
        // Duplicate aliases: three names of one ext4 superblock.
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        let value = freeze_list(&rig.ctx, &list(&["/", "/var/www", "/mnt/rootbind"]))
            .await
            .unwrap();
        assert_eq!(value, json!(1), "one superblock, whatever its names");
        assert_eq!(rig.fifreezes(), paths(&["/"]));
        // Missing target: a required path outside the plan lowers the
        // count below the number requested.
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        let value = freeze_list(&rig.ctx, &list(&["/data", "/nope"]))
            .await
            .unwrap();
        assert_eq!(value, json!(1));
        assert_eq!(rig.fifreezes(), paths(&["/data"]));
        // Mixed supported/unsupported: the unsupported one is skipped, so
        // the count says the request is not fully covered.
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        rig.kernel.script_freeze_error("/data", Errno::EOPNOTSUPP);
        let value = freeze_list(&rig.ctx, &list(&["/", "/data"])).await.unwrap();
        assert_eq!(value, json!(1));
        // EBUSY under the single-freezer assumption is another freezer's
        // freeze, not this operation's: not counted (AC17), retained for
        // the drain, and the count again says "not fully covered".
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        rig.kernel.script_freeze_error("/data", Errno::EBUSY);
        let value = freeze_list(&rig.ctx, &list(&["/", "/data"])).await.unwrap();
        assert_eq!(value, json!(1));
        assert_eq!(rig.held(), 2, "both handles are held for the thaw");
        // Full coverage: exactly the number of distinct superblocks, each
        // frozen through the name the request gave for it (an alias here),
        // never through another name of the same superblock.
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        let value = freeze_list(&rig.ctx, &list(&["/", "/srv/exports"]))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert_eq!(rig.fifreezes(), paths(&["/srv/exports", "/"]));
    }

    #[tokio::test]
    async fn an_entirely_skipped_plan_settles_thawed_too() {
        // Every target answers EOPNOTSUPP: nothing was frozen, nothing is
        // held, nothing is outstanding. Same rule as the empty plan.
        let rig = Rig::new(FreezeState::Thawed, "simple.txt");
        rig.kernel.script_freeze_error("/", Errno::EOPNOTSUPP);
        rig.kernel.script_freeze_error("/home", Errno::EOPNOTSUPP);
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(0));
        assert_eq!(rig.fifreezes(), paths(&["/home", "/"]));
        assert!(rig.fithaws().is_empty(), "nothing to drain");
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["freezing", "thawed"]);
    }

    #[tokio::test]
    async fn a_zero_count_with_a_busy_target_keeps_the_conservative_state() {
        // Not `successful_freezes == 0` alone: an EBUSY target is held for
        // the drain (§4.2), so the operation settles Frozen with the
        // marker and the watchdog, and a thaw drains it.
        let rig = Rig::new(FreezeState::Thawed, "simple.txt");
        rig.kernel.script_freeze_error("/", Errno::EBUSY);
        rig.kernel.script_freeze_error("/home", Errno::EOPNOTSUPP);
        rig.kernel.script_thaw_successes("/home", 0);
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(0), "EBUSY is not counted (AC17)");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
        assert_eq!(rig.held(), 1, "the busy target's handle is retained");
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(1), "the retained target is drained");
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn a_zero_work_operation_whose_marker_cannot_be_removed_stays_frozen() {
        // Cleanup failed: the marker path was replaced by a non-empty
        // directory while the last (skipped) target was being processed,
        // so unlink fails. The conservative state is kept (the next start
        // would recover) and the reply is an error, never a 0 that reads
        // as a clean settlement.
        let rig = Rig::new(FreezeState::Thawed, "simple.txt");
        rig.kernel.script_freeze_error("/", Errno::EOPNOTSUPP);
        rig.kernel.script_freeze_error("/home", Errno::EOPNOTSUPP);
        let marker_path = rig.marker().path().to_path_buf();
        rig.kernel.set_hook(Box::new(move |call| {
            if matches!(call, Call::Fifreeze(p) if p == Path::new("/")) {
                let _ = std::fs::remove_file(&marker_path);
                std::fs::create_dir(&marker_path).unwrap();
                std::fs::write(marker_path.join("child"), b"x").unwrap();
            }
        }));
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("nothing was frozen")
                && err.to_string().contains("cannot remove recovery marker"),
            "{err}"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().path().exists(), "marker path retained");
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
    }

    #[tokio::test]
    async fn thaw_drains_each_mountpoint_until_error_and_counts_once() {
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_successes("/", 3);
        rig.kernel.script_thaw_successes("/home", 1);
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert_eq!(
            rig.fithaws(),
            paths(&["/", "/", "/", "/", "/home", "/home"]),
            "3 + EINVAL on /, 1 + EINVAL on /home, forward order"
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["thaw_claimed", "thawed"]);
        // A target that never succeeds is not counted and does not fail
        // the thaw (EINVAL is the normal end of a drain).
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.kernel.script_thaw_successes("/home", 0);
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(1));
        assert_eq!(rig.state(), FreezeState::Thawed);
    }

    #[tokio::test]
    async fn thaw_from_thawed_state_still_drains() {
        let rig = Rig::new(FreezeState::Thawed, "simple.txt");
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert_eq!(rig.fithaws().len(), 4);
        assert_eq!(rig.state(), FreezeState::Thawed);
        // No marker to remove is fine for a recovery drain.
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["thaw_claimed", "thawed"]);
        // Thaw while a transition is in progress is refused.
        for state in [FreezeState::Freezing, FreezeState::Thawing] {
            let rig = Rig::new(state, "simple.txt");
            let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
                .await
                .unwrap_err();
            assert_eq!(err.class(), ErrorClass::GenericError);
            assert!(rig.kernel.calls().is_empty());
            assert_eq!(rig.state(), state);
        }
    }

    #[tokio::test]
    async fn thaw_removes_marker_only_after_all_drains() {
        let rig = Rig::new(FreezeState::Frozen, "nested.txt");
        rig.marker().create().unwrap();
        let marker = rig.marker().clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        rig.kernel.set_hook(Box::new(move |call| {
            if let Call::Fithaw(_) = call {
                seen2.lock().unwrap().push(marker.exists());
            }
        }));
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 8, "4 targets × (1 success + EINVAL)");
        assert!(seen.iter().all(|present| *present));
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn thaw_keeps_marker_and_returns_frozen_on_unrecoverable_failure() {
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_error("/home", Errno::EPERM);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        assert!(err.to_string().contains("marker retained"), "{err}");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
        assert_eq!(
            rig.hooks.events(),
            ["thaw_claimed", "frozen"],
            "no `thawed` hook; `frozen` re-arms the watchdog (§4.4)"
        );
        // The host can retry; a now-permitted drain completes.
        let rig2 = Rig::new(FreezeState::Frozen, "simple.txt");
        rig2.marker().create().unwrap();
        let value = thaw(&rig2.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));

        // Any other errno on a FITHAW is uncertain, not a completed drain:
        // Linux keeps a filesystem frozen when its unfreeze fails, so the
        // marker and the frozen gate are retained (OQ-3). The later target
        // is still drained.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_error("/", Errno::EIO);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "thaw incomplete: FITHAW failed; filesystem may still be frozen (1 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(rig.fithaws(), paths(&["/", "/home", "/home"]));
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());

        // A mountpoint that cannot be opened (EMFILE) never received a
        // FITHAW at all: nothing is known about the filesystem, so it is
        // treated the same way, and the reason says no ioctl ran.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_open_error("/home", Errno::EMFILE);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "thaw incomplete: target unreachable; no FITHAW issued (1 target(s) thawed); state frozen, marker retained"
        );
        assert!(
            !text.contains("/home") && !text.contains("8:2"),
            "wire error must hide mount and device: {text}"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());

        // The documented end of a drain on a target that was never frozen
        // (EINVAL at once) completes normally, as does a filesystem that
        // does not support freezing.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_successes("/", 0);
        rig.kernel.script_thaw_error("/home", Errno::EOPNOTSUPP);
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(0));
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());

        // A marker that cannot be removed is unrecoverable too.
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        let marker = Marker::open(ro.join("frozen")).unwrap();
        marker.create().unwrap();
        std::fs::set_permissions(
            &ro,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o500),
        )
        .unwrap();
        if !nix::unistd::geteuid().is_root() {
            let rig = Rig::new(FreezeState::Frozen, "simple.txt");
            let ctx = Arc::new(
                Context::new(
                    rig.ctx.config.clone(),
                    rig.ctx.state.clone(),
                    Router::new(Box::new(std::io::sink())),
                    marker.clone(),
                )
                .with_kernel(rig.kernel.clone())
                .with_mounts(rig.ctx.mounts.clone()),
            );
            let err = thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("cannot remove recovery marker"),
                "{err}"
            );
            assert_eq!(ctx.state.current(), FreezeState::Frozen);
        }
        std::fs::set_permissions(
            &ro,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn a_denied_thaw_still_drains_the_later_targets() {
        // EPERM on the first target must not skip the drain of the later
        // ones: everything that can be thawed is thawed, then the failure
        // is reported with the marker retained.
        let rig = Rig::new(FreezeState::Frozen, "nested.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_error("/", Errno::EPERM);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "thaw incomplete: FITHAW permission denied (3 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(
            rig.fithaws(),
            paths(&[
                "/",
                "/home",
                "/home",
                "/home/data",
                "/home/data",
                "/home/data/deep",
                "/home/data/deep",
            ]),
            "every later target is drained (success + EINVAL)"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
        // A drain that never converges on one target does not stop the
        // others either.
        let rig = Rig::new(FreezeState::Frozen, "nested.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_successes("/home", u32::MAX);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("did not converge"), "{err}");
        assert!(rig.fithaws().contains(&PathBuf::from("/home/data/deep")));
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[tokio::test]
    async fn recovery_drain_failure_returns_to_thawed() {
        // An unprivileged agent (no CAP_SYS_ADMIN) gets EPERM on the first
        // FITHAW of a recovery drain from Thawed: the error is reported but
        // the state must not become Frozen, since nothing was frozen.
        let rig = Rig::new(FreezeState::Thawed, "simple.txt");
        rig.kernel.script_thaw_error("/", Errno::EPERM);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["thaw_claimed", "thawed"]);
        // From Frozen the same failure keeps the marker and the state.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_error("/", Errno::EPERM);
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
    }

    #[tokio::test]
    async fn thaw_cancels_watchdog_and_flushes_audit() {
        // The hooks are the extension points for T3.5 (cancel the watchdog
        // on `thaw_claimed`) and T3.6 (flush the audit ring on `thawed`);
        // they must fire in that order around the drain.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        let hooks = rig.hooks.clone();
        rig.kernel.set_hook(Box::new(move |call| {
            if let Call::Fithaw(_) = call {
                assert_eq!(
                    hooks.events(),
                    ["thaw_claimed"],
                    "drain runs after thaw_claimed and before thawed"
                );
            }
        }));
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(rig.hooks.events(), ["thaw_claimed", "thawed"]);
        // Full cycle ordering.
        let rig = Rig::nested();
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
            .await
            .unwrap();
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(
            rig.hooks.events(),
            ["freezing", "frozen", "heartbeat", "thaw_claimed", "thawed"]
        );
    }

    #[tokio::test]
    async fn drain_has_a_defensive_upper_bound_and_a_capped_drain_stays_frozen() {
        // With an unknown nesting depth beyond the bound at least one hold
        // may remain: the thaw fails, the state stays Frozen and the marker
        // is retained.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_successes("/", u32::MAX);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "thaw incomplete: drain did not converge; filesystem may still be frozen (2 target(s) thawed); state frozen, marker retained"
        );
        let root_calls = rig
            .fithaws()
            .iter()
            .filter(|p| *p == Path::new("/"))
            .count();
        assert_eq!(root_calls, MAX_THAW_ITERATIONS as usize);
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
    }

    #[tokio::test]
    async fn rollback_drains_every_processed_target_even_after_a_denied_one() {
        // Freeze order: deep, data, home, /. Fail hard on the third (home),
        // so deep and data were frozen; the rollback runs forward (data,
        // then deep) and the first FITHAW on data is denied. deep must
        // still be drained: a target that can be thawed now is not left
        // frozen until a later recovery. The denial is what is reported,
        // the marker and the frozen gate are retained.
        let rig = Rig::nested();
        rig.kernel.script_freeze_error("/home", Errno::EIO);
        rig.kernel.script_thaw_error("/home/data", Errno::EPERM);
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze failed: FIFREEZE failed; rollback incomplete (FITHAW permission denied, 1 target(s) thawed); state frozen, marker retained"
        );
        assert!(
            !text.contains("/home"),
            "wire error must hide mounts: {text}"
        );
        assert_eq!(
            rig.fifreezes(),
            paths(&["/home/data/deep", "/home/data", "/home"])
        );
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data", "/home/data/deep", "/home/data/deep"]),
            "data denied at once; deep still drained (success + EINVAL)"
        );
        assert!(rig.marker().exists(), "marker retained");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
    }

    #[tokio::test]
    async fn thawed_is_published_only_after_the_finalisation_hook() {
        // `on_thawed` (the audit flush in production) runs while the
        // machine is still `Thawing`, so a new freeze cannot be accepted
        // until it has completed; the same for a rollback (`Freezing`).
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(rig.hooks.states_at("thawed"), [FreezeState::Thawing]);
        assert_eq!(rig.state(), FreezeState::Thawed);
        // A recovery drain that fails still finalises before publishing.
        let rig = Rig::new(FreezeState::Thawed, "simple.txt");
        rig.kernel.script_thaw_error("/", Errno::EPERM);
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(rig.hooks.states_at("thawed"), [FreezeState::Thawing]);
        assert_eq!(rig.state(), FreezeState::Thawed);
        // Rollback after a hard freeze error.
        let rig = Rig::nested();
        rig.kernel.script_freeze_error("/home/data", Errno::EIO);
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(rig.hooks.states_at("thawed"), [FreezeState::Freezing]);
        assert_eq!(rig.state(), FreezeState::Thawed);
        // And the frozen side of the contract: `frozen` after `Frozen`,
        // `freezing` in `Freezing`, `thaw_claimed` in `Thawing`.
        let rig = Rig::nested();
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(rig.hooks.states_at("freezing"), [FreezeState::Freezing]);
        assert_eq!(rig.hooks.states_at("frozen"), [FreezeState::Frozen]);
        assert_eq!(rig.hooks.states_at("thaw_claimed"), [FreezeState::Thawing]);
        assert_eq!(rig.hooks.states_at("thawed"), [FreezeState::Thawing]);
    }

    #[tokio::test]
    async fn rollback_denied_thaw_keeps_the_frozen_state_and_marker() {
        // deep freezes, then /home/data fails hard; the rollback's first
        // FITHAW on deep is denied, so deep may still be frozen.
        let rig = Rig::nested();
        rig.kernel.script_freeze_error("/home/data", Errno::EIO);
        rig.kernel
            .script_thaw_error("/home/data/deep", Errno::EPERM);
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze failed: FIFREEZE failed; rollback incomplete (FITHAW permission denied, 0 target(s) thawed); state frozen, marker retained"
        );
        assert!(
            !text.contains("/home/data"),
            "wire error must hide mounts: {text}"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists(), "marker retained");
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
        // The frozen gate now applies until a thaw drains it.
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "thaw incomplete: FITHAW permission denied (0 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
    }

    #[tokio::test]
    async fn rollback_that_cannot_remove_the_marker_keeps_the_frozen_state() {
        // The rollback thaws deep, but the marker path was replaced by a
        // non-empty directory meanwhile: unlink fails (not ENOENT).
        let rig = Rig::nested();
        let marker_path = rig.marker().path().to_path_buf();
        rig.kernel.script_freeze_error("/home/data", Errno::EIO);
        rig.kernel.set_hook(Box::new(move |call| {
            if matches!(call, Call::Fifreeze(p) if p == Path::new("/home/data")) {
                let _ = std::fs::remove_file(&marker_path);
                std::fs::create_dir(&marker_path).unwrap();
                std::fs::write(marker_path.join("child"), b"x").unwrap();
            }
        }));
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze failed: FIFREEZE failed; rolled back (1 target(s) thawed) but cannot remove recovery marker: recovery marker unlink failed; state frozen, marker retained"
        );
        assert!(
            !text.contains("/home/data") && !text.contains("/frozen"),
            "wire error must hide paths: {text}"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().path().exists(), "marker path retained");
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
    }

    fn lifecycle_rig(
        dir: &tempfile::TempDir,
        idle: u64,
        max: u64,
    ) -> (Arc<Context>, Arc<FakeKernel>) {
        let config = Config::parse(&format!(
            "[agent]\nfsfreeze_idle_timeout_secs = {idle}\nfsfreeze_max_timeout_secs = {max}\n"
        ))
        .unwrap();
        let kernel = Arc::new(FakeKernel::new());
        let ctx = Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(fixture("simple.txt"))))
        .with_hooks(Arc::new(LifecycleHooks));
        (Arc::new(ctx), kernel)
    }

    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// Waits (bounded, in real time) for the blocking-pool drain to
    /// finish; paused Tokio time cannot be used to wait for a blocking
    /// thread.
    async fn wait_until_thawed(ctx: &Arc<Context>) {
        let start = std::time::Instant::now();
        while ctx.state.current() != FreezeState::Thawed {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "drain did not finish; state {}",
                ctx.state.current()
            );
            tokio::task::yield_now().await;
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        settle().await;
    }

    /// The production hooks with a gate in front of the thaw finalisation:
    /// `on_thawed` signals `reached`, then blocks until `release` fires,
    /// then flushes like [`LifecycleHooks`].
    struct GatedHooks {
        reached: tokio::sync::Notify,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl FreezeHooks for GatedHooks {
        fn on_freezing(&self, ctx: &Arc<Context>) {
            LifecycleHooks.on_freezing(ctx);
        }
        fn on_frozen(&self, ctx: &Arc<Context>) {
            LifecycleHooks.on_frozen(ctx);
        }
        fn on_thaw_claimed(&self, ctx: &Arc<Context>) {
            LifecycleHooks.on_thaw_claimed(ctx);
        }
        fn on_thawed(&self, ctx: &Arc<Context>) {
            self.reached.notify_one();
            self.release.lock().unwrap().recv().unwrap();
            LifecycleHooks.on_thawed(ctx);
        }
        fn on_heartbeat(&self, ctx: &Arc<Context>) {
            LifecycleHooks.on_heartbeat(ctx);
        }
    }

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_thaw_finalisation_cannot_touch_the_logging_of_a_newer_freeze() {
        // The audit flush of a completed thaw runs before the state is
        // published as `Thawed`. A freeze that arrives while the flush is
        // still in progress is refused, so it can never enter the ring
        // and then have this thaw's flush switch the router back to the
        // normal sink underneath it (a write to a frozen journal).
        use std::io::Write;
        use tracing_subscriber::fmt::MakeWriter;
        let dir = tempfile::tempdir().unwrap();
        let sink = SharedSink::default();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let hooks = Arc::new(GatedHooks {
            reached: tokio::sync::Notify::new(),
            release: Mutex::new(release_rx),
        });
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(sink.clone())),
                Marker::open(dir.path().join("frozen")).unwrap(),
            )
            .with_kernel(Arc::new(FakeKernel::new()))
            .with_mounts(Arc::new(StaticMounts(fixture("simple.txt"))))
            .with_hooks(hooks.clone()),
        );
        freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Ring);
        // Something is in the ring for the flush to write.
        ctx.audit
            .make_writer()
            .write_all(b"{\"event\":\"during_freeze\"}\n")
            .unwrap();
        // The thaw drains, then stops at the gate before its flush.
        let thawing = {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(
                async move { thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#)).await },
            )
        };
        // Bounded: a thaw that never reaches its finalisation (a mutant
        // that skips the hook) must fail here, not hang the test binary.
        tokio::time::timeout(Duration::from_secs(10), hooks.reached.notified())
            .await
            .expect("the thaw reached the finalisation gate");
        assert_eq!(ctx.state.current(), FreezeState::Thawing);
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Ring);
        assert!(sink.0.lock().unwrap().is_empty(), "nothing flushed yet");
        // A new freeze while the finalisation is pending is refused: the
        // state is not `Thawed` yet.
        let err = freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot freeze"), "{err}");
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Ring);
        // Let the thaw finish: it flushes the ring and publishes `Thawed`.
        release_tx.send(()).unwrap();
        thawing.await.unwrap().unwrap();
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Normal);
        assert!(ctx.audit.settle(Duration::from_secs(10)));
        let flushed = sink.0.lock().unwrap().len();
        assert!(flushed > 0, "the ring was flushed to the sink");
        // The next freeze window is intact: its records stay in the ring
        // and nothing reaches the sink while it is frozen.
        freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Ring);
        ctx.audit
            .make_writer()
            .write_all(b"{\"event\":\"second_window\"}\n")
            .unwrap();
        assert_eq!(
            sink.0.lock().unwrap().len(),
            flushed,
            "no sink write while frozen"
        );
        release_tx.send(()).unwrap();
        thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(ctx.audit.mode(), crate::audit::Mode::Normal);
        assert!(ctx.audit.settle(Duration::from_secs(10)));
        assert!(sink.0.lock().unwrap().len() > flushed);
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_hooks_arm_watchdog_and_idle_timeout_drains() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, kernel) = lifecycle_rig(&dir, 30, 300);
        freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert!(ctx.watchdog_slot().is_some(), "armed on Frozen");
        assert!(ctx.marker.exists());
        // Heartbeats keep it frozen.
        for _ in 0..4 {
            tokio::time::advance(std::time::Duration::from_secs(20)).await;
            settle().await;
            status(&ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
                .await
                .unwrap();
            settle().await;
        }
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        // Silence: the idle timeout drains, removes the marker, thaws.
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        wait_until_thawed(&ctx).await;
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!ctx.marker.exists());
        let thaws = kernel
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::Fithaw(_)))
            .count();
        assert_eq!(thaws, 4, "two targets drained (success + EINVAL each)");
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_hooks_cancel_watchdog_on_manual_thaw() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, kernel) = lifecycle_rig(&dir, 30, 300);
        freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        let value = thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert!(
            ctx.watchdog_slot().is_none(),
            "handle taken on thaw_claimed"
        );
        let before = kernel.calls().len();
        tokio::time::advance(std::time::Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(
            kernel.calls().len(),
            before,
            "no watchdog drain after a manual thaw"
        );
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
    }

    #[tokio::test(start_paused = true)]
    async fn unrecoverable_thaw_failure_rearms_watchdog() {
        // `Thawing → Frozen` is an entry into `Frozen` like any other
        // (§4.2, §4.4): after a manual thaw fails with the marker retained
        // the watchdog must be armed again, so that a dead orchestrator
        // does not leave the filesystems frozen for ever; and when the
        // watchdog's own drain fails, it is armed yet again.
        let dir = tempfile::tempdir().unwrap();
        let (ctx, kernel) = lifecycle_rig(&dir, 30, 300);
        freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        kernel.script_thaw_error("/", Errno::EPERM);
        let err = thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("marker retained"), "{err}");
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        settle().await;
        assert!(
            ctx.watchdog_slot().is_some(),
            "re-armed after the failed thaw"
        );
        // Silence: the re-armed idle timeout runs a drain (which fails
        // again on `/`, so the state stays Frozen and it re-arms again).
        let before = kernel.calls().len();
        tokio::time::advance(std::time::Duration::from_secs(31)).await;
        let start = std::time::Instant::now();
        while kernel.calls().len() == before {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "the re-armed watchdog never drained"
            );
            tokio::task::yield_now().await;
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        settle().await;
        assert!(
            kernel.calls()[before..]
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/"))),
            "the watchdog drain retries the held target (tracked scope: the drained ones are done)"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());
        assert!(
            ctx.watchdog_slot().is_some(),
            "re-armed after the watchdog's own failed drain"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn lifecycle_hooks_hard_cap_wins_over_heartbeats() {
        let dir = tempfile::tempdir().unwrap();
        let (ctx, _kernel) = lifecycle_rig(&dir, 30, 60);
        freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        for _ in 0..6 {
            tokio::time::advance(std::time::Duration::from_secs(10)).await;
            settle().await;
            status(&ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
                .await
                .unwrap();
            settle().await;
        }
        wait_until_thawed(&ctx).await;
        assert_eq!(
            ctx.state.current(),
            FreezeState::Thawed,
            "thawed at the 60 s cap"
        );
        assert!(!ctx.marker.exists());
    }

    #[tokio::test]
    async fn a_thaw_drains_through_the_handles_its_freeze_opened() {
        // bind_mounts.txt: / (8:1, aliases /var/www and /mnt/rootbind) and
        // /data (8:2, alias /srv/exports). After the freeze every pathname
        // of both superblocks leads somewhere else (mounts placed over
        // them): the thaw still reaches the frozen filesystems, through
        // the handles the freeze opened, without opening anything.
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert_eq!(rig.opens(), paths(&["/data", "/"]));
        assert_eq!(rig.held(), 2, "one handle per processed target");
        for path in ["/", "/var/www", "/mnt/rootbind", "/data", "/srv/exports"] {
            rig.kernel.script_mount_device(path, (8, 9));
        }
        rig.kernel.clear_calls();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert!(rig.opens().is_empty(), "no pathname was consulted");
        assert_eq!(rig.fithaws(), paths(&["/", "/", "/data", "/data"]));
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(rig.held(), 0, "handles are released once drained");
    }

    #[tokio::test]
    async fn a_recovery_thaw_reaches_a_hidden_superblock_through_an_alias() {
        // Nothing is held after a restart: the drain goes by pathnames,
        // and /data now leads to another filesystem (8:9). The kernel shim
        // refuses it and the alias /srv/exports reaches 8:2 instead.
        let rig = Rig::new(FreezeState::Frozen, "bind_mounts.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_mount_device("/data", (8, 9));
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert_eq!(rig.opens(), paths(&["/", "/data", "/srv/exports"]));
        assert_eq!(
            rig.fithaws(),
            paths(&["/", "/", "/srv/exports", "/srv/exports"])
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn an_unreachable_planned_superblock_keeps_the_marker_and_the_frozen_gate() {
        // Every pathname of 8:2 fails (one leads elsewhere, the other
        // cannot be opened): nothing was asked of that filesystem, so the
        // thaw is incomplete; the other target is still drained, the
        // marker and the frozen gate are retained, and the wire error keeps
        // paths and device numbers out of host replies (§5.9).
        let rig = Rig::new(FreezeState::Frozen, "bind_mounts.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_mount_device("/data", (8, 9));
        rig.kernel.script_open_error("/srv/exports", Errno::ENOENT);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "thaw incomplete: target unreachable; no FITHAW issued (1 target(s) thawed); state frozen, marker retained"
        );
        for forbidden in ["/data", "/srv/exports", "8:2", "8:9"] {
            assert!(!text.contains(forbidden), "leaked {forbidden} in {text}");
        }
        assert_eq!(
            rig.fithaws(),
            paths(&["/", "/"]),
            "the other target is drained"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["thaw_claimed", "frozen"]);
    }

    #[tokio::test]
    async fn a_freeze_reaches_a_hidden_superblock_through_an_alias_and_rolls_back_through_handles()
    {
        // /data leads elsewhere: the freeze opens 8:2 through /srv/exports.
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        rig.kernel.script_mount_device("/data", (8, 9));
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));
        assert_eq!(rig.opens(), paths(&["/data", "/srv/exports", "/"]));
        assert_eq!(rig.fifreezes(), paths(&["/srv/exports", "/"]));

        // A target none of whose pathnames opens on its device stops the
        // freeze: hard error, and the rollback drains the processed target
        // through the handle already open rather than reopening it.
        let rig = Rig::new(FreezeState::Thawed, "bind_mounts.txt");
        rig.kernel.script_mount_device("/data", (8, 9));
        for path in ["/", "/var/www", "/mnt/rootbind"] {
            rig.kernel.script_open_error(path, Errno::EACCES);
        }
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze failed: target open permission denied; no FIFREEZE issued; rolled back (1 target(s) thawed); state thawed"
        );
        for forbidden in ["/var/www", "/mnt/rootbind", "/srv/exports"] {
            assert!(!text.contains(forbidden), "leaked {forbidden} in {text}");
        }
        assert_eq!(rig.fifreezes(), paths(&["/srv/exports"]));
        assert_eq!(rig.fithaws(), paths(&["/srv/exports", "/srv/exports"]));
        let reopened = rig
            .opens()
            .iter()
            .filter(|p| *p == Path::new("/srv/exports"))
            .count();
        assert_eq!(reopened, 1, "the rollback used the freeze's handle");
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(rig.held(), 0);
    }

    #[tokio::test]
    async fn an_open_failure_at_freeze_is_a_hard_error_not_a_skip() {
        // EOPNOTSUPP from open(2) is not the filesystem declining to
        // freeze: nothing was asked of it. The target is not skipped; the
        // freeze fails and rolls back like any other hard error.
        let rig = Rig::nested();
        rig.kernel
            .script_open_error("/home/data", Errno::EOPNOTSUPP);
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze failed: target unreachable; no FIFREEZE issued; rolled back (1 target(s) thawed); state thawed"
        );
        assert!(
            !text.contains("/home/data"),
            "wire error must hide mount: {text}"
        );
        assert_eq!(rig.fifreezes(), paths(&["/home/data/deep"]));
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data/deep", "/home/data/deep"])
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn handles_whose_drain_is_incomplete_are_held_for_the_next_thaw() {
        let rig = Rig::nested();
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(rig.held(), 4);
        rig.kernel.script_thaw_error("/home", Errno::EIO);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("marker retained"), "{err}");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert_eq!(rig.held(), 1, "only the undrained target keeps its handle");
        // The next thaw is still the operation's (tracked scope, §4.2): it
        // drains /home through that handle and opens nothing, since the
        // targets whose drain completed are done; it fails the same way
        // and keeps the handle again.
        rig.kernel.clear_calls();
        let _ = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#)).await;
        assert!(rig.opens().is_empty(), "{:?}", rig.opens());
        assert_eq!(rig.fithaws(), paths(&["/home"]));
        assert_eq!(rig.held(), 1);
        assert_eq!(rig.state(), FreezeState::Frozen);
        // Once the kernel permits it, the drain of that one target
        // completes the operation: marker gone, `Thawed`.
        rig.kernel.script_thaw_successes("/home", 1);
        rig.kernel.clear_thaw_errors();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(1));
        assert_eq!(rig.held(), 0);
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn handlers_reject_arguments() {
        let rig = Rig::nested();
        for (name, json) in [
            (
                "freeze",
                r#"{"execute":"guest-fsfreeze-freeze","arguments":{"x":1}}"#,
            ),
            (
                "thaw",
                r#"{"execute":"guest-fsfreeze-thaw","arguments":{"x":1}}"#,
            ),
            (
                "status",
                r#"{"execute":"guest-fsfreeze-status","arguments":{"x":1}}"#,
            ),
        ] {
            let result = match name {
                "freeze" => freeze(&rig.ctx, &req(json)).await,
                "thaw" => thaw(&rig.ctx, &req(json)).await,
                _ => status(&rig.ctx, &req(json)).await,
            };
            assert!(matches!(result, Err(Error::InvalidArguments(_))), "{name}");
        }
        assert!(rig.kernel.calls().is_empty());
        assert_eq!(rig.state(), FreezeState::Thawed);
    }

    /// Real freeze/thaw through the handlers on loop-mounted ext4 and xfs
    /// (AC2). `QEMINGA_TEST_EXT4_MOUNT` and `QEMINGA_TEST_XFS_MOUNT` are set
    /// by `scripts/ci/mk-loop-fs.sh` (T5.2); a missing XFS mount is
    /// tolerated so the test can run where `mkfs.xfs` is unavailable.
    #[tokio::test]
    #[ignore = "needs root and loop-mounted ext4/xfs (QEMINGA_TEST_EXT4_MOUNT, QEMINGA_TEST_XFS_MOUNT)"]
    async fn privileged_freeze_thaw_cycle_on_ext4_and_xfs() {
        let ext4 = std::env::var("QEMINGA_TEST_EXT4_MOUNT").expect("QEMINGA_TEST_EXT4_MOUNT");
        let xfs = std::env::var("QEMINGA_TEST_XFS_MOUNT").ok();
        let wanted: Vec<String> = std::iter::once(ext4).chain(xfs).collect();
        let dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
            Marker::open(dir.path().join("frozen")).unwrap(),
        ));
        let list =
            json!({"execute": "guest-fsfreeze-freeze-list", "arguments": {"mountpoints": wanted}});
        let frozen = freeze_list(&ctx, &parse_request(list.to_string().as_bytes()).unwrap())
            .await
            .unwrap();
        assert_eq!(frozen, json!(wanted.len()));
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());
        let thawed = thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        // The thaw drains the whole plan; at least the frozen ones count.
        assert!(thawed.as_u64().unwrap() >= wanted.len() as u64);
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!ctx.marker.exists());
    }

    #[tokio::test]
    async fn thaw_drains_held_mounts_when_mountinfo_read_fails() {
        // The freeze holds one handle per processed target. A thaw whose
        // mount-table read fails (EMFILE: the retained handles may be what
        // exhausted the descriptors) still drains every held handle and
        // releases it, and only then reports the read failure: the marker
        // and the frozen gate are retained, since targets frozen by an
        // earlier instance could not be discovered.
        let mounts = Arc::new(SwitchableMounts::new(fixture("nested.txt")));
        let rig = Rig::with_mounts(FreezeState::Thawed, mounts.clone());
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4));
        assert_eq!(rig.held(), 4);
        // As after an uncertain settlement (a lost worker): the thaw must
        // discover its targets, so the table matters.
        rig.ctx.set_thaw_scope(ThawScope::Discovery);
        mounts.fail_reads(true);
        rig.kernel.clear_calls();
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot build thaw plan (4 target(s) thawed); state frozen, marker retained"
        );
        assert!(rig.opens().is_empty(), "no pathname was consulted");
        assert_eq!(
            rig.fithaws(),
            paths(&[
                "/",
                "/",
                "/home",
                "/home",
                "/home/data",
                "/home/data",
                "/home/data/deep",
                "/home/data/deep"
            ]),
            "every held target is drained, in forward mount order"
        );
        assert_eq!(rig.held(), 0, "drained handles are released");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists(), "conservative: discovery failed");
        assert_eq!(
            rig.hooks.events(),
            ["freezing", "frozen", "thaw_claimed", "frozen"],
            "the watchdog is re-armed"
        );
        // Discovery works again: nothing is held any more, the drain goes
        // by pathnames and finds every target already thawed.
        mounts.fail_reads(false);
        rig.kernel.clear_calls();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(0));
        assert_eq!(rig.opens().len(), 4);
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn a_recovery_thaw_that_cannot_read_the_mount_table_stays_frozen() {
        // After a restart nothing is held: a failed read leaves nothing
        // to drain, and the marker and the frozen gate are retained.
        let mounts = Arc::new(SwitchableMounts::new(fixture("nested.txt")));
        let rig = Rig::with_mounts(FreezeState::Frozen, mounts.clone());
        rig.marker().create().unwrap();
        mounts.fail_reads(true);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot build thaw plan (0 target(s) thawed); state frozen, marker retained"
        );
        assert!(rig.kernel.calls().is_empty());
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
    }

    #[tokio::test]
    async fn a_tracked_thaw_reads_no_mount_table() {
        // The thaw of an operation this process completed has every
        // obligation in hand: it drains the held descriptors and completes
        // (marker gone, `Thawed`) although the table cannot be read at
        // all, the EMFILE those descriptors may have caused included.
        let mounts = Arc::new(SwitchableMounts::new(fixture("nested.txt")));
        let rig = Rig::with_mounts(FreezeState::Thawed, mounts.clone());
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(rig.ctx.thaw_scope(), ThawScope::Tracked);
        mounts.fail_reads(true);
        rig.kernel.clear_calls();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4));
        assert!(rig.opens().is_empty());
        assert_eq!(
            rig.fithaws().len(),
            8,
            "every held target, success + EINVAL"
        );
        assert_eq!(rig.held(), 0);
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(
            rig.ctx.thaw_scope(),
            ThawScope::Discovery,
            "a completed thaw leaves the conservative default"
        );
    }

    #[tokio::test]
    async fn a_lost_thaw_worker_leaves_the_next_thaw_to_discovery() {
        // The external review's fifth-round finding: the ordinary thaw
        // moves the held descriptors into its blocking task; when that
        // task is lost (a panic on the first FITHAW, in an unwind build)
        // the descriptors are gone with it, so they are no longer evidence
        // of complete ownership. The state returns to `Frozen` with the
        // marker, and the next thaw must discover its targets through the
        // table (pathnames consulted, every target drained) before the
        // marker goes, never drain an empty list and publish `Thawed`.
        let rig = Rig::nested();
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(rig.held(), 4);
        rig.kernel.set_hook(Box::new(|call| {
            if matches!(call, Call::Fithaw(_)) {
                panic!("thaw worker lost");
            }
        }));
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "thaw task failed; state frozen, marker retained"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
        assert_eq!(rig.held(), 0, "the descriptors were lost with the task");
        assert_eq!(rig.ctx.thaw_scope(), ThawScope::Discovery);
        rig.kernel.set_hook(Box::new(|_| {}));
        rig.kernel.clear_calls();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4), "every target found frozen by its pathname");
        assert_eq!(rig.opens().len(), 4, "discovery: {:?}", rig.opens());
        assert_eq!(rig.fithaws().len(), 8);
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn a_discovery_drain_uses_the_held_handle_of_the_same_superblock() {
        // Under discovery (as after an uncertain settlement) a planned
        // target is drained through the handle this process holds for
        // *its* superblock, matched by device, so nothing is reopened even
        // where a pathname now leads elsewhere, and the drain runs in
        // forward mount order: a handle of another device never stands in.
        let rig = Rig::nested();
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(rig.held(), 4);
        rig.ctx.set_thaw_scope(ThawScope::Discovery);
        rig.kernel.script_mount_device("/home/data", (8, 9));
        rig.kernel.clear_calls();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4));
        assert!(rig.opens().is_empty(), "{:?}", rig.opens());
        assert_eq!(
            rig.fithaws(),
            paths(&[
                "/",
                "/",
                "/home",
                "/home",
                "/home/data",
                "/home/data",
                "/home/data/deep",
                "/home/data/deep"
            ]),
            "each target through its own handle, forward"
        );
        assert_eq!(rig.held(), 0);
        assert_eq!(rig.state(), FreezeState::Thawed);
    }

    #[tokio::test]
    async fn an_operation_that_lost_a_worker_leaves_its_thaw_to_discovery() {
        // The worker for /home/data panics inside FIFREEZE: its outcome is
        // unknown and no descriptor shows for it, so the operation settles
        // `Frozen` with the target uncertain and the thaw must discover
        // its targets through the table: /home/data is reached by its
        // pathname although this process holds nothing for it.
        let rig = Rig::nested();
        rig.kernel.set_hook(Box::new(|call| {
            if matches!(call, Call::Fifreeze(p) if p == Path::new("/home/data")) {
                panic!("worker lost");
            }
        }));
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("worker lost"), "{err}");
        // The reply went out when the abort committed; the recovery of the
        // target frozen before (/home/data/deep) settles afterwards.
        if let Some(op) = rig.ctx.freeze_op() {
            op.wait_for_settlement().await;
        }
        settle().await;
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert_eq!(rig.ctx.thaw_scope(), ThawScope::Discovery);
        rig.kernel.set_hook(Box::new(|_| {}));
        rig.kernel.clear_calls();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        // Three targets are found frozen by their pathnames (the fake
        // thaws once per path); /home/data/deep was drained by the
        // recovery pass and answers EINVAL at once.
        assert_eq!(value, json!(3));
        assert!(
            rig.opens().contains(&PathBuf::from("/home/data")),
            "the uncertain target is discovered by its pathname: {:?}",
            rig.opens()
        );
        assert!(rig.fithaws().contains(&PathBuf::from("/home/data")));
    }

    #[tokio::test]
    async fn a_first_target_worker_loss_publishes_worker_lost_reason_without_leaking_path() {
        // When the first target's worker panics, nothing was frozen before it
        // so no recovery pass runs: `Driver::publish_unrecoverable` is the
        // only path that publishes `WorkerLost` on `op.progress()` for a
        // joining thaw.
        let rig = Rig::nested();
        let gate = Gate::new();
        let _release = gate.release_on_drop();
        let wait_gate = gate.clone();
        rig.kernel.set_hook(Box::new(move |call| {
            if matches!(call, Call::Fifreeze(p) if p == Path::new(A)) {
                wait_gate.wait();
                panic!("first worker lost");
            }
        }));
        let freezing = rig.spawn_freeze();
        rig.wait_for("first worker paused", |_| gate.waiting() == 1)
            .await;
        let op = rig.ctx.freeze_op().expect("operation registered");
        gate.release();
        let err = freezing.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("worker lost"), "{err}");
        assert!(
            !err.to_string().contains(A),
            "wire error hides target: {err}"
        );
        let progress = op.wait_for_settlement().await;
        assert_eq!(progress.settled, Some(FreezeState::Frozen));
        assert_eq!(
            progress.unrecoverable_reason,
            Some(RecoveryReason::WorkerLost)
        );
        let joined = join_operation(&rig.ctx, &op).await.unwrap_err().to_string();
        assert!(
            joined.contains("freeze worker lost; target outcome unknown")
                && joined.contains("state frozen, marker retained"),
            "{joined}"
        );
        assert!(!joined.contains(A), "joining error hides target: {joined}");
    }

    #[tokio::test]
    async fn an_incomplete_held_drain_is_reported_before_the_read_failure() {
        // Both retain the marker; the target that may still be frozen is
        // the more specific report, and its handle is kept.
        let mounts = Arc::new(SwitchableMounts::new(fixture("nested.txt")));
        let rig = Rig::with_mounts(FreezeState::Thawed, mounts.clone());
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        rig.ctx.set_thaw_scope(ThawScope::Discovery);
        mounts.fail_reads(true);
        rig.kernel.script_thaw_error("/home", Errno::EACCES);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "thaw incomplete: FITHAW permission denied (3 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(rig.held(), 1, "only the incomplete handle is kept");
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
    }

    /// Set in the child of
    /// `a_thaw_under_descriptor_pressure_drains_its_held_targets`.
    const FD_PRESSURE_CHILD: &str = "QEMINGA_TEST_FD_PRESSURE_CHILD";

    /// The production reader of `/proc/self/mountinfo` (subject to
    /// `EMFILE`), whose content is replaced by a fixture.
    struct RealReadThenFixture(String);

    impl MountSource for RealReadThenFixture {
        fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
            crate::mountinfo::read_mountinfo_bounded(Path::new(crate::mountinfo::MOUNTINFO_PATH))?;
            Ok(self.0.clone().into_bytes())
        }
    }

    #[test]
    fn a_thaw_under_descriptor_pressure_drains_its_held_targets() {
        // The descriptor limit is process-wide: the scenario runs in a
        // child process (this binary, one ignored test) so the rest of
        // the suite is unaffected.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "handlers::fsfreeze::tests::descriptor_pressure_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(FD_PRESSURE_CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
    }

    #[tokio::test]
    #[ignore = "child of a_thaw_under_descriptor_pressure_drains_its_held_targets"]
    async fn descriptor_pressure_child() {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        use std::fs::File;
        if std::env::var_os(FD_PRESSURE_CHILD).is_none() {
            return;
        }
        // A small soft limit keeps the hoard small; everything the rig
        // needs (runtime, marker directory) is open already.
        let (_, hard) = getrlimit(Resource::RLIMIT_NOFILE).unwrap();
        setrlimit(Resource::RLIMIT_NOFILE, hard.min(64), hard).unwrap();
        let mounts = Arc::new(RealReadThenFixture(fixture("nested.txt")));
        let rig = Rig::with_mounts(FreezeState::Thawed, mounts);
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4));
        // A tracked thaw would read no table at all (§4.2 "Thaw scope");
        // the case is the discovery drain's, as after an uncertain
        // settlement.
        rig.ctx.set_thaw_scope(ThawScope::Discovery);
        // Exhaust the descriptors, as retained handles on a busy agent
        // could: the mount table can no longer be opened.
        let mut hoard = Vec::new();
        loop {
            match File::open("/dev/null") {
                Ok(file) => hoard.push(file),
                Err(err) => {
                    assert_eq!(err.raw_os_error(), Some(Errno::EMFILE as i32), "{err}");
                    break;
                }
            }
        }
        rig.kernel.clear_calls();
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "cannot build thaw plan (4 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(rig.fithaws().len(), 8, "every held target is drained");
        assert_eq!(rig.held(), 0);
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
        // The drained handles freed their descriptors (here: the hoard);
        // the next attempt discovers the plan and completes.
        drop(hoard);
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(0));
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
    }

    /// A mount table whose read blocks at a gate (a slow `/proc` read).
    struct GatedMounts {
        table: String,
        gate: Gate,
    }

    impl MountSource for GatedMounts {
        fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
            self.gate.wait();
            Ok(self.table.clone().into_bytes())
        }
    }

    /// A mount table whose read panics (a lost preparation task).
    struct PanickingMounts;

    impl MountSource for PanickingMounts {
        fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
            panic!("mount table reader lost");
        }
    }

    /// nested.txt freezes deepest-first: A = /home/data/deep, B =
    /// /home/data, C = /home, D = /.
    const A: &str = "/home/data/deep";
    const B: &str = "/home/data";
    const C: &str = "/home";
    const D: &str = "/";

    /// An operation aborted by its deadline while B is blocked inside
    /// FIFREEZE, with A already drained. The gate's release guard is owned
    /// here, before any wait or assertion, so a failure never leaves the
    /// worker blocked.
    struct AbortedAtB {
        rig: Rig,
        gate: Gate,
        _release: ReleaseOnDrop,
        err: Error,
    }

    async fn aborted_at_b() -> AbortedAtB {
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let gate = rig.kernel.script_freeze_gate(B);
        let release = gate.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("B blocked", |_| gate.waiting() == 1).await;
        rig.expire();
        let err = freezing.await.unwrap().unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        // The driver's own signal that the pass over A is recorded (the
        // fake's call log alone would race the driver's bookkeeping).
        let op = rig.ctx.freeze_op().unwrap();
        rig.wait_for("A's recovery pass recorded", |_| {
            op.progress().recovery_pass_done()
        })
        .await;
        assert_eq!(rig.fithaws(), paths(&[A, A]));
        AbortedAtB {
            rig,
            gate,
            _release: release,
            err,
        }
    }

    #[tokio::test]
    async fn a_completed_target_is_thawed_while_a_later_fifreeze_is_still_blocked() {
        // When the deadline expires with B still inside FIFREEZE, A is
        // drained through its handle on independent capacity, C is never
        // authorised, the request fails, and the marker, the frozen gate
        // and the ring stay until B settles. B's late success (a worker
        // past its last check, owned to its end) is accounted to the
        // aborted operation and drained through its own handle; no
        // `frozen` hook ever fires.
        let ab = aborted_at_b().await;
        let (rig, gate, err) = (&ab.rig, &ab.gate, &ab.err);
        let text = err.to_string();
        assert!(
            text.contains("operation deadline expired with a FIFREEZE in flight")
                && text.contains("1 target(s) frozen so far are being thawed")
                && text.contains("state thawing, marker retained"),
            "{text}"
        );
        assert!(
            !text.contains(B) && !text.contains("1 s"),
            "wire error must hide in-flight target and timeout: {text}"
        );
        assert_eq!(gate.waiting(), 1, "B is still inside FIFREEZE");
        assert_eq!(rig.fifreezes(), paths(&[A, B]));
        assert_eq!(rig.opens(), paths(&[A, B]), "C never authorised");
        assert_eq!(rig.held(), 0, "A's handle was released by its drain");
        assert!(rig.marker().exists(), "unresolved: B may still freeze");
        assert_eq!(rig.state(), FreezeState::Thawing);
        assert!(rig.state().is_frozen_for_gate());
        let value = status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!("frozen"), "status is served meanwhile");
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot freeze"), "{err}");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed"]);
        assert!(rig.ctx.freeze_op().unwrap().progress().recovery_pass_done());
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fithaws(), paths(&[A, A, B, B]));
        assert_eq!(rig.opens().len(), 2, "no pathname was consulted");
        assert!(!rig.marker().exists());
        assert_eq!(rig.held(), 0);
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        assert!(rig.ctx.freeze_op().is_none(), "the operation is retired");
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4), "a new freeze is accepted again");
    }

    #[tokio::test]
    async fn a_dead_instances_walk_is_aborted_and_never_publishes() {
        // `Context::abort_tasks` is a harness's SIGKILL (§4.5 scenarios,
        // T6.3): the driver waiting on B is ended where it waits, so when
        // B's FIFREEZE lands the walk does not go on to C, publishes no
        // state, arms no watchdog and answers nothing; the marker written
        // before the walk and the kernel's freezes stay for the recovery
        // of the next instance.
        let rig = Rig::nested();
        let gate = rig.kernel.script_freeze_gate(B);
        let _release = gate.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("B blocked", |_| gate.waiting() == 1).await;
        assert_eq!(rig.state(), FreezeState::Freezing);
        rig.ctx.abort_tasks();
        gate.release();
        rig.wait_for("B's late FIFREEZE landed", |_| gate.waiting() == 0)
            .await;
        // Real time, so a driver that survived would have gone on to C.
        tokio::time::sleep(Duration::from_millis(100)).await;
        settle().await;
        assert_eq!(rig.fifreezes(), paths(&[A, B]), "C never authorised");
        assert_eq!(rig.state(), FreezeState::Freezing, "nothing published");
        assert!(rig.ctx.watchdog_slot().is_none(), "no watchdog armed");
        assert_eq!(rig.hooks.events(), ["freezing"]);
        assert!(rig.marker().exists(), "the marker stays for recovery");
        assert_eq!(rig.fithaws(), Vec::<PathBuf>::new(), "nothing drained");
        if let Ok(Ok(Ok(value))) = tokio::time::timeout(Duration::from_millis(100), freezing).await
        {
            panic!("a dead walk answered {value}");
        }
    }

    #[tokio::test]
    async fn a_completion_and_the_expiry_ready_together_abort_the_walk() {
        // The deadline passes and B completes before the driver is polled
        // again (the runtime has one thread: it runs only when this test
        // yields). The abort is polled ahead of the completion, so C is
        // never authorised and B's success is recovered.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let gate = rig.kernel.script_freeze_gate(B);
        let _release = gate.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("B blocked", |_| gate.waiting() == 1).await;
        rig.expire();
        gate.release();
        // Let B's thread finish without yielding to the driver.
        while gate.waiting() > 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(20));
        let err = freezing.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("deadline"), "{err}");
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.opens(), paths(&[A, B]), "C never authorised");
        assert_eq!(rig.fithaws(), paths(&[A, A, B, B]));
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn a_worker_released_after_the_expiry_issues_no_ioctl() {
        // B's worker is held between opening its target and its last
        // check (the fake's hook, which runs before FIFREEZE). The clock
        // passes the deadline meanwhile: the worker sees it before the
        // driver does and issues nothing; A is recovered.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let opening = Gate::new();
        let _release = opening.release_on_drop();
        let hook_gate = opening.clone();
        rig.kernel.set_hook(Box::new(move |call| {
            if matches!(call, Call::Open(p, _) if p == Path::new(B)) {
                hook_gate.wait();
            }
        }));
        let freezing = rig.spawn_freeze();
        rig.wait_for("B opening", |_| opening.waiting() == 1).await;
        rig.expire();
        opening.release();
        while opening.waiting() > 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(20));
        let err = freezing.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("deadline"), "{err}");
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fifreezes(), paths(&[A]), "B never issued FIFREEZE");
        assert_eq!(rig.opens(), paths(&[A, B]), "C never authorised");
        assert_eq!(rig.fithaws(), paths(&[A, A]));
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn an_already_expired_deadline_authorises_no_target_at_all() {
        // The deadline has passed before the first authorisation: nothing
        // is opened or frozen, the marker created by the preparation is
        // removed, and the request fails naming the preparation.
        let rig = Rig::nested().with_operation_timeout(Duration::ZERO);
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "freeze aborted: operation deadline expired while preparing; abort accepted, recovery pending"
        );
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert!(rig.kernel.calls().is_empty(), "no open, no ioctl");
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
    }

    /// Holds the driver in the synchronous window after a completion:
    /// another thread takes the held-handles lock the driver needs to
    /// publish the completed target, so the driver, past its await and
    /// short of its next decision, waits there until the gate opens.
    fn hold_driver_after_completion(rig: &Rig) -> (Gate, std::thread::JoinHandle<()>) {
        let hold = Gate::new();
        let gate = hold.clone();
        let ctx = Arc::clone(&rig.ctx);
        let holder = std::thread::spawn(move || {
            let _held = ctx.frozen_mounts_lock_for_tests();
            gate.wait();
        });
        (hold, holder)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_deadline_passing_between_a_completion_and_the_next_authorisation_opens_nothing() {
        // A completes; before the driver reaches its next decision the
        // clock passes the deadline, with no await in between to notice
        // it: the decision boundary itself must catch it, so B is never
        // opened, let alone frozen, and A is recovered.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let a = rig.kernel.script_freeze_gate(A);
        let _release_a = a.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("A blocked", |_| a.waiting() == 1).await;
        let (hold, holder) = hold_driver_after_completion(&rig);
        rig.wait_for("lock held", |_| hold.waiting() == 1).await;
        a.release();
        let op = rig.ctx.freeze_op().unwrap();
        rig.wait_for("driver past A's await", |_| {
            op.progress().in_flight.is_none()
        })
        .await;
        assert_eq!(
            op.progress().frozen,
            0,
            "A not yet published: the driver is held"
        );
        rig.expire();
        hold.release();
        holder.join().unwrap();
        let err = freezing.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("operation deadline expired")
                && !err.to_string().contains("1 s"),
            "{err}"
        );
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.opens(), paths(&[A]), "B never authorised");
        assert_eq!(rig.fifreezes(), paths(&[A]));
        assert_eq!(rig.fithaws(), paths(&[A, A]));
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        assert!(!rig.marker().exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_deadline_passing_between_the_last_completion_and_the_commit_enters_recovery() {
        // D, the last target, completes; the clock passes the deadline
        // while the driver is held short of its commit: the decision
        // before the commit enters recovery, `Frozen` is never published.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let d = rig.kernel.script_freeze_gate(D);
        let _release_d = d.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("D blocked", |_| d.waiting() == 1).await;
        let (hold, holder) = hold_driver_after_completion(&rig);
        rig.wait_for("lock held", |_| hold.waiting() == 1).await;
        d.release();
        let op = rig.ctx.freeze_op().unwrap();
        rig.wait_for("driver past D's await", |_| {
            op.progress().in_flight.is_none()
        })
        .await;
        assert_eq!(
            op.progress().frozen,
            3,
            "D not yet published: the driver is held"
        );
        rig.expire();
        hold.release();
        holder.join().unwrap();
        let err = freezing.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("operation deadline expired")
                && !err.to_string().contains("1 s"),
            "{err}"
        );
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fifreezes(), paths(&[A, B, C, D]));
        assert_eq!(rig.fithaws().len(), 8, "all four recovered");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn the_last_completion_after_the_expiry_enters_recovery_not_frozen() {
        // Every target but the last is frozen when the deadline passes
        // and D completes late: the operation recovers all four instead
        // of publishing a stale success.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let gate = rig.kernel.script_freeze_gate(D);
        let _release = gate.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("D blocked", |_| gate.waiting() == 1).await;
        rig.expire();
        let err = freezing.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("3 target(s) frozen so far"),
            "{err}"
        );
        rig.wait_for("A, B, C drained", |r| r.fithaws().len() == 6)
            .await;
        assert_eq!(rig.state(), FreezeState::Thawing);
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(
            rig.fithaws(),
            paths(&[C, C, B, B, A, A, D, D]),
            "the pass drains forward (parents first), then D"
        );
        assert!(!rig.marker().exists());
        assert!(!rig.hooks.events().contains(&"frozen"));
    }

    #[tokio::test]
    async fn a_late_error_after_the_abort_needs_no_recovery_and_ebusy_is_drained() {
        // B fails after the abort: nothing of B is frozen, so nothing is
        // drained for it, and the operation settles `Thawed`.
        let ab = aborted_at_b().await;
        let (rig, gate) = (&ab.rig, &ab.gate);
        rig.kernel.script_freeze_error(B, Errno::EIO);
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fithaws(), paths(&[A, A]));
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        // B answers EBUSY after the abort: retained and drained like any
        // EBUSY target (§4.2), then `Thawed`.
        let ab = aborted_at_b().await;
        let (rig, gate) = (&ab.rig, &ab.gate);
        rig.kernel.script_freeze_error(B, Errno::EBUSY);
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fithaws(), paths(&[A, A, B, B]));
        assert!(!rig.marker().exists());
        assert_eq!(rig.held(), 0);
    }

    #[tokio::test]
    async fn expiry_during_preparation_freezes_nothing_and_leaves_no_marker() {
        // The deadline expires while the mount table is still being read:
        // the preparation stays owned to its end, no target is ever
        // authorised, neither reply claims a marker is retained before
        // preparation creates one nor leaks the configured timeout duration,
        // the late marker is removed, and `Thawed` is published after the
        // finalisation hook.
        let gate = Gate::new();
        let _release = gate.release_on_drop();
        let mounts = Arc::new(GatedMounts {
            table: fixture("nested.txt"),
            gate: gate.clone(),
        });
        let rig = Rig::with_mounts(FreezeState::Thawed, mounts)
            .with_operation_timeout(Duration::from_secs(1));
        let freezing = rig.spawn_freeze();
        rig.wait_for("preparing", |_| gate.waiting() == 1).await;
        rig.expire();
        let err = freezing.await.unwrap().unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "freeze aborted: operation deadline expired while preparing; abort accepted, recovery pending"
        );
        assert!(
            !text.contains("1 s") && !text.contains("marker retained"),
            "must not disclose timeout or claim a marker before one exists: {text}"
        );
        assert_eq!(gate.waiting(), 1, "the preparation is still running");
        assert_eq!(rig.state(), FreezeState::Thawing);
        assert!(!rig.marker().exists(), "no marker exists yet");
        let join_err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let join_text = join_err.to_string();
        assert_eq!(
            join_text,
            "thaw requested: abort accepted, recovery pending (preparation still in flight)"
        );
        assert!(
            !join_text.contains("marker retained"),
            "joining thaw during preparation must not claim marker retained: {join_text}"
        );
        assert!(rig.kernel.calls().is_empty());
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert!(rig.kernel.calls().is_empty(), "no ioctl at all");
        assert!(!rig.marker().exists(), "the late marker was removed");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        assert!(rig.ctx.freeze_op().is_none());
    }

    #[tokio::test]
    async fn thaw_during_preparation_reports_abort_accepted_without_claiming_marker_retained() {
        // A thaw arrives while preparation is still reading the mount table
        // (before `commit_abort` and before `marker.create()`): both the
        // immediate join reply and the freeze-abort reply report pending
        // recovery without claiming a marker is retained.
        let gate = Gate::new();
        let _release = gate.release_on_drop();
        let mounts = Arc::new(GatedMounts {
            table: fixture("nested.txt"),
            gate: gate.clone(),
        });
        let rig = Rig::with_mounts(FreezeState::Thawed, mounts);
        let freezing = rig.spawn_freeze();
        rig.wait_for("preparing", |_| gate.waiting() == 1).await;
        assert!(!rig.marker().exists(), "no marker exists yet");
        let join_err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert_eq!(
            join_err.to_string(),
            "thaw requested: abort accepted, recovery pending (preparation still in flight)"
        );
        let freeze_err = freezing.await.unwrap().unwrap_err();
        assert_eq!(
            freeze_err.to_string(),
            "freeze aborted: thaw requested while preparing; abort accepted, recovery pending"
        );
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert!(!rig.marker().exists());
        assert!(rig.kernel.calls().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn thaw_joining_during_finalisation_after_marker_unlink_does_not_claim_marker_retained() {
        // PR #57 review [P2]: `settle_aborted` removes the marker before
        // `conclude` runs `on_thawed` and retires the operation. A joining
        // thaw in that finalisation window must report pending recovery with
        // observed counts and must not falsely claim `marker retained` after
        // unlink succeeded. Also verify `Phase::Recovering` is already
        // published when the freeze abort reply is delivered.
        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        let b = kernel.script_freeze_gate(B);
        let _release_b = b.release_on_drop();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let hooks = Arc::new(GatedHooks {
            reached: tokio::sync::Notify::new(),
            release: Mutex::new(release_rx),
        });
        let clock = ManualClock::new();
        let marker = Marker::open(dir.path().join("frozen")).unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
                marker.clone(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(StaticMounts(fixture("nested.txt"))))
            .with_hooks(hooks.clone())
            .with_freeze_clock(Arc::new(clock.clone()))
            .with_freeze_operation_timeout(Duration::from_secs(1)),
        );
        // Ensure `on_thawed` never deadlocks even if an assertion fails.
        struct ReleaseOnDrop(Option<std::sync::mpsc::Sender<()>>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        let mut release_guard = ReleaseOnDrop(Some(release_tx));

        let freezing = tokio::spawn({
            let ctx = Arc::clone(&ctx);
            async move { freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#)).await }
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while b.waiting() != 1 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for B"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(marker.exists(), "marker created before FIFREEZE");

        // Trigger deadline abort; once the freeze reply is delivered,
        // `Phase::Recovering` must already be published.
        clock.advance(Duration::from_secs(2));
        let freeze_err = freezing.await.unwrap().unwrap_err();
        assert!(
            freeze_err
                .to_string()
                .contains("operation deadline expired"),
            "{freeze_err}"
        );
        let op = ctx.freeze_op().expect("operation still active");
        assert_eq!(
            op.progress().phase,
            crate::freeze_op::Phase::Recovering,
            "Phase::Recovering must be published before the abort reply is sent"
        );

        // Release B so recovery drains both A and B, unlinks the marker, and
        // pauses inside `on_thawed` before `conclude` retires the operation.
        let entered_on_thawed = hooks.reached.notified();
        tokio::pin!(entered_on_thawed);
        b.release();
        tokio::time::timeout(Duration::from_secs(5), entered_on_thawed)
            .await
            .expect("on_thawed reached");
        assert!(
            !marker.exists(),
            "marker has already been unlinked before on_thawed"
        );
        assert!(
            ctx.freeze_op().is_some(),
            "operation is still registered during finalisation"
        );

        let join_err = thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let text = join_err.to_string();
        assert_eq!(
            text,
            "thaw requested: abort accepted, recovery pending (2 target(s) thawed so far)"
        );
        assert!(
            !text.contains("marker retained")
                && !text.contains("state freezing")
                && !text.contains("state thawing"),
            "unsettled join must not make stale state or marker claims: {text}"
        );

        // Let finalisation finish and confirm clean Thawed settlement.
        let _ = release_guard.0.take().unwrap().send(());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while ctx.state.current() != FreezeState::Thawed {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for Thawed"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(ctx.freeze_op().is_none());
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn a_blocked_recovery_drain_keeps_status_served_and_spawns_nothing_more() {
        // A's FITHAW blocks during the recovery pass: status is still
        // answered, a thaw is answered at once with the recovery pending
        // (it never waits on the drain), a freeze is refused, and no
        // second drain or worker appears.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let b = rig.kernel.script_freeze_gate(B);
        let _release_b = b.release_on_drop();
        let a_thaw = rig.kernel.script_thaw_gate(A);
        let _release_a = a_thaw.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("B blocked", |_| b.waiting() == 1).await;
        rig.expire();
        freezing.await.unwrap().unwrap_err();
        rig.wait_for("drain blocked", |_| a_thaw.waiting() == 1)
            .await;
        let op = rig.ctx.freeze_op().unwrap();
        assert!(!op.progress().recovery_pass_done());
        let value = status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!("frozen"));
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains(
                "recovery pending (0 target(s) thawed so far, a FIFREEZE is still in flight)"
            ),
            "{text}"
        );
        assert!(
            !text.contains(B),
            "wire error must hide in-flight target: {text}"
        );
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot freeze"), "{err}");
        assert_eq!(rig.fithaws(), paths(&[A]), "one drain, blocked");
        assert_eq!(rig.fifreezes().len(), 2, "no new worker");
        a_thaw.release();
        rig.wait_for("pass done", |_| op.progress().recovery_pass_done())
            .await;
        assert_eq!(rig.fithaws(), paths(&[A, A]));
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("1 target(s) thawed so far"),
            "{err}"
        );
        assert_eq!(b.waiting(), 1);
        b.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert!(!rig.marker().exists());
    }

    #[tokio::test]
    async fn a_thaw_during_the_walk_aborts_it_and_is_answered_at_once() {
        // No deadline pressure: the host gives up and sends a thaw while
        // B is still inside FIFREEZE. The thaw aborts the walk and is
        // answered at once; A is drained once, C is never authorised, and
        // a second thaw drains nothing again.
        let rig = Rig::nested();
        let b = rig.kernel.script_freeze_gate(B);
        let _release_b = b.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("B blocked", |_| b.waiting() == 1).await;
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("recovery pending"), "{err}");
        let err = freezing.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("thaw requested"), "{err}");
        let op = rig.ctx.freeze_op().unwrap();
        rig.wait_for("A's recovery pass recorded", |_| {
            op.progress().recovery_pass_done()
        })
        .await;
        assert_eq!(rig.fithaws(), paths(&[A, A]));
        assert_eq!(rig.opens(), paths(&[A, B]));
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("1 target(s) thawed so far"),
            "{err}"
        );
        assert_eq!(rig.fithaws().len(), 2, "no duplicate drain");
        assert!(rig.marker().exists());
        b.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fithaws().len(), 4);
        assert!(!rig.marker().exists());
        // Once settled, a thaw is an ordinary recovery drain again (by
        // pathname over the whole plan).
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(rig.state(), FreezeState::Thawed);
    }

    #[tokio::test]
    async fn an_incomplete_recovery_drain_settles_frozen_with_the_marker_and_the_watchdog() {
        // A's FITHAW is denied: the recovery is incomplete, so when B
        // settles the operation publishes `Frozen` (the watchdog hook
        // fires), keeps the marker, keeps A's handle for the next drain,
        // and retires itself; B itself was thawed.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let b = rig.kernel.script_freeze_gate(B);
        let _release_b = b.release_on_drop();
        rig.kernel.script_thaw_error(A, Errno::EACCES);
        let freezing = rig.spawn_freeze();
        rig.wait_for("B blocked", |_| b.waiting() == 1).await;
        rig.expire();
        freezing.await.unwrap().unwrap_err();
        rig.wait_for("A's drain attempted", |r| r.fithaws() == paths(&[A]))
            .await;
        b.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Frozen)
            .await;
        assert_eq!(rig.fithaws(), paths(&[A, B, B]));
        assert!(rig.marker().exists());
        assert_eq!(rig.held(), 1, "A's handle is kept for the next drain");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "frozen"]);
        assert!(rig.ctx.freeze_op().is_none());
        // The next thaw is an ordinary one from `Frozen`: it retries A
        // through the kept handle (still denied here) and reports it.
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert_eq!(
            text,
            "thaw incomplete: FITHAW permission denied (0 target(s) thawed); state frozen, marker retained"
        );
        assert!(!text.contains(A), "wire error must hide mount: {text}");
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[tokio::test]
    async fn repeated_commands_during_an_unresolved_operation_add_no_work() {
        let ab = aborted_at_b().await;
        let (rig, gate) = (&ab.rig, &ab.gate);
        let before = rig.kernel.calls().len();
        for _ in 0..5 {
            freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
                .await
                .unwrap_err();
            freeze_list(
                &rig.ctx,
                &req(
                    r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/"]}}"#,
                ),
            )
            .await
            .unwrap_err();
            thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
                .await
                .unwrap_err();
            status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
                .await
                .unwrap();
        }
        assert_eq!(rig.kernel.calls().len(), before, "no ioctl, no open");
        assert_eq!(gate.waiting(), 1, "still the one worker");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed"]);
        assert!(rig.ctx.freeze_op().is_some());
    }

    #[tokio::test]
    async fn a_deadline_expiring_during_the_rollback_does_not_abort_it() {
        // C fails hard after A and B froze; the rollback's drain of A
        // blocks past the operation deadline. The rollback is itself the
        // recovery, so the deadline must not abort it: the request reports
        // the hard error once the rollback is complete, the state is
        // `Thawed`, and no abort ever happened.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        rig.kernel.script_freeze_error(C, Errno::EIO);
        let a_thaw = rig.kernel.script_thaw_gate(A);
        let _release = a_thaw.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("rollback blocked", |_| a_thaw.waiting() == 1)
            .await;
        rig.expire();
        tokio::task::yield_now().await;
        assert!(!freezing.is_finished(), "the reply waits for the rollback");
        assert_eq!(rig.state(), FreezeState::Freezing);
        a_thaw.release();
        let err = freezing.await.unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "freeze failed: FIFREEZE failed; rolled back (2 target(s) thawed); state thawed"
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["freezing", "thawed"], "no abort");
        assert!(rig.ctx.freeze_op().is_none());
    }

    #[tokio::test]
    async fn a_lost_preparation_reports_the_task_failure_and_ends_thawed() {
        // The preparation task panics before the marker is created: no
        // ioctl, the (absent) marker is tolerated, and the operation ends
        // `Thawed` with the task failure reported.
        let rig = Rig::with_mounts(FreezeState::Thawed, Arc::new(PanickingMounts));
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "freeze preparation failed; state thawed");
        assert!(rig.kernel.calls().is_empty());
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["freezing", "thawed"]);
    }

    #[tokio::test]
    async fn the_recovered_count_counts_only_targets_a_fithaw_succeeded_on() {
        // B answers EBUSY late and its drain finds it not frozen (EINVAL at
        // once): drained, but not counted as recovered; A was.
        let ab = aborted_at_b().await;
        let (rig, gate) = (&ab.rig, &ab.gate);
        let op = rig.ctx.freeze_op().unwrap();
        rig.kernel.script_freeze_error(B, Errno::EBUSY);
        rig.kernel.script_thaw_successes(B, 0);
        gate.release();
        let progress = op.wait_for_settlement().await;
        assert_eq!(rig.fithaws(), paths(&[A, A, B]));
        assert_eq!(progress.recovered, 1);
        assert_eq!(progress.settled, Some(FreezeState::Thawed));
        assert!(progress.recovery_pass_done());
    }

    #[tokio::test]
    async fn rapid_freeze_thaw_refreeze_keeps_one_operation_registered() {
        // Each operation retires itself before the next is admitted and
        // never touches its successor: the slot is empty between cycles
        // and holds exactly the running operation during one.
        let rig = Rig::nested();
        for _ in 0..10 {
            let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
                .await
                .unwrap();
            assert_eq!(value, json!(4));
            assert!(rig.ctx.freeze_op().is_none(), "retired on settlement");
            assert_eq!(rig.state(), FreezeState::Frozen);
            thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
                .await
                .unwrap();
            assert!(rig.ctx.freeze_op().is_none());
            assert_eq!(rig.state(), FreezeState::Thawed);
        }
        // A settlement in `Frozen` (incomplete recovery) retires too.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(1));
        let b = rig.kernel.script_freeze_gate(B);
        let _release = b.release_on_drop();
        rig.kernel.script_thaw_error(A, Errno::EACCES);
        let freezing = rig.spawn_freeze();
        rig.wait_for("B blocked", |_| b.waiting() == 1).await;
        rig.expire();
        freezing.await.unwrap().unwrap_err();
        b.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Frozen)
            .await;
        assert!(rig.ctx.freeze_op().is_none());
    }

    #[tokio::test]
    async fn a_thaw_that_finds_a_committed_operation_takes_the_ordinary_path() {
        // The operation commits its success a moment before the thaw
        // reaches it (the thaw still holds the registration it looked up
        // while the last target was in flight): the request is answered
        // as committed, the thaw waits for the settlement and then drains
        // from `Frozen` like any thaw, never reporting a recovery that was
        // not started.
        let rig = Rig::nested();
        let d = rig.kernel.script_freeze_gate(D);
        let _release = d.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("D blocked", |_| d.waiting() == 1).await;
        let op = rig.ctx.freeze_op().unwrap();
        d.release();
        let value = freezing.await.unwrap().unwrap();
        assert_eq!(value, json!(4));
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert_eq!(
            op.request_abort(),
            crate::freeze_op::AbortRequest::Committed,
            "nothing to abort after the commit"
        );
        let value = join_operation(&rig.ctx, &op).await.unwrap();
        assert_eq!(value, json!(4), "an ordinary thaw of the four targets");
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert_eq!(
            rig.hooks.events(),
            ["freezing", "frozen", "thaw_claimed", "thawed"]
        );
    }

    #[tokio::test]
    async fn a_thaw_accepted_before_the_commit_makes_the_driver_recover() {
        // The request lands after the driver's last decision boundary and
        // before its commit: the commit fails on the shared transition and
        // the driver recovers everything instead of publishing `Frozen`.
        // Modelled by accepting the abort on the operation directly while
        // the last target is in flight, without waking the driver.
        let rig = Rig::nested();
        let d = rig.kernel.script_freeze_gate(D);
        let _release = d.release_on_drop();
        let freezing = rig.spawn_freeze();
        rig.wait_for("D blocked", |_| d.waiting() == 1).await;
        let op = rig.ctx.freeze_op().unwrap();
        assert_eq!(op.request_abort(), crate::freeze_op::AbortRequest::Accepted);
        d.release();
        let err = freezing.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("thaw requested"), "{err}");
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fithaws(), paths(&[C, C, B, B, A, A, D, D]));
        assert!(!rig.hooks.events().contains(&"frozen"));
        assert!(!rig.marker().exists());
    }

    #[test]
    fn lifecycle_errors_hide_guest_paths_devices_and_marker_paths_on_wire_while_logging_locally() {
        // CVM Blocker 2 (#53, AC27): under the data-protection profile (and
        // unconditionally across profiles), freeze, freeze-list, rollback,
        // marker failure, in-flight abort/join, and recovery thaw errors emit
        // only GenericError, a fixed reason, recovery state, and counts on
        // the wire. Guest mount names, aliases, device numbers, and marker
        // paths stay in guest-local diagnostics only.
        use crate::dispatch::Dispatcher;
        use crate::framing::DecodeEvent;

        const PRIMARY: &str = "/srv/tenant-alpha/db";
        const ALIAS: &str = "/mnt/alias-vol";
        const ALT: &str = "/srv/tenant-alpha/alt";
        const SECOND: &str = "/srv/tenant-beta/app";
        const MARKER_NAME: &str = "tenant-secret-marker";
        const TABLE: &str = concat!(
            "10 1 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n",
            "11 10 8:42 / /srv/tenant-alpha/db rw,relatime - ext4 /dev/vdb1 rw\n",
            "12 10 8:42 / /mnt/alias-vol rw,relatime - ext4 /dev/vdb1 rw\n",
            "13 10 8:42 / /srv/tenant-alpha/alt rw,relatime - ext4 /dev/vdb1 rw\n",
            "14 10 8:43 / /srv/tenant-beta/app rw,relatime - xfs /dev/vdc1 rw\n",
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let dp_config = || {
            let mut cfg = Config::default();
            cfg.features.information = false;
            cfg.features.fstrim = false;
            cfg.features.shutdown = false;
            cfg
        };
        let forbidden = |marker_dir: &Path| {
            vec![
                PRIMARY.to_owned(),
                ALIAS.to_owned(),
                ALT.to_owned(),
                SECOND.to_owned(),
                "tenant-alpha".to_owned(),
                "tenant-beta".to_owned(),
                "8:42".to_owned(),
                "8:43".to_owned(),
                "8:99".to_owned(),
                MARKER_NAME.to_owned(),
                marker_dir.to_string_lossy().into_owned(),
                "/proc/self/mountinfo".to_owned(),
            ]
        };
        let assert_host_safe = |label: &str, reply: &Value, marker_dir: &Path| -> String {
            assert_eq!(reply["error"]["class"], "GenericError", "{label}: {reply}");
            let desc = reply["error"]["desc"]
                .as_str()
                .unwrap_or_else(|| panic!("{label}: missing error.desc: {reply}"))
                .to_owned();
            for item in forbidden(marker_dir) {
                assert!(
                    !desc.contains(&item),
                    "{label}: wire error.desc disclosed {item:?}: {desc:?}"
                );
            }
            desc
        };
        let dispatch_json = |dispatcher: &Dispatcher, json_req: &str| -> Value {
            let raw = runtime
                .block_on(dispatcher.handle(DecodeEvent::Frame {
                    bytes: json_req.as_bytes().to_vec(),
                    sentinel: false,
                }))
                .expect("reply");
            serde_json::from_slice(&raw[..raw.len() - 1]).unwrap()
        };

        // 1. freeze-list via bind alias failing on primary superblock + inventory/trim disabled.
        let dir = tempfile::tempdir().unwrap();
        let marker = Marker::open(dir.path().join(MARKER_NAME)).unwrap();
        let kernel = Arc::new(FakeKernel::new());
        kernel.script_freeze_error(ALIAS, Errno::EIO);
        let ctx = Arc::new(
            Context::new(
                Arc::new(dp_config()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(TABLE.to_owned()))),
        );
        let dispatcher = Dispatcher::new(Arc::clone(&ctx));
        for disabled in ["guest-get-fsinfo", "guest-fstrim"] {
            let reply = dispatch_json(&dispatcher, &format!(r#"{{"execute":"{disabled}"}}"#));
            assert_eq!(reply["error"]["class"], "CommandNotFound", "{reply}");
        }
        let mut reply = Value::Null;
        let logs = capture_warnings(|| {
            reply = dispatch_json(
                &dispatcher,
                r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/mnt/alias-vol"]}}"#,
            );
        });
        let desc = assert_host_safe("freeze-list hard error", &reply, dir.path());
        assert!(
            desc.contains("rolled back") && desc.contains("0 target(s) thawed"),
            "{desc}"
        );
        assert!(desc.contains("state thawed"), "{desc}");
        assert!(logs.contains(PRIMARY), "local log keeps mountpoint: {logs}");

        // 2. Pre-existing marker failure with sensitive custom marker path.
        ctx.marker.create().unwrap();
        let mut reply = Value::Null;
        let logs = capture_warnings(|| {
            reply = dispatch_json(&dispatcher, r#"{"execute":"guest-fsfreeze-freeze"}"#);
        });
        let desc = assert_host_safe("marker create error", &reply, dir.path());
        assert!(desc.contains("cannot create recovery marker"), "{desc}");
        assert!(desc.contains("state thawed"), "{desc}");
        assert!(
            logs.contains(MARKER_NAME),
            "local log keeps marker path: {logs}"
        );
        ctx.marker.remove().unwrap();

        // 3. Hard error with rollback incomplete (stays Frozen, marker retained).
        let kernel = Arc::new(FakeKernel::new());
        kernel.script_freeze_error(PRIMARY, Errno::EIO);
        kernel.script_thaw_error(SECOND, Errno::EIO);
        let ctx = Arc::new(
            Context::new(
                Arc::new(dp_config()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir.path().join(MARKER_NAME)).unwrap(),
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(TABLE.to_owned()))),
        );
        let dispatcher = Dispatcher::new(Arc::clone(&ctx));
        let mut reply = Value::Null;
        let logs = capture_warnings(|| {
            reply = dispatch_json(&dispatcher, r#"{"execute":"guest-fsfreeze-freeze"}"#);
        });
        let desc = assert_host_safe("rollback incomplete", &reply, dir.path());
        assert!(desc.contains("rollback incomplete"), "{desc}");
        assert!(desc.contains("state frozen, marker retained"), "{desc}");
        assert!(
            logs.contains(PRIMARY) && logs.contains(SECOND),
            "local log keeps targets: {logs}"
        );
        let _ = std::fs::remove_file(dir.path().join(MARKER_NAME));

        // 4. In-flight deadline abort + joining thaw (in-flight and after settling Frozen).
        let clock = ManualClock::new();
        let kernel = Arc::new(FakeKernel::new());
        let gate = kernel.script_freeze_gate(PRIMARY);
        let _release = gate.release_on_drop();
        kernel.script_thaw_error(SECOND, Errno::EACCES);
        let ctx = Arc::new(
            Context::new(
                Arc::new(dp_config()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir.path().join(MARKER_NAME)).unwrap(),
            )
            .with_kernel(Arc::clone(&kernel) as Arc<dyn KernelOps>)
            .with_mounts(Arc::new(StaticMounts(TABLE.to_owned())))
            .with_freeze_clock(Arc::new(clock.clone()))
            .with_freeze_operation_timeout(Duration::from_secs(1)),
        );
        let dispatcher = Arc::new(Dispatcher::new(Arc::clone(&ctx)));
        let mut abort_reply = Value::Null;
        let mut join_pending = Value::Null;
        let mut join_settled = Value::Null;
        let logs = capture_warnings(|| {
            use tracing::instrument::WithSubscriber;
            let sub = tracing::dispatcher::get_default(Clone::clone);
            let d = Arc::clone(&dispatcher);
            let freezing = runtime.spawn(
                async move {
                    let raw = d
                        .handle(DecodeEvent::Frame {
                            bytes: br#"{"execute":"guest-fsfreeze-freeze"}"#.to_vec(),
                            sentinel: false,
                        })
                        .await
                        .unwrap();
                    serde_json::from_slice::<Value>(&raw[..raw.len() - 1]).unwrap()
                }
                .with_subscriber(sub),
            );
            runtime.block_on(async {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while gate.waiting() == 0 {
                    assert!(std::time::Instant::now() < deadline);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            clock.advance(Duration::from_secs(1));
            abort_reply = runtime.block_on(freezing).unwrap();
            join_pending = dispatch_json(&dispatcher, r#"{"execute":"guest-fsfreeze-thaw"}"#);
            let op = ctx.freeze_op().unwrap();
            gate.release();
            runtime.block_on(op.wait_for_settlement());
            // Calling join_operation directly on the settled Frozen operation
            // exercises the `Some(state)` arm as well.
            let settled_err = runtime.block_on(join_operation(&ctx, &op)).unwrap_err();
            join_settled = json!({
                "error": {
                    "class": settled_err.class().as_str(),
                    "desc": settled_err.to_string(),
                }
            });
        });
        let desc = assert_host_safe("in-flight deadline abort", &abort_reply, dir.path());
        assert!(
            desc.contains("operation deadline expired") && !desc.contains("1 s"),
            "{desc}"
        );
        assert!(desc.contains("1 target(s) frozen so far"), "{desc}");
        assert!(desc.contains("marker retained"), "{desc}");
        let desc = assert_host_safe("joining thaw pending", &join_pending, dir.path());
        assert!(desc.contains("abort accepted, recovery pending"), "{desc}");
        assert!(desc.contains("target(s) thawed so far"), "{desc}");
        assert!(
            !desc.contains("marker retained"),
            "unsettled join must not claim marker retained: {desc}"
        );
        let desc = assert_host_safe("joining thaw settled frozen", &join_settled, dir.path());
        assert!(desc.contains("target(s) thawed"), "{desc}");
        assert!(desc.contains("state frozen, marker retained"), "{desc}");
        assert!(
            logs.contains(PRIMARY) && logs.contains("\"timeout_secs\":1"),
            "local log keeps in-flight target and timeout_secs: {logs}"
        );
        let _ = std::fs::remove_file(dir.path().join(MARKER_NAME));

        // 5. Recovery thaw with unreachable overmounted superblock and aliases.
        let kernel = Arc::new(FakeKernel::new());
        kernel.script_mount_device(PRIMARY, (8, 99));
        kernel.script_open_error(ALIAS, Errno::ENOENT);
        kernel.script_open_error(ALT, Errno::EACCES);
        let marker = Marker::open(dir.path().join(MARKER_NAME)).unwrap();
        marker.create().unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(dp_config()),
                Arc::new(FreezeStateMachine::starting_frozen()),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(TABLE.to_owned()))),
        );
        let dispatcher = Dispatcher::new(Arc::clone(&ctx));
        let mut reply = Value::Null;
        let logs = capture_warnings(|| {
            reply = dispatch_json(&dispatcher, r#"{"execute":"guest-fsfreeze-thaw"}"#);
        });
        let desc = assert_host_safe("recovery thaw unreachable", &reply, dir.path());
        assert!(
            desc.contains("target unreachable; no FITHAW issued"),
            "{desc}"
        );
        assert!(desc.contains("2 target(s) thawed"), "{desc}");
        assert!(desc.contains("state frozen, marker retained"), "{desc}");
        assert!(
            logs.contains(PRIMARY)
                && logs.contains(ALIAS)
                && logs.contains(ALT)
                && logs.contains("8:42"),
            "local log keeps unreachable diagnostics: {logs}"
        );
        let _ = std::fs::remove_file(dir.path().join(MARKER_NAME));

        // 6. Recovery thaw when mountinfo cannot be read.
        struct FailingMounts;
        impl MountSource for FailingMounts {
            fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
                Err(Error::Internal(
                    "cannot read /proc/self/mountinfo: Too many open files".to_owned(),
                ))
            }
        }
        let marker = Marker::open(dir.path().join(MARKER_NAME)).unwrap();
        marker.create().unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(dp_config()),
                Arc::new(FreezeStateMachine::starting_frozen()),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(Arc::new(FakeKernel::new()))
            .with_mounts(Arc::new(FailingMounts)),
        );
        let dispatcher = Dispatcher::new(Arc::clone(&ctx));
        let mut reply = Value::Null;
        let logs = capture_warnings(|| {
            reply = dispatch_json(&dispatcher, r#"{"execute":"guest-fsfreeze-thaw"}"#);
        });
        let desc = assert_host_safe("recovery thaw plan error", &reply, dir.path());
        assert!(desc.contains("cannot build thaw plan"), "{desc}");
        assert!(desc.contains("0 target(s) thawed"), "{desc}");
        assert!(desc.contains("state frozen, marker retained"), "{desc}");
        assert!(
            logs.contains("/proc/self/mountinfo"),
            "local log keeps mountinfo error: {logs}"
        );
    }

    #[test]
    fn all_host_descriptions_are_fixed_and_redact_guest_secrets() {
        const GUEST_MOUNT: &str = "/srv/tenant-alpha/vault";
        const GUEST_ALIAS: &str = "/mnt/tenant-alpha-alias";
        const GUEST_MARKER: &str = "/run/qeminga-tenant/frozen";
        const GUEST_DEV: &str = "253:77";
        const GUEST_DETAIL: &str = "internal-diagnostic-detail";

        let marker_err = || MarkerError::Io {
            path: PathBuf::from(GUEST_MARKER),
            op: "unlink",
            errno: Errno::EACCES,
        };
        let assert_clean = |label: &str, text: &str| {
            for forbidden in [
                GUEST_MOUNT,
                GUEST_ALIAS,
                GUEST_MARKER,
                GUEST_DEV,
                GUEST_DETAIL,
                "/proc/self/mountinfo",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{label}: leaked {forbidden:?} in {text:?}"
                );
            }
        };

        // Every FreezeStop arm.
        let stops = [
            (
                FreezeStop::Ioctl(KernelError::Errno(Errno::EPERM)),
                "FIFREEZE permission denied",
            ),
            (
                FreezeStop::Ioctl(KernelError::Open(Errno::EMFILE)),
                "target open failed; no FIFREEZE issued",
            ),
            (
                FreezeStop::Ioctl(KernelError::WrongFilesystem {
                    expected: (253, 77),
                    found: (8, 9),
                }),
                "target unreachable; no FIFREEZE issued",
            ),
            (
                FreezeStop::Ioctl(KernelError::Errno(Errno::EIO)),
                "FIFREEZE failed",
            ),
            (
                FreezeStop::Unreachable {
                    attempts: format!("{GUEST_MOUNT}: EACCES; {GUEST_ALIAS}: EACCES"),
                    permission_denied: true,
                },
                "target open permission denied; no FIFREEZE issued",
            ),
            (
                FreezeStop::Unreachable {
                    attempts: format!("{GUEST_MOUNT}: on {GUEST_DEV}; {GUEST_ALIAS}: ENOENT"),
                    permission_denied: false,
                },
                "target unreachable; no FIFREEZE issued",
            ),
            (
                FreezeStop::OwnershipAmbiguous(format!(
                    "{GUEST_MOUNT}: {GUEST_DEV}: {GUEST_DETAIL}"
                )),
                "freeze ownership is ambiguous; cannot claim target",
            ),
            (
                FreezeStop::OwnershipError(crate::ownership::OwnershipError::Io {
                    dev: Some((253, 77)),
                    op: "create",
                    errno: Errno::EIO,
                }),
                "cannot update freeze ownership state",
            ),
            (
                FreezeStop::OwnershipReleaseFailed {
                    kind: RecoveryReason::OwnershipError,
                    detail: format!("{GUEST_MOUNT}: {GUEST_DEV}: {GUEST_DETAIL}"),
                },
                "cannot update freeze ownership state",
            ),
        ];
        for (stop, expected) in &stops {
            assert_eq!(stop.host_reason(), *expected);
            assert_clean("FreezeStop", stop.host_reason());
        }

        // Every RecoveryReason arm.
        for reason in [
            RecoveryReason::TargetUnreachable,
            RecoveryReason::TargetOpenFailed,
            RecoveryReason::TargetOpenPermissionDenied,
            RecoveryReason::PermissionDenied,
            RecoveryReason::IoctlFailed,
            RecoveryReason::DrainDidNotConverge,
            RecoveryReason::WorkerLost,
            RecoveryReason::DrainLost,
            RecoveryReason::MarkerRetained,
            RecoveryReason::OwnershipAmbiguous,
            RecoveryReason::OwnershipError,
        ] {
            let text = reason.host_reason();
            assert!(!text.is_empty());
            assert_clean("RecoveryReason", text);
        }

        // Every FreezeFailure arm + retains_frozen_state.
        let freeze_cases: Vec<(FreezeFailure, bool, &str)> = vec![
            (
                FreezeFailure::Plan(format!("/proc/self/mountinfo: {GUEST_DETAIL}")),
                false,
                "cannot build freeze plan; state thawed",
            ),
            (
                FreezeFailure::Marker(MarkerError::AlreadyPresent {
                    path: PathBuf::from(GUEST_MARKER),
                }),
                false,
                "cannot create recovery marker: recovery marker already exists; state thawed",
            ),
            (
                FreezeFailure::Hard {
                    mountpoint: GUEST_MOUNT.into(),
                    cause: FreezeStop::Ioctl(KernelError::Errno(Errno::EIO)),
                    rolled_back: 2,
                },
                false,
                "freeze failed: FIFREEZE failed; rolled back (2 target(s) thawed); state thawed",
            ),
            (
                FreezeFailure::RollbackIncomplete {
                    failed: GUEST_MOUNT.into(),
                    cause: FreezeStop::Ioctl(KernelError::Errno(Errno::EIO)),
                    mountpoint: GUEST_ALIAS.into(),
                    recovery_reason: RecoveryReason::PermissionDenied,
                    reason: format!("{GUEST_ALIAS}: {GUEST_DEV}: {GUEST_DETAIL}"),
                    rolled_back: 1,
                },
                true,
                "freeze failed: FIFREEZE failed; rollback incomplete (FITHAW permission denied, 1 target(s) thawed); state frozen, marker retained",
            ),
            (
                FreezeFailure::MarkerRetained {
                    failed: GUEST_MOUNT.into(),
                    cause: FreezeStop::Ioctl(KernelError::Errno(Errno::EIO)),
                    marker: marker_err(),
                    rolled_back: 3,
                },
                true,
                "freeze failed: FIFREEZE failed; rolled back (3 target(s) thawed) but cannot remove recovery marker: recovery marker unlink failed; state frozen, marker retained",
            ),
            (
                FreezeFailure::PreparationMarkerRetained {
                    cause: GUEST_DETAIL.into(),
                    marker: marker_err(),
                },
                true,
                "freeze preparation failed; cannot remove recovery marker: recovery marker unlink failed; state frozen, marker retained",
            ),
            (
                FreezeFailure::Task {
                    stage: FreezeTaskStage::Preparation,
                    detail: GUEST_DETAIL.into(),
                },
                false,
                "freeze preparation failed; state thawed",
            ),
            (
                FreezeFailure::Task {
                    stage: FreezeTaskStage::Rollback,
                    detail: GUEST_DETAIL.into(),
                },
                true,
                "freeze rollback failed; state frozen, marker retained",
            ),
            (
                FreezeFailure::Task {
                    stage: FreezeTaskStage::MarkerRemoval,
                    detail: GUEST_DETAIL.into(),
                },
                true,
                "nothing was frozen (0 target(s) frozen) and marker removal failed; state frozen, marker retained",
            ),
            (
                FreezeFailure::NothingFrozenMarkerRetained(marker_err()),
                true,
                "nothing was frozen (0 target(s) frozen) but cannot remove recovery marker: recovery marker unlink failed; state frozen, marker retained",
            ),
            (
                FreezeFailure::Aborted {
                    cause: crate::freeze_op::AbortCause::Deadline,
                    timeout_secs: 30,
                    frozen: 0,
                    in_flight: Some(crate::freeze_op::PREPARING.into()),
                },
                false,
                "freeze aborted: operation deadline expired while preparing; abort accepted, recovery pending",
            ),
            (
                FreezeFailure::Aborted {
                    cause: crate::freeze_op::AbortCause::ThawRequested,
                    timeout_secs: 30,
                    frozen: 2,
                    in_flight: Some(GUEST_MOUNT.into()),
                },
                false,
                "freeze aborted: thaw requested with a FIFREEZE in flight; 2 target(s) frozen so far are being thawed; state thawing, marker retained",
            ),
            (
                FreezeFailure::Aborted {
                    cause: crate::freeze_op::AbortCause::Deadline,
                    timeout_secs: 10,
                    frozen: 1,
                    in_flight: None,
                },
                false,
                "freeze aborted: operation deadline expired; 1 target(s) frozen so far are being thawed; state thawing, marker retained",
            ),
        ];
        for (failure, retains, expected) in &freeze_cases {
            assert_eq!(failure.retains_frozen_state(), *retains, "{failure:?}");
            let desc = failure.host_description();
            assert_eq!(desc, *expected);
            assert!(
                !desc.contains("30 s") && !desc.contains("10 s"),
                "wire error must not disclose timeout duration: {desc}"
            );
            assert_clean("FreezeFailure", &desc);
        }
        // Two different timeout configurations reaching the same deadline
        // outcome produce identical host-facing wire text (PR #57).
        let short_timeout = FreezeFailure::Aborted {
            cause: crate::freeze_op::AbortCause::Deadline,
            timeout_secs: 5,
            frozen: 1,
            in_flight: Some(GUEST_MOUNT.into()),
        };
        let long_timeout = FreezeFailure::Aborted {
            cause: crate::freeze_op::AbortCause::Deadline,
            timeout_secs: 300,
            frozen: 1,
            in_flight: Some(GUEST_MOUNT.into()),
        };
        assert_eq!(
            short_timeout.host_description(),
            long_timeout.host_description()
        );
        assert!(short_timeout.to_string().contains("5 s"));
        assert!(long_timeout.to_string().contains("300 s"));

        // Every joining-thaw pending arm across the unsettled window uses the
        // fixed "abort accepted, recovery pending" wording with observed count
        // and activity, never making stale state or marker claims.
        let joining_cases = [
            (
                crate::freeze_op::Progress {
                    phase: crate::freeze_op::Phase::Freezing,
                    frozen: 0,
                    in_flight: Some(crate::freeze_op::PREPARING.into()),
                    recovery_pass_done: false,
                    recovered: 0,
                    unrecoverable_reason: None,
                    settled: None,
                },
                "thaw requested: abort accepted, recovery pending (preparation still in flight)",
            ),
            (
                crate::freeze_op::Progress {
                    phase: crate::freeze_op::Phase::Recovering,
                    frozen: 0,
                    in_flight: Some(crate::freeze_op::PREPARING.into()),
                    recovery_pass_done: false,
                    recovered: 0,
                    unrecoverable_reason: None,
                    settled: None,
                },
                "thaw requested: abort accepted, recovery pending (preparation still in flight)",
            ),
            (
                crate::freeze_op::Progress {
                    phase: crate::freeze_op::Phase::Freezing,
                    frozen: 1,
                    in_flight: Some(GUEST_MOUNT.into()),
                    recovery_pass_done: false,
                    recovered: 0,
                    unrecoverable_reason: None,
                    settled: None,
                },
                "thaw requested: abort accepted, recovery pending (0 target(s) thawed so far, a FIFREEZE is still in flight)",
            ),
            (
                crate::freeze_op::Progress {
                    phase: crate::freeze_op::Phase::Recovering,
                    frozen: 1,
                    in_flight: Some(GUEST_MOUNT.into()),
                    recovery_pass_done: false,
                    recovered: 1,
                    unrecoverable_reason: None,
                    settled: None,
                },
                "thaw requested: abort accepted, recovery pending (1 target(s) thawed so far, a FIFREEZE is still in flight)",
            ),
            (
                crate::freeze_op::Progress {
                    phase: crate::freeze_op::Phase::Recovering,
                    frozen: 2,
                    in_flight: None,
                    recovery_pass_done: false,
                    recovered: 2,
                    unrecoverable_reason: None,
                    settled: None,
                },
                "thaw requested: abort accepted, recovery pending (2 target(s) thawed so far)",
            ),
        ];
        for (progress, expected) in &joining_cases {
            let desc = format_joining_pending(progress);
            assert_eq!(desc, *expected);
            assert_clean("format_joining_pending", &desc);
        }

        // Every ThawFailure arm in both Frozen and Thawed final states.
        let thaw_cases = [
            (
                ThawFailure::Plan {
                    detail: format!("/proc/self/mountinfo: {GUEST_DETAIL}"),
                    thawed: 2,
                },
                "cannot build thaw plan (2 target(s) thawed); state frozen, marker retained",
                "cannot build thaw plan (2 target(s) thawed); state thawed",
            ),
            (
                ThawFailure::Incomplete {
                    mountpoint: GUEST_MOUNT.into(),
                    kind: RecoveryReason::TargetOpenFailed,
                    reason: format!("{GUEST_MOUNT}: {GUEST_DEV}: {GUEST_DETAIL}"),
                    thawed: 1,
                },
                "thaw incomplete: target open failed; no FITHAW issued (1 target(s) thawed); state frozen, marker retained",
                "thaw incomplete: target open failed; no FITHAW issued (1 target(s) thawed); state thawed",
            ),
            (
                ThawFailure::Marker {
                    err: marker_err(),
                    thawed: 4,
                },
                "drain complete (4 target(s) thawed) but cannot remove recovery marker: recovery marker unlink failed; state frozen, marker retained",
                "drain complete (4 target(s) thawed) but cannot remove recovery marker: recovery marker unlink failed; state thawed",
            ),
            (
                ThawFailure::Task(GUEST_DETAIL.into()),
                "thaw task failed; state frozen, marker retained",
                "thaw task failed; state thawed",
            ),
        ];
        for (failure, frozen_expected, thawed_expected) in &thaw_cases {
            let frozen_desc = failure.host_description(FreezeState::Frozen);
            let unavail_desc = failure.host_description_with_marker(FreezeState::Frozen, false);
            let thawed_desc = failure.host_description(FreezeState::Thawed);
            assert_eq!(frozen_desc, *frozen_expected);
            assert_eq!(
                unavail_desc,
                frozen_expected.replace("marker retained", "marker unavailable")
            );
            assert_eq!(thawed_desc, *thawed_expected);
            assert_clean("ThawFailure(Frozen)", &frozen_desc);
            assert_clean("ThawFailure(Frozen, unavailable)", &unavail_desc);
            assert_clean("ThawFailure(Thawed)", &thawed_desc);
        }
    }

    fn rig_with_allowed(state: FreezeState, mountinfo: &str, allowed: Option<Vec<&str>>) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let hooks = Arc::new(Recorder::default());
        let clock = ManualClock::new();
        let mut config = Config::default();
        config.agent.freeze_allowed_mountpoints =
            allowed.map(|list| list.into_iter().map(str::to_owned).collect());
        let ctx = Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(std::io::sink())),
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(mountinfo.to_owned())))
        .with_hooks(hooks.clone())
        .with_freeze_clock(Arc::new(clock.clone()));
        Rig {
            ctx: Arc::new(ctx),
            kernel,
            hooks,
            clock,
            _dir: dir,
        }
    }

    #[tokio::test]
    async fn guest_allowlist_blocks_unauthorized_selections_aliases_and_whole_guest() {
        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:2 / /data-alias rw - ext4 /dev/sdb1 rw\n",
            "4 1 8:3 / /secret rw - ext4 /dev/sdc1 rw\n",
        );
        let rig = rig_with_allowed(FreezeState::Thawed, mounts, Some(vec!["/data"]));

        // 1. Unauthorized mount selection yields guest-independent 0 without opening it.
        let req = parse_request(
            br#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/secret"]}}"#,
        )
        .unwrap();
        assert_eq!(freeze_list(&rig.ctx, &req).await.unwrap(), json!(0));
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert!(rig.kernel.calls().is_empty(), "{:?}", rig.kernel.calls());

        // 2. Unauthorized alias of an allowed superblock also yields 0 without lookup.
        let req = parse_request(
            br#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/data-alias"]}}"#,
        )
        .unwrap();
        assert_eq!(freeze_list(&rig.ctx, &req).await.unwrap(), json!(0));
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert!(rig.kernel.calls().is_empty(), "{:?}", rig.kernel.calls());

        // 3. Mixed authorized + unauthorized selection freezes only `/data` and returns 1.
        let req = parse_request(
            br#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/secret","/data","/data-alias"]}}"#,
        )
        .unwrap();
        assert_eq!(freeze_list(&rig.ctx, &req).await.unwrap(), json!(1));
        assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
        let opened: Vec<(PathBuf, (u32, u32))> = rig
            .kernel
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Open(p, d) => Some((p, d)),
                _ => None,
            })
            .collect();
        assert_eq!(opened, vec![(PathBuf::from("/data"), (8, 2))]);
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&rig.ctx, &req).await.unwrap(), json!(1));
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);

        // 4. Whole-guest freeze is narrowed to the guest allowlist.
        let rig_whole = rig_with_allowed(FreezeState::Thawed, mounts, Some(vec!["/data"]));
        let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        assert_eq!(freeze(&rig_whole.ctx, &req).await.unwrap(), json!(1));
        assert!(
            !rig_whole
                .kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Open(_, d) if *d != (8, 2)))
        );
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&rig_whole.ctx, &req).await.unwrap(), json!(1));

        // 5. Omitted-list `guest-fsfreeze-freeze-list` is narrowed identically.
        let rig_omitted = rig_with_allowed(FreezeState::Thawed, mounts, Some(vec!["/data"]));
        let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze-list"}"#).unwrap();
        assert_eq!(freeze_list(&rig_omitted.ctx, &req).await.unwrap(), json!(1));
        assert!(
            !rig_omitted
                .kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Open(_, d) if *d != (8, 2)))
        );
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&rig_omitted.ctx, &req).await.unwrap(), json!(1));

        // 6. Explicit empty allowlist freezes nothing even on whole-guest requests.
        let rig_empty = rig_with_allowed(FreezeState::Thawed, mounts, Some(vec![]));
        let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        assert_eq!(freeze(&rig_empty.ctx, &req).await.unwrap(), json!(0));
        assert_eq!(rig_empty.ctx.state.current(), FreezeState::Thawed);
        assert!(rig_empty.kernel.calls().is_empty());
    }

    #[tokio::test]
    async fn guest_allowlist_marker_recovery_drains_narrowed_obligations_and_filters_wire_count() {
        // After a crash while `/data` (8:2) and `/extra` (8:3, authorized under
        // an earlier broader config) were frozen, the restarted guest narrows
        // `freeze_allowed_mountpoints` to `["/data"]`. Under v1's sole-freezer
        // assumption, marker recovery drains BOTH 8:2 and 8:3 before removing
        // `/run/qeminga/frozen` so no earlier freeze is stranded, while
        // reporting only the currently visible allowlisted count `1` on the wire.
        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /extra rw - ext4 /dev/sdc1 rw\n",
        );
        let rig = rig_with_allowed(FreezeState::Frozen, mounts, Some(vec!["/data"]));
        rig.ctx.marker.create().unwrap();
        let m2 = rig.kernel.open_mount(Path::new("/data"), (8, 2)).unwrap();
        rig.kernel.fifreeze(&m2).unwrap();
        let m3 = rig.kernel.open_mount(Path::new("/extra"), (8, 3)).unwrap();
        rig.kernel.fifreeze(&m3).unwrap();

        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&rig.ctx, &req).await.unwrap(), json!(1));
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert!(!rig.ctx.marker.exists());
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);

        // Once Thawed (no marker, no crash obligation), a host-requested
        // recovery drain strictly scopes discovery to currently visible
        // `freeze_allowed_mountpoints` and never opens unprovisioned mounts.
        let m3_again = rig.kernel.open_mount(Path::new("/extra"), (8, 3)).unwrap();
        rig.kernel.fifreeze(&m3_again).unwrap();
        let before = rig.kernel.calls().len();
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&rig.ctx, &req).await.unwrap(), json!(0));
        let after_calls = &rig.kernel.calls()[before..];
        assert!(
            !after_calls
                .iter()
                .any(|c| matches!(c, Call::Open(_, d) if *d == (8, 1) || *d == (8, 3))),
            "thaw from Thawed must not open unprovisioned superblocks: {after_calls:?}"
        );
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 1);
    }

    #[tokio::test]
    async fn guest_allowlist_hides_overmounted_historical_occupant_in_count_and_thawed_drain() {
        // 8:2 was mounted at `/data` (with unlisted alias `/data-alias`), then
        // 8:4 was mounted over `/data`. Only 8:4 is currently visible at `/data`.
        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:2 / /data-alias rw - ext4 /dev/sdb1 rw\n",
            "4 2 8:4 / /data rw - ext4 /dev/sdd1 rw\n",
        );
        let rig = rig_with_allowed(FreezeState::Frozen, mounts, Some(vec!["/data"]));
        rig.ctx.marker.create().unwrap();
        let m2 = rig
            .kernel
            .open_mount(Path::new("/data-alias"), (8, 2))
            .unwrap();
        rig.kernel.fifreeze(&m2).unwrap();

        // Marker recovery drains hidden 8:2 internally via `/data-alias` so no
        // prior freeze is stranded, removes the marker, and reports 0 because
        // 8:2 is NOT currently visible at `/data`.
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&rig.ctx, &req).await.unwrap(), json!(0));
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert!(!rig.ctx.marker.exists());
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);

        // From clean Thawed (marker absent), thaw must NOT open `/data-alias`
        // or thaw hidden 8:2.
        let m2_again = rig
            .kernel
            .open_mount(Path::new("/data-alias"), (8, 2))
            .unwrap();
        rig.kernel.fifreeze(&m2_again).unwrap();
        let before = rig.kernel.calls().len();
        assert_eq!(thaw(&rig.ctx, &req).await.unwrap(), json!(0));
        let after_calls = &rig.kernel.calls()[before..];
        assert!(
            !after_calls
                .iter()
                .any(|c| matches!(c, Call::Open(_, d) if *d == (8, 2))),
            "clean Thawed drain must not act on hidden historical occupant 8:2: {after_calls:?}"
        );
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 1);
    }

    #[tokio::test]
    async fn guest_allowlist_marker_recovery_retains_marker_if_narrowed_target_cannot_thaw() {
        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /extra rw - ext4 /dev/sdc1 rw\n",
        );
        let rig = rig_with_allowed(FreezeState::Frozen, mounts, Some(vec!["/data"]));
        rig.ctx.marker.create().unwrap();
        let m2 = rig.kernel.open_mount(Path::new("/data"), (8, 2)).unwrap();
        rig.kernel.fifreeze(&m2).unwrap();
        let m3 = rig.kernel.open_mount(Path::new("/extra"), (8, 3)).unwrap();
        rig.kernel.fifreeze(&m3).unwrap();
        rig.kernel.script_thaw_error("/extra", Errno::EIO);

        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let err = thaw(&rig.ctx, &req).await.unwrap_err();
        let desc = err.to_string();
        assert_eq!(
            desc,
            "thaw incomplete: recovery did not complete; filesystem may still be frozen (1 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
        assert!(rig.ctx.marker.exists());
    }

    #[tokio::test]
    async fn excluded_target_recovery_failures_collapse_to_single_fixed_reason_while_authorized_keeps_detail()
     {
        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /extra rw - ext4 /dev/sdc1 rw\n",
        );
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let fixed_excluded = "thaw incomplete: recovery did not complete; filesystem may still be frozen (0 target(s) thawed); state frozen, marker retained";

        // 1. Excluded open ENOENT (unreachable), open EACCES, FITHAW EACCES,
        //    FITHAW EIO, and non-convergence all emit the exact same fixed wire reason.
        for case in 0..5 {
            let rig = rig_with_allowed(FreezeState::Frozen, mounts, Some(vec!["/data"]));
            rig.ctx.marker.create().unwrap();
            match case {
                0 => rig.kernel.script_open_error("/extra", Errno::ENOENT),
                1 => rig.kernel.script_open_error("/extra", Errno::EACCES),
                2 => {
                    let m3 = rig.kernel.open_mount(Path::new("/extra"), (8, 3)).unwrap();
                    rig.kernel.fifreeze(&m3).unwrap();
                    rig.kernel.script_thaw_error("/extra", Errno::EACCES);
                }
                3 => {
                    let m3 = rig.kernel.open_mount(Path::new("/extra"), (8, 3)).unwrap();
                    rig.kernel.fifreeze(&m3).unwrap();
                    rig.kernel.script_thaw_error("/extra", Errno::EIO);
                }
                4 => {
                    rig.kernel
                        .script_thaw_successes("/extra", MAX_THAW_ITERATIONS);
                }
                _ => unreachable!(),
            }
            let err = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
            assert_eq!(err, fixed_excluded, "case {case} leaked failure class");
            assert!(rig.ctx.marker.exists());
        }

        // 2. When an excluded target fails FIRST (`/`) and an authorized target
        //    fails LATER (`/data` EACCES), the authorized failure class wins.
        let rig_auth_second = rig_with_allowed(FreezeState::Frozen, mounts, Some(vec!["/data"]));
        rig_auth_second.ctx.marker.create().unwrap();
        rig_auth_second.kernel.script_open_error("/", Errno::ENOENT);
        let m2 = rig_auth_second
            .kernel
            .open_mount(Path::new("/data"), (8, 2))
            .unwrap();
        rig_auth_second.kernel.fifreeze(&m2).unwrap();
        rig_auth_second
            .kernel
            .script_thaw_error("/data", Errno::EACCES);
        let err = thaw(&rig_auth_second.ctx, &req)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("FITHAW permission denied"),
            "authorized failure should take precedence over excluded placeholder: {err}"
        );

        // 3. When an authorized target fails FIRST (`/data` EACCES) and an
        //    excluded target fails LATER (`/extra` EIO), authorized reason stays.
        let rig_auth_first = rig_with_allowed(FreezeState::Frozen, mounts, Some(vec!["/data"]));
        rig_auth_first.ctx.marker.create().unwrap();
        let m2 = rig_auth_first
            .kernel
            .open_mount(Path::new("/data"), (8, 2))
            .unwrap();
        rig_auth_first.kernel.fifreeze(&m2).unwrap();
        rig_auth_first
            .kernel
            .script_thaw_error("/data", Errno::EACCES);
        rig_auth_first
            .kernel
            .script_open_error("/extra", Errno::EIO);
        let err = thaw(&rig_auth_first.ctx, &req)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("FITHAW permission denied"),
            "authorized first failure must be preserved: {err}"
        );
    }

    #[tokio::test]
    async fn thawed_drain_escalates_on_present_or_indeterminate_marker_and_narrow_drain_preserves_marker()
     {
        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /extra rw - ext4 /dev/sdc1 rw\n",
        );
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // A. State is Thawed yet marker IS present: must escalate to full
        //    recovery, drain `/extra`, and remove the marker.
        let rig_present = rig_with_allowed(FreezeState::Thawed, mounts, Some(vec!["/data"]));
        rig_present.ctx.marker.create().unwrap();
        let m3 = rig_present
            .kernel
            .open_mount(Path::new("/extra"), (8, 3))
            .unwrap();
        rig_present.kernel.fifreeze(&m3).unwrap();
        assert_eq!(thaw(&rig_present.ctx, &req).await.unwrap(), json!(0));
        assert_eq!(rig_present.kernel.tracked_frozen_superblocks(), 0);
        assert!(!rig_present.ctx.marker.exists());

        // B. State is Thawed and marker probe is indeterminate (ENAMETOOLONG):
        //    must NOT silently narrow — escalates to full recovery, drains
        //    `/extra`, fails to clear the unconfirmed marker, and stays Frozen.
        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let mut config = Config::default();
        config.agent.freeze_allowed_mountpoints = Some(vec!["/data".to_owned()]);
        let ctx_indet = Arc::new(
            Context::new(
                Arc::new(config),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir.path().join("a".repeat(256))).unwrap(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(StaticMounts(mounts.to_owned()))),
        );
        let m3 = kernel.open_mount(Path::new("/extra"), (8, 3)).unwrap();
        kernel.fifreeze(&m3).unwrap();
        let err = thaw(&ctx_indet, &req).await.unwrap_err().to_string();
        assert_eq!(kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(ctx_indet.state.current(), FreezeState::Frozen);
        assert!(err.contains("marker retained"), "{err}");

        // C. State is Frozen with no marker (e.g. discovery recovery after an
        //    uncertain freeze): must NOT narrow even though marker is absent.
        let rig_frozen_no_marker =
            rig_with_allowed(FreezeState::Frozen, mounts, Some(vec!["/data"]));
        let m3 = rig_frozen_no_marker
            .kernel
            .open_mount(Path::new("/extra"), (8, 3))
            .unwrap();
        rig_frozen_no_marker.kernel.fifreeze(&m3).unwrap();
        assert_eq!(
            thaw(&rig_frozen_no_marker.ctx, &req).await.unwrap(),
            json!(0)
        );
        assert_eq!(rig_frozen_no_marker.kernel.tracked_frozen_superblocks(), 0);

        // D. Clean Thawed drain (marker confirmed absent) must NEVER call
        //    marker.remove() — verified by creating a marker mid-drain while
        //    `/data`'s thaw gate is paused.
        let rig_narrow = rig_with_allowed(FreezeState::Thawed, mounts, Some(vec!["/data"]));
        let gate = rig_narrow.kernel.script_thaw_gate("/data");
        let _guard = gate.release_on_drop();
        let ctx_clone = Arc::clone(&rig_narrow.ctx);
        let req_clone = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let task = tokio::spawn(async move { thaw(&ctx_clone, &req_clone).await });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        rig_narrow.ctx.marker.create().unwrap();
        gate.release();
        assert_eq!(task.await.unwrap().unwrap(), json!(0));
        assert!(
            rig_narrow.ctx.marker.exists(),
            "narrowed Thawed drain must never remove a marker"
        );
    }

    #[tokio::test]
    async fn empty_effective_freeze_selection_settles_without_mountinfo_or_marker_io_through_dispatch()
     {
        use crate::dispatch::Dispatcher;
        use crate::framing::DecodeEvent;

        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        let mut config = Config::default();
        config.agent.freeze_allowed_mountpoints = Some(vec!["/data".to_owned()]);
        config.rate_limits.fsfreeze_freeze_per_min = 2;
        // Create a directory at the marker path so `marker.create()` would fail
        // with EEXIST/EISDIR, AND `PanickingMounts` panics if `read_mountinfo()`
        // is ever touched!
        let marker_path = dir.path().join("frozen");
        std::fs::create_dir(&marker_path).unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(config),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(&marker_path).unwrap(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(PanickingMounts)),
        );
        let dispatcher = Dispatcher::new(Arc::clone(&ctx));

        // 1. Unauthorized selection settles to 0 without touching mountinfo,
        //    marker, or kernel, through normal dispatch.
        let frame = |b: &[u8]| DecodeEvent::Frame {
            bytes: b.to_vec(),
            sentinel: false,
        };
        let raw = dispatcher
            .handle(frame(
                br#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/secret"]}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).unwrap(),
            json!({"return": 0})
        );
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(kernel.calls().is_empty());

        // 2. Explicit empty list also settles to 0 without mountinfo/marker I/O.
        let raw = dispatcher
            .handle(frame(
                br#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":[]}}"#,
            ))
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).unwrap(),
            json!({"return": 0})
        );
        assert_eq!(ctx.state.current(), FreezeState::Thawed);

        // 3. Rate limiting still applies on the 3rd request (limit = 2/min).
        let raw = dispatcher
            .handle(frame(
                br#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":[]}}"#,
            ))
            .await
            .unwrap();
        let val: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(val["error"]["class"], "GenericError");
        assert!(
            val["error"]["desc"]
                .as_str()
                .unwrap()
                .contains("rate limit")
        );

        // 4. While Frozen (outstanding recovery), an empty selection is still
        //    rejected at the admission gate.
        let mut frozen_config = Config::default();
        frozen_config.agent.freeze_allowed_mountpoints = Some(vec![]);
        let frozen_ctx = Arc::new(
            Context::new(
                Arc::new(frozen_config),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Frozen)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(&marker_path).unwrap(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(PanickingMounts)),
        );
        let frozen_dispatcher = Dispatcher::new(frozen_ctx);
        let raw = frozen_dispatcher
            .handle(frame(br#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        let val: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            val["error"]["desc"],
            "filesystems are frozen; retry after thaw"
        );
    }

    fn rig_with_allowed_mounts(
        state: FreezeState,
        mounts: Arc<dyn MountSource>,
        allowed: Option<Vec<&str>>,
    ) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let hooks = Arc::new(Recorder::default());
        let clock = ManualClock::new();
        let mut config = Config::default();
        config.agent.freeze_allowed_mountpoints =
            allowed.map(|list| list.into_iter().map(str::to_owned).collect());
        let ctx = Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(std::io::sink())),
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(kernel.clone())
        .with_mounts(mounts)
        .with_hooks(hooks.clone())
        .with_freeze_clock(Arc::new(clock.clone()));
        Rig {
            ctx: Arc::new(ctx),
            kernel,
            hooks,
            clock,
            _dir: dir,
        }
    }

    #[tokio::test]
    async fn marker_recovery_retry_mountinfo_failure_hides_unauthorized_retained_handle() {
        let mounts = Arc::new(SwitchableMounts::new(
            concat!(
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
                "2 1 8:2 / /secret rw - ext4 /dev/sdb1 rw\n",
            )
            .to_owned(),
        ));
        let rig = rig_with_allowed_mounts(FreezeState::Frozen, mounts.clone(), Some(vec![]));
        rig.ctx.marker.create().unwrap();
        let secret = rig.kernel.open_mount(Path::new("/secret"), (8, 2)).unwrap();
        rig.kernel.fifreeze(&secret).unwrap();
        rig.kernel.script_thaw_error("/secret", Errno::EIO);

        // Attempt 1: /secret fails to thaw, so its handle is retained in `held`.
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let err1 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(err1.contains("0 target(s) thawed"), "{err1}");
        assert_eq!(rig.ctx.frozen_mount_count(), 1);
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 1);

        // Attempt 2: /proc/self/mountinfo fails (EMFILE) while the transient
        // FITHAW error clears. The retained /secret handle must still be
        // drained, released, AND excluded from the wire count (0, not 1).
        rig.kernel.clear_thaw_errors();
        mounts.fail_reads(true);
        let err2 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert!(
            err2.contains("0 target(s) thawed"),
            "unauthorized retained handle leaked in error count: {err2}"
        );
    }

    #[tokio::test]
    async fn marker_recovery_retry_unplanned_unauthorized_retained_handle_stays_hidden() {
        let mounts = Arc::new(SwitchableMounts::new(concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /secret rw - ext4 /dev/sdb1 rw\n",
        )));
        let rig = rig_with_allowed_mounts(FreezeState::Frozen, mounts.clone(), Some(vec![]));
        rig.ctx.marker.create().unwrap();
        let secret = rig.kernel.open_mount(Path::new("/secret"), (8, 2)).unwrap();
        rig.kernel.fifreeze(&secret).unwrap();
        rig.kernel.script_thaw_error("/secret", Errno::EIO);

        // Attempt 1 retains /secret because FITHAW failed transiently.
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let err1 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(err1.contains("0 target(s) thawed"), "{err1}");
        assert_eq!(rig.ctx.frozen_mount_count(), 1);

        // Attempt 2: /secret is no longer listed in mountinfo, so it reaches
        // the leftover-handle drain loop. It must still thaw and report 0.
        rig.kernel.clear_thaw_errors();
        mounts.set_table("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
        let reply = thaw(&rig.ctx, &req).await.unwrap();
        assert_eq!(reply, json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert!(!rig.ctx.marker.exists());
    }

    #[tokio::test]
    async fn marker_recovery_retry_formerly_countable_disappeared_handle_drains_and_reports_zero() {
        let mounts = Arc::new(SwitchableMounts::new(concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
        )));
        let rig = rig_with_allowed_mounts(FreezeState::Frozen, mounts.clone(), Some(vec!["/data"]));
        rig.ctx.marker.create().unwrap();
        let data = rig.kernel.open_mount(Path::new("/data"), (8, 2)).unwrap();
        rig.kernel.fifreeze(&data).unwrap();
        rig.kernel.script_thaw_error("/data", Errno::EIO);

        // Attempt 1: /data is currently authorized (countable = true) and fails
        // transiently, so its handle is retained with countable = true.
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let err1 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(err1.contains("0 target(s) thawed"), "{err1}");
        assert_eq!(rig.ctx.frozen_mount_count(), 1);

        // Attempt 2: /data disappears from mountinfo before rescan while the
        // transient EIO clears. Recovery must STILL drain and release the
        // descriptor, remove the marker, and report 0 because no configured
        // allowlist name covers 8:2 in the current table (#63).
        rig.kernel.clear_thaw_errors();
        mounts.set_table("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
        let reply = thaw(&rig.ctx, &req).await.unwrap();
        assert_eq!(reply, json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert!(!rig.ctx.marker.exists());
    }

    #[tokio::test]
    async fn clean_thawed_rescan_excludes_disappeared_retained_handle_from_count_and_error_detail()
    {
        let mounts = Arc::new(SwitchableMounts::new(concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
        )));
        let rig = rig_with_allowed_mounts(FreezeState::Thawed, mounts.clone(), Some(vec!["/data"]));
        let data = rig.kernel.open_mount(Path::new("/data"), (8, 2)).unwrap();
        rig.kernel.fifreeze(&data).unwrap();
        rig.kernel.script_thaw_error("/data", Errno::EIO);

        // Attempt 1 (clean Thawed, no marker): /data fails transiently so its
        // handle is retained in deferred recovery and state returns to Thawed.
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let err1 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(err1.contains("FITHAW failed"), "{err1}");
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);

        // /data disappears from mountinfo before the second clean Thawed rescan.
        mounts.set_table("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");

        // Attempt 2a (failure on disappeared retained handle): must collapse to
        // fixed RecoveryIncomplete rather than disclosing FITHAW permission denied.
        rig.kernel.clear_thaw_errors();
        rig.kernel.script_thaw_error("/data", Errno::EACCES);
        let err2 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert_eq!(
            err2,
            "thaw incomplete: recovery did not complete; filesystem may still be frozen (0 target(s) thawed); state thawed"
        );
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);

        // Attempt 2b (success on disappeared retained handle): still drains and
        // releases the descriptor, and reports 0 on the wire.
        rig.kernel.clear_thaw_errors();
        assert_eq!(thaw(&rig.ctx, &req).await.unwrap(), json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 0);
    }

    #[tokio::test]
    async fn live_thawed_escalation_enters_audit_ring_retains_on_failure_and_flushes_on_settlement()
    {
        use crate::audit::Mode;

        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /extra rw - ext4 /dev/sdc1 rw\n",
        );
        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let mut config = Config::default();
        config.agent.freeze_allowed_mountpoints = Some(vec!["/data".to_owned()]);
        let ctx = Arc::new(
            Context::new(
                Arc::new(config),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(StaticMounts(mounts.to_owned())))
            .with_hooks(Arc::new(LifecycleHooks)),
        );
        assert_eq!(ctx.audit.mode(), Mode::Normal);

        // 1. Clean Thawed drain (marker confirmed absent) keeps audit router in Normal mode.
        let clean_gate = kernel.script_thaw_gate("/data");
        let _clean_guard = clean_gate.release_on_drop();
        let ctx_c = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
            thaw(&ctx_c, &req).await
        });
        while clean_gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            ctx.audit.mode(),
            Mode::Normal,
            "clean Thawed drain without marker should stay in normal audit mode"
        );
        clean_gate.release();
        assert_eq!(task.await.unwrap().unwrap(), json!(0));
        assert_eq!(ctx.audit.mode(), Mode::Normal);

        // 2. Live Thawed service discovers a present marker -> escalates to full
        //    recovery, enters Ring mode BEFORE recovery ioctls, and RETAINS Ring
        //    mode when the drain fails and transitions to Frozen.
        ctx.marker.create().unwrap();
        let m3 = kernel.open_mount(Path::new("/extra"), (8, 3)).unwrap();
        kernel.fifreeze(&m3).unwrap();
        kernel.script_thaw_error("/extra", Errno::EIO);
        let esc_gate = kernel.script_thaw_gate("/extra");
        let _esc_guard = esc_gate.release_on_drop();
        let ctx_e = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
            thaw(&ctx_e, &req).await
        });
        while esc_gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            ctx.audit.mode(),
            Mode::Ring,
            "live Thawed escalation must enter freeze-safe audit ring before recovery work"
        );
        esc_gate.release();
        assert!(task.await.unwrap().is_err());
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(
            ctx.audit.mode(),
            Mode::Ring,
            "failed escalated drain into Frozen must retain ring mode"
        );

        // 3. Subsequent successful recovery settles Thawed and flushes back to Normal.
        kernel.clear_thaw_errors();
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&ctx, &req).await.unwrap(), json!(0));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!ctx.marker.exists());
        assert_eq!(
            ctx.audit.mode(),
            Mode::Normal,
            "successful settlement must flush audit router back to normal mode"
        );
    }

    #[tokio::test]
    async fn thawed_escalated_worker_loss_preserves_recovery_obligation_and_clean_worker_loss_stays_thawed()
     {
        use crate::audit::Mode;

        // 1. Live Thawed service discovers a present marker, then its blocking
        //    worker panics (PanickingMounts). Must fail closed: publish Frozen,
        //    retain Ring mode, arm the watchdog, and keep the marker.
        let dir1 = tempfile::tempdir().unwrap();
        let mut cfg1 = Config::default();
        cfg1.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx1 = Arc::new(
            Context::new(
                Arc::new(cfg1),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir1.path().join("frozen")).unwrap(),
            )
            .with_kernel(Arc::new(FakeKernel::new()))
            .with_mounts(Arc::new(PanickingMounts))
            .with_hooks(Arc::new(LifecycleHooks)),
        );
        ctx1.marker.create().unwrap();
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let err1 = thaw(&ctx1, &req).await.unwrap_err().to_string();
        assert!(
            err1.contains("state frozen, marker retained"),
            "escalated worker loss must report Frozen state: {err1}"
        );
        assert_eq!(
            ctx1.state.current(),
            FreezeState::Frozen,
            "escalated worker loss must fail closed to Frozen"
        );
        assert_eq!(
            ctx1.audit.mode(),
            Mode::Ring,
            "escalated worker loss into Frozen must retain freeze-safe audit ring"
        );
        assert!(
            ctx1.watchdog_slot().is_some(),
            "escalated worker loss into Frozen must arm the watchdog"
        );
        assert!(ctx1.marker.exists());
        if let Some(wd) = ctx1.watchdog_slot().take() {
            wd.cancel();
        }

        // 2. Live Thawed service confirms marker absence (ENOENT), then its
        //    blocking worker panics. With no marker obligation, state returns
        //    to Thawed in normal audit mode without arming the watchdog.
        let dir2 = tempfile::tempdir().unwrap();
        let mut cfg2 = Config::default();
        cfg2.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx2 = Arc::new(
            Context::new(
                Arc::new(cfg2),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir2.path().join("frozen")).unwrap(),
            )
            .with_kernel(Arc::new(FakeKernel::new()))
            .with_mounts(Arc::new(PanickingMounts))
            .with_hooks(Arc::new(LifecycleHooks)),
        );
        let err2 = thaw(&ctx2, &req).await.unwrap_err().to_string();
        assert!(
            err2.contains("state thawed"),
            "clean Thawed worker loss must report Thawed state: {err2}"
        );
        assert_eq!(ctx2.state.current(), FreezeState::Thawed);
        assert_eq!(ctx2.audit.mode(), Mode::Normal);
        assert!(ctx2.watchdog_slot().is_none());
    }

    #[test]
    fn thaw_state_record_failure_keeps_first_excluded_diagnostic_and_upgrades_on_authorized() {
        let mut state = ThawState::default();
        // Two consecutive excluded failures keep the first excluded target's diagnostic.
        state.record_failure(
            ThawFailure::Incomplete {
                mountpoint: "/secret1".into(),
                kind: RecoveryReason::RecoveryIncomplete,
                reason: "first excluded".into(),
                thawed: 0,
            },
            false,
        );
        state.record_failure(
            ThawFailure::Incomplete {
                mountpoint: "/secret2".into(),
                kind: RecoveryReason::RecoveryIncomplete,
                reason: "second excluded".into(),
                thawed: 0,
            },
            false,
        );
        assert!(
            matches!(
                &state.unrecoverable,
                Some(ThawFailure::Incomplete {
                    mountpoint,
                    kind: RecoveryReason::RecoveryIncomplete,
                    reason,
                    ..
                }) if mountpoint == "/secret1" && reason == "first excluded"
            ),
            "second excluded failure must not overwrite the first: {:?}",
            state.unrecoverable
        );
        let host_desc = state
            .unrecoverable
            .as_ref()
            .unwrap()
            .host_description(FreezeState::Frozen);
        assert_eq!(
            host_desc,
            "thaw incomplete: recovery did not complete; filesystem may still be frozen (0 target(s) thawed); state frozen, marker retained"
        );
        assert!(!host_desc.contains("/secret1") && !host_desc.contains("first excluded"));

        // An authorized target failure upgrades the excluded placeholder.
        state.record_failure(
            ThawFailure::Incomplete {
                mountpoint: "/data".into(),
                kind: RecoveryReason::PermissionDenied,
                reason: "authorized denied".into(),
                thawed: 0,
            },
            true,
        );
        assert!(
            matches!(
                &state.unrecoverable,
                Some(ThawFailure::Incomplete {
                    mountpoint,
                    kind: RecoveryReason::PermissionDenied,
                    ..
                }) if mountpoint == "/data"
            ),
            "authorized failure must upgrade excluded placeholder: {:?}",
            state.unrecoverable
        );

        // A later authorized failure keeps the first authorized failure.
        state.record_failure(
            ThawFailure::Incomplete {
                mountpoint: "/data2".into(),
                kind: RecoveryReason::IoctlFailed,
                reason: "later authorized".into(),
                thawed: 0,
            },
            true,
        );
        assert!(
            matches!(
                &state.unrecoverable,
                Some(ThawFailure::Incomplete {
                    mountpoint,
                    kind: RecoveryReason::PermissionDenied,
                    ..
                }) if mountpoint == "/data"
            ),
            "later authorized failure must not overwrite first authorized failure: {:?}",
            state.unrecoverable
        );
    }

    #[tokio::test]
    async fn rollback_preserves_excluded_held_handle_disclosure_policy_and_drains_it() {
        // Codex P1 (#63): an excluded (`countable = false`) retained handle
        // carried from an earlier Thawed rescan into a later freeze's rollback
        // must still be drained without contributing to rollback counts or
        // exposing its target-specific failure class.
        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
        );
        let rig = rig_with_allowed_mounts(
            FreezeState::Thawed,
            Arc::new(StaticMounts(mounts.to_owned())),
            Some(vec!["/data"]),
        );
        let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();

        // 1. Excluded handle drains cleanly during rollback of a failed freeze:
        //    it must be thawed & released, while wire rolled_back count is 0.
        let secret = rig.kernel.open_mount(Path::new("/secret"), (8, 9)).unwrap();
        rig.kernel.fifreeze(&secret).unwrap();
        rig.ctx.hold_frozen_mounts(vec![HeldMount {
            mount: secret,
            countable: false,
        }]);
        rig.kernel.script_freeze_error("/data", Errno::EIO);
        let err1 = freeze(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(
            err1.contains("rolled back (0 target(s) thawed)"),
            "excluded handle must not inflate rollback count: {err1}"
        );
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);

        // 2. Excluded handle fails with EPERM during rollback: wire error must
        //    collapse to RecoveryIncomplete, NOT expose FITHAW permission denied.
        let secret2 = rig.kernel.open_mount(Path::new("/secret"), (8, 9)).unwrap();
        rig.kernel.fifreeze(&secret2).unwrap();
        rig.kernel.script_thaw_error("/secret", Errno::EPERM);
        rig.ctx.hold_frozen_mounts(vec![HeldMount {
            mount: secret2,
            countable: false,
        }]);
        let err2 = freeze(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(
            err2.contains("recovery did not complete; filesystem may still be frozen"),
            "excluded rollback failure must use fixed RecoveryIncomplete reason: {err2}"
        );
        assert!(
            !err2.contains("FITHAW permission denied"),
            "excluded rollback failure leaked specific errno class: {err2}"
        );
        assert!(err2.contains("0 target(s) thawed"), "{err2}");

        // 3. Direct drain_held ordering cases (killing every countable-guard mutant):
        //    a) Two excluded failures keep the first excluded diagnostic (in drain/rev order).
        let k = FakeKernel::new();
        k.track_freeze_depth();
        let s1 = k.open_mount(Path::new("/secret1"), (8, 10)).unwrap();
        let s2 = k.open_mount(Path::new("/secret2"), (8, 11)).unwrap();
        let a1 = k.open_mount(Path::new("/data"), (8, 2)).unwrap();
        k.fifreeze(&s1).unwrap();
        k.fifreeze(&s2).unwrap();
        k.fifreeze(&a1).unwrap();
        k.script_thaw_error("/secret1", Errno::EPERM);
        k.script_thaw_error("/secret2", Errno::EIO);
        k.script_thaw_error("/data", Errno::EPERM);
        // drain_held iterates held.into_iter().rev(), so push second first.
        let DrainHeldResult {
            recovered: rec,
            keep,
            incomplete: inc,
            ..
        } = drain_held(
            &k,
            None,
            vec![
                HeldMount {
                    mount: s2,
                    countable: false,
                },
                HeldMount {
                    mount: s1,
                    countable: false,
                },
            ],
        );
        assert_eq!(rec, 0);
        assert_eq!(keep.len(), 2);
        let inc = inc.unwrap();
        assert_eq!(inc.kind, RecoveryReason::RecoveryIncomplete);
        assert_eq!(inc.mountpoint, "/secret1");

        //    b) Excluded failure followed by authorized failure upgrades to authorized class.
        let DrainHeldResult {
            incomplete: inc, ..
        } = drain_held(
            &k,
            None,
            vec![
                HeldMount {
                    mount: a1,
                    countable: true,
                },
                HeldMount {
                    mount: k.open_mount(Path::new("/secret1"), (8, 10)).unwrap(),
                    countable: false,
                },
            ],
        );
        let inc = inc.unwrap();
        assert_eq!(inc.kind, RecoveryReason::PermissionDenied);
        assert_eq!(inc.mountpoint, "/data");

        //    c) Authorized failure followed by excluded failure keeps authorized class.
        let DrainHeldResult {
            incomplete: inc, ..
        } = drain_held(
            &k,
            None,
            vec![
                HeldMount {
                    mount: k.open_mount(Path::new("/secret1"), (8, 10)).unwrap(),
                    countable: false,
                },
                HeldMount {
                    mount: k.open_mount(Path::new("/data"), (8, 2)).unwrap(),
                    countable: true,
                },
            ],
        );
        let inc = inc.unwrap();
        assert_eq!(inc.kind, RecoveryReason::PermissionDenied);
        assert_eq!(inc.mountpoint, "/data");
    }

    #[tokio::test]
    async fn later_freeze_after_clean_rescan_preserves_excluded_cleanup_without_disclosing_it() {
        let table = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /app rw - ext4 /dev/sdc1 rw\n",
        );
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // Helper: puts `rig` into `Thawed` with a deferred `countable == false`
        // recovery handle on `/data` (8:2) via the real clean-Thawed rescan path.
        let setup_carried_over = |thaw_err_on_data: Option<Errno>| async move {
            let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
            let mounts = Arc::new(SwitchableMounts::new(table));
            let rig = rig_with_allowed_mounts(
                FreezeState::Thawed,
                mounts.clone(),
                Some(vec!["/data", "/app"]),
            );
            let data = rig.kernel.open_mount(Path::new("/data"), (8, 2)).unwrap();
            rig.kernel.fifreeze(&data).unwrap();
            rig.kernel.script_thaw_error("/data", Errno::EIO);

            // Clean Thawed rescan retains /data in deferred_recovery_mounts while staying Thawed.
            let _ = thaw(&rig.ctx, &thaw_req).await.unwrap_err();
            assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
            assert_eq!(rig.ctx.frozen_mount_count(), 0);
            assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);

            // /data disappears from mountinfo; second clean rescan marks it
            // countable = false and stays Thawed with the handle still held.
            mounts.set_table(concat!(
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
                "3 1 8:3 / /app rw - ext4 /dev/sdc1 rw\n",
            ));
            rig.kernel.clear_thaw_errors();
            rig.kernel.script_thaw_error("/data", Errno::EACCES);
            let err = thaw(&rig.ctx, &thaw_req).await.unwrap_err().to_string();
            assert!(
                err.contains("recovery did not complete; filesystem may still be frozen"),
                "{err}"
            );
            assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
            assert_eq!(rig.ctx.frozen_mount_count(), 0);
            assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);

            rig.kernel.clear_thaw_errors();
            if let Some(errno) = thaw_err_on_data {
                rig.kernel.script_thaw_error("/data", errno);
            }
            (rig, mounts)
        };

        // 1. Zero-work later freeze (allowed `/app` returns EOPNOTSUPP so Driver
        //    commits with 0 frozen and 0 handles of its own): MUST settle `Thawed`
        //    with reply `0`, NEVER `Frozen`, while keeping the old `/data` cleanup
        //    obligation retained in deferred recovery for a later discovery drain.
        let (rig, _mounts) = setup_carried_over(None).await;
        rig.kernel.script_freeze_error("/app", Errno::EOPNOTSUPP);
        let zero_req = parse_request(
            br#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/app"]}}"#,
        )
        .unwrap();
        assert_eq!(freeze_list(&rig.ctx, &zero_req).await.unwrap(), json!(0));
        assert_eq!(
            rig.ctx.state.current(),
            FreezeState::Thawed,
            "zero-work freeze must not disclose deferred recovery handle via Frozen state"
        );
        assert!(!rig.ctx.marker.exists());
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert_eq!(
            rig.ctx.deferred_recovery_mount_count(),
            1,
            "deferred cleanup obligation must stay retained across zero-work freeze"
        );
        // Subsequent explicit thaw drains the deferred handle cleanly with count 0.
        assert_eq!(thaw(&rig.ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 0);

        // 2a. Later freeze that aborts while deferred `/data` is held (even when
        //     `/data` still fails EACCES): abort drains ONLY the current op's
        //     `/app`, reports recovered=1 and unrecoverable_reason=None, settles
        //     `Thawed`, and leaves `/data` recoverable on the next discovery thaw.
        let (rig, _mounts) = setup_carried_over(Some(Errno::EACCES)).await;
        let gate = rig.kernel.script_freeze_gate("/app");
        let _guard = gate.release_on_drop();
        let ctx_bg = Arc::clone(&rig.ctx);
        let freeze_task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        rig.clock.advance(Duration::from_secs(600));
        while rig
            .ctx
            .freeze_op()
            .is_some_and(|op| op.progress().phase == crate::freeze_op::Phase::Freezing)
        {
            tokio::task::yield_now().await;
        }
        let op = rig.ctx.freeze_op().expect("aborted op registered");
        gate.release();
        assert!(freeze_task.await.unwrap().is_err());
        while rig.ctx.freeze_op().is_some() {
            tokio::task::yield_now().await;
        }
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);
        assert_eq!(op.progress().recovered, 1);
        assert_eq!(op.progress().unrecoverable_reason, None);
        // Deferred `/data` remains recoverable by a discovery thaw once EACCES clears.
        rig.kernel.clear_thaw_errors();
        assert_eq!(thaw(&rig.ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 0);

        // 2b. Two-pass abort within one operation where pass 1 fails ONLY on an
        //     excluded handle (`countable == false`) held on `frozen_mounts`
        //     (RecoveryIncomplete) and pass 2 fails on authorized `/app` (EPERM):
        //     `Driver::record_recovery` upgrades unrecoverable_reason to PermissionDenied.
        let mounts = Arc::new(SwitchableMounts::new(concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "3 1 8:3 / /app rw - ext4 /dev/sdc1 rw\n",
        )));
        let rig = rig_with_allowed_mounts(FreezeState::Thawed, mounts, Some(vec!["/app"]));
        let secret = rig.kernel.open_mount(Path::new("/secret"), (8, 9)).unwrap();
        rig.kernel.fifreeze(&secret).unwrap();
        rig.kernel.script_thaw_error("/secret", Errno::EACCES);
        rig.kernel.script_thaw_error("/app", Errno::EPERM);
        rig.ctx.hold_frozen_mounts(vec![HeldMount {
            mount: secret,
            countable: false,
        }]);
        let gate = rig.kernel.script_freeze_gate("/app");
        let _guard = gate.release_on_drop();
        let ctx_bg = Arc::clone(&rig.ctx);
        let freeze_task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        rig.clock.advance(Duration::from_secs(600));
        while rig
            .ctx
            .freeze_op()
            .is_some_and(|op| op.progress().phase == crate::freeze_op::Phase::Freezing)
        {
            tokio::task::yield_now().await;
        }
        let op = rig.ctx.freeze_op().expect("aborted op registered");
        // Wait for pass 1 (excluded /secret -> RecoveryIncomplete) before releasing /app.
        while op.progress().unrecoverable_reason.is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            op.progress().unrecoverable_reason,
            Some(RecoveryReason::RecoveryIncomplete)
        );
        gate.release();
        assert!(freeze_task.await.unwrap().is_err());
        while rig.ctx.freeze_op().is_some() {
            tokio::task::yield_now().await;
        }
        assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
        assert_eq!(rig.ctx.frozen_mount_count(), 2);
        assert_eq!(
            op.progress().unrecoverable_reason,
            Some(RecoveryReason::PermissionDenied),
            "authorized pass-2 failure must upgrade generic pass-1 RecoveryIncomplete"
        );
    }

    #[tokio::test]
    async fn tracked_thaw_and_rollback_isolate_current_operation_from_earlier_thawed_recovery_handle()
     {
        let table = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /app rw - ext4 /dev/sdc1 rw\n",
        );
        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // Helper: fails a single clean-Thawed recovery scan on `/data` while
        // `/data` is STILL visible (retaining it with `countable: true`), then
        // removes `/data` from mountinfo WITHOUT running a second rescan.
        let setup_old_countable = |thaw_err_on_data: Option<Errno>| async move {
            let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
            let mounts = Arc::new(SwitchableMounts::new(table));
            let rig = rig_with_allowed_mounts(
                FreezeState::Thawed,
                mounts.clone(),
                Some(vec!["/data", "/app"]),
            );
            let data = rig.kernel.open_mount(Path::new("/data"), (8, 2)).unwrap();
            rig.kernel.fifreeze(&data).unwrap();
            rig.kernel.script_thaw_error("/data", Errno::EIO);

            let err = thaw(&rig.ctx, &thaw_req).await.unwrap_err().to_string();
            assert!(err.contains("FITHAW failed"), "{err}");
            assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
            assert_eq!(rig.ctx.frozen_mount_count(), 0);
            assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);

            // `/data` disappears from mountinfo before the next cycle begins.
            mounts.set_table(concat!(
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
                "3 1 8:3 / /app rw - ext4 /dev/sdc1 rw\n",
            ));
            rig.kernel.clear_thaw_errors();
            if let Some(errno) = thaw_err_on_data {
                rig.kernel.script_thaw_error("/data", errno);
            }
            (rig, mounts)
        };

        // 1. Successful freeze of `/app` (1) followed by tracked thaw when the
        //    older `/data` descriptor has cleared: tracked thaw MUST return `1`
        //    (NEVER `2`), leaving `/data` recoverable by a subsequent recovery
        //    thaw (which re-evaluates mountinfo and drains `/data` with count `0`).
        let (rig, _mounts) = setup_old_countable(None).await;
        assert_eq!(freeze(&rig.ctx, &freeze_req).await.unwrap(), json!(1));
        assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
        assert_eq!(rig.ctx.thaw_scope(), ThawScope::Tracked);
        assert_eq!(
            thaw(&rig.ctx, &thaw_req).await.unwrap(),
            json!(1),
            "tracked thaw count must reflect ONLY the current operation's /app descriptor"
        );
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);
        assert_eq!(
            rig.kernel.tracked_frozen_superblocks(),
            1,
            "older /data descriptor must remain untouched by tracked thaw of the new cycle"
        );
        // Recovery thaw from Thawed drains the older `/data` descriptor with count 0.
        assert_eq!(thaw(&rig.ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 0);

        // 2a. Successful freeze of `/app` followed by tracked thaw when the older
        //     `/data` descriptor fails with EACCES: tracked thaw succeeds with `1`
        //     (does NOT inherit `/data`'s PermissionDenied error class) and leaves
        //     `/data` recoverable by discovery thaw (which collapses to generic
        //     RecoveryIncomplete, then drains cleanly once EACCES clears).
        let (rig, _mounts) = setup_old_countable(Some(Errno::EACCES)).await;
        assert_eq!(freeze(&rig.ctx, &freeze_req).await.unwrap(), json!(1));
        assert_eq!(
            thaw(&rig.ctx, &thaw_req).await.unwrap(),
            json!(1),
            "tracked thaw must not fail with an unrelated older descriptor's error class"
        );
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        let err = thaw(&rig.ctx, &thaw_req).await.unwrap_err().to_string();
        assert_eq!(
            err,
            "thaw incomplete: recovery did not complete; filesystem may still be frozen (0 target(s) thawed); state thawed"
        );
        rig.kernel.clear_thaw_errors();
        assert_eq!(thaw(&rig.ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);

        // 2b. Tracked thaw when `/app` fails with EIO and older `/data` fails
        //     with EACCES: tracked thaw reports ONLY `/app`'s FITHAW failed class
        //     (never `/data`'s PermissionDenied), keeps `/app` in frozen_mounts
        //     and `/data` in deferred_recovery_mounts.
        let (rig, _mounts) = setup_old_countable(Some(Errno::EACCES)).await;
        assert_eq!(freeze(&rig.ctx, &freeze_req).await.unwrap(), json!(1));
        rig.kernel.script_thaw_error("/app", Errno::EIO);
        let err = thaw(&rig.ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("FITHAW failed"),
            "tracked thaw must report current op /app error class: {err}"
        );
        assert!(
            !err.contains("permission denied"),
            "tracked thaw must not leak older /data EACCES error class: {err}"
        );
        assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
        assert_eq!(rig.ctx.frozen_mount_count(), 1);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);
        // Once `/app` clears, tracked thaw finishes cleanly with 1, and `/data`
        // remains recoverable on the following discovery thaw.
        rig.kernel.clear_thaw_errors();
        assert_eq!(thaw(&rig.ctx, &thaw_req).await.unwrap(), json!(1));
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);
        assert_eq!(thaw(&rig.ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 0);

        // 3. Rollback of a later freeze failing on `/app` when older `/data`
        //    fails EACCES: rollback count, error class, and state depend ONLY
        //    on the new operation's descriptors, and older `/data` remains
        //    recoverable afterwards.
        let (rig, _mounts) = setup_old_countable(Some(Errno::EACCES)).await;
        rig.kernel.script_freeze_error("/app", Errno::EIO);
        let err = freeze(&rig.ctx, &freeze_req).await.unwrap_err().to_string();
        assert!(
            err.contains("rolled back (0 target(s) thawed); state thawed"),
            "rollback must not disclose or fail on unrelated older /data: {err}"
        );
        assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 1);
        rig.kernel.clear_thaw_errors();
        assert_eq!(thaw(&rig.ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.deferred_recovery_mount_count(), 0);
    }

    #[tokio::test]
    async fn restricted_recovery_unreadable_mountinfo_suppresses_previously_countable_count_and_error_class()
     {
        let mounts = Arc::new(SwitchableMounts::new(
            concat!(
                "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
                "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            )
            .to_owned(),
        ));
        let req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // Case A: previously countable descriptor (/data) fails with EACCES
        // while `/proc/self/mountinfo` is unreadable -> guest still attempts
        // FITHAW and keeps the handle, while wire collapses to fixed
        // RecoveryIncomplete with 0 thawed (never exposing PermissionDenied).
        let rig = rig_with_allowed_mounts(FreezeState::Frozen, mounts.clone(), Some(vec!["/data"]));
        rig.ctx.marker.create().unwrap();
        let data = rig.kernel.open_mount(Path::new("/data"), (8, 2)).unwrap();
        rig.kernel.fifreeze(&data).unwrap();
        rig.kernel.script_thaw_error("/data", Errno::EIO);

        // Pass 1: /data is visible and allowlisted -> retained with countable=true.
        let err1 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(err1.contains("FITHAW failed"), "{err1}");
        assert_eq!(rig.ctx.frozen_mount_count(), 1);

        // Pass 2: mountinfo unreadable (`EMFILE`) and /data now fails with EACCES.
        mounts.fail_reads(true);
        rig.kernel.clear_thaw_errors();
        rig.kernel.script_thaw_error("/data", Errno::EACCES);
        let err2 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert_eq!(
            err2,
            "thaw incomplete: recovery did not complete; filesystem may still be frozen (0 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(rig.ctx.frozen_mount_count(), 1);

        // Pass 3: mountinfo readable again while /data is still visible at `/data`
        // and still fails EACCES -> eligibility verified, specific class restored.
        mounts.fail_reads(false);
        let err3 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert!(err3.contains("FITHAW permission denied"), "{err3}");

        // Case B: previously countable descriptor (/data) drains cleanly while
        // `/proc/self/mountinfo` is unreadable -> guest recovery completes on
        // /data (handle released, superblock unfrozen), while wire reports 0
        // thawed because current eligibility could not be verified.
        mounts.fail_reads(true);
        rig.kernel.clear_thaw_errors();
        let err4 = thaw(&rig.ctx, &req).await.unwrap_err().to_string();
        assert_eq!(
            err4,
            "cannot build thaw plan (0 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(rig.kernel.tracked_frozen_superblocks(), 0);
        assert_eq!(rig.ctx.frozen_mount_count(), 0);
    }

    fn cooperative_rig(
        state: FreezeState,
        mountinfo: &str,
        ownership: Arc<dyn crate::ownership::OwnershipStore>,
        hooks: Arc<dyn FreezeHooks>,
    ) -> (
        Arc<Context>,
        Arc<FakeKernel>,
        ManualClock,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let clock = ManualClock::new();
        let ctx = Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(std::io::sink())),
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(mountinfo.to_owned())))
        .with_hooks(hooks)
        .with_freeze_clock(Arc::new(clock.clone()))
        .with_ownership(ownership);
        (Arc::new(ctx), kernel, clock, dir)
    }

    #[tokio::test]
    async fn cooperative_freeze_skips_foreign_claimed_and_unannounced_busy_while_preserving_self_busy()
     {
        use crate::ownership::{InMemoryOwnershipStore, QEMINGA_OWNER};

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /c rw - ext4 /dev/sdc1 rw\n",
            "4 1 8:4 / /d rw - ext4 /dev/sdd1 rw\n",
        );
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            store.clone(),
            Arc::new(NoHooks),
        );

        // /b (8:2): claimed and frozen by an independent guest integrity owner.
        assert!(store.claim_foreign((8, 2), "guest-integrity"));
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel.fifreeze(&mb).unwrap();

        // /c (8:3): frozen in kernel without a claim file (unannounced foreign freeze).
        let mc = kernel.open_mount(Path::new("/c"), (8, 3)).unwrap();
        kernel.fifreeze(&mc).unwrap();
        kernel.script_freeze_error("/c", Errno::EBUSY);

        // /d (8:4): already claimed by qeminga AND frozen in kernel.
        store.seed_self_claim((8, 4));
        let md = kernel.open_mount(Path::new("/d"), (8, 4)).unwrap();
        kernel.fifreeze(&md).unwrap();
        kernel.script_freeze_error("/d", Errno::EBUSY);
        kernel.clear_calls();

        // Freeze: only /a (8:1) is newly frozen; /b is never opened/frozen;
        // /c hits EBUSY on a fresh claim -> claim immediately released & not retained;
        // /d hits EBUSY on AlreadyOwnedBySelf -> retained for qeminga thaw.
        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        let reply = freeze(&ctx, &freeze_req).await.unwrap();
        assert_eq!(reply, json!(1));
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(store.owner_of((8, 1)).as_deref(), Some(QEMINGA_OWNER));
        assert_eq!(store.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(
            store.owner_of((8, 3)),
            None,
            "fresh claim on unannounced EBUSY must be released immediately"
        );
        assert_eq!(store.owner_of((8, 4)).as_deref(), Some(QEMINGA_OWNER));
        assert_eq!(
            ctx.frozen_mount_count(),
            2,
            "only /a and AlreadyOwnedBySelf /d should be retained"
        );
        assert!(
            !kernel.calls().iter().any(|c| matches!(
                c,
                Call::Open(p, _) | Call::Fifreeze(p) if p == Path::new("/b")
            )),
            "foreign-claimed /b must never be opened or frozen: {:?}",
            kernel.calls()
        );
        kernel.clear_calls();

        // Tracked thaw: drains ONLY /a and /d, releases their claims, and leaves
        // both /b (claimed) and /c (unannounced) frozen without issuing FITHAW.
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let thawed = thaw(&ctx, &thaw_req).await.unwrap();
        assert_eq!(thawed, json!(2));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!ctx.marker.exists());
        assert_eq!(store.owner_of((8, 1)), None);
        assert_eq!(store.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(store.owner_of((8, 3)), None);
        assert_eq!(store.owner_of((8, 4)), None);
        assert_eq!(
            kernel.tracked_frozen_superblocks(),
            2,
            "/b and /c must stay frozen"
        );
        assert!(
            !kernel.calls().iter().any(
                |c| matches!(c, Call::Fithaw(p) if p == Path::new("/b") || p == Path::new("/c"))
            ),
            "foreign /b and /c must never receive FITHAW: {:?}",
            kernel.calls()
        );
    }

    #[tokio::test]
    async fn cooperative_freeze_releases_fresh_claims_on_eopnotsupp_rollback_and_deadline_abort() {
        use crate::ownership::{InMemoryOwnershipStore, QEMINGA_OWNER};

        // Reverse mount order freezes /c (8:3), /b (8:2), /a (8:1).
        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /c rw - ext4 /dev/sdc1 rw\n",
        );

        // 1. EOPNOTSUPP on /c releases fresh claim; /b is foreign-owned (untouched);
        //    /a freezes; thaw drains /a only.
        let store1 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx1, kernel1, _clock1, _dir1) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            store1.clone(),
            Arc::new(NoHooks),
        );
        store1.claim_foreign((8, 2), "guest-integrity");
        let mb = kernel1.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel1.fifreeze(&mb).unwrap();
        kernel1.script_freeze_error("/c", Errno::EOPNOTSUPP);
        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        assert_eq!(freeze(&ctx1, &freeze_req).await.unwrap(), json!(1));
        assert_eq!(store1.owner_of((8, 3)), None);
        assert_eq!(store1.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(store1.owner_of((8, 1)).as_deref(), Some(QEMINGA_OWNER));
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&ctx1, &thaw_req).await.unwrap(), json!(1));
        assert_eq!(store1.owner_of((8, 1)), None);
        assert_eq!(kernel1.tracked_frozen_superblocks(), 1);

        // 2. Hard EIO on /a rolls back /c (releasing (8,3)), releases fresh (8,1),
        //    and leaves foreign /b frozen and claimed.
        let store2 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx2, kernel2, _clock2, _dir2) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            store2.clone(),
            Arc::new(NoHooks),
        );
        store2.claim_foreign((8, 2), "guest-integrity");
        let mb2 = kernel2.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel2.fifreeze(&mb2).unwrap();
        kernel2.script_freeze_error("/a", Errno::EIO);
        assert!(freeze(&ctx2, &freeze_req).await.is_err());
        assert_eq!(ctx2.state.current(), FreezeState::Thawed);
        assert!(!ctx2.marker.exists());
        assert_eq!(store2.owner_of((8, 1)), None);
        assert_eq!(store2.owner_of((8, 3)), None);
        assert_eq!(store2.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(kernel2.tracked_frozen_superblocks(), 1);

        // 3. Pre-existing AlreadyOwnedBySelf claim on /a is NOT removed on EIO.
        let store3 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx3, kernel3, _clock3, _dir3) = cooperative_rig(
            FreezeState::Thawed,
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            store3.clone(),
            Arc::new(NoHooks),
        );
        store3.seed_self_claim((8, 1));
        kernel3.script_freeze_error("/a", Errno::EIO);
        assert!(freeze(&ctx3, &freeze_req).await.is_err());
        assert_eq!(
            store3.owner_of((8, 1)).as_deref(),
            Some(QEMINGA_OWNER),
            "pre-existing self claim must be preserved on freeze error"
        );

        // 4. Deadline expiring while open_mount is in flight releases fresh claim
        //    on NotAuthorized and issues zero FIFREEZE; an in-flight FIFREEZE
        //    that completes late is drained and its claim is released on recovery.
        #[derive(Debug)]
        struct GatedOpenKernel {
            inner: Arc<FakeKernel>,
            gate: Gate,
        }
        impl KernelOps for GatedOpenKernel {
            fn open_mount(&self, mountpoint: &Path, dev: (u32, u32)) -> Result<Mount, KernelError> {
                self.gate.wait();
                self.inner.open_mount(mountpoint, dev)
            }
            fn fifreeze(&self, mount: &Mount) -> Result<(), KernelError> {
                self.inner.fifreeze(mount)
            }
            fn fithaw(&self, mount: &Mount) -> Result<(), KernelError> {
                self.inner.fithaw(mount)
            }
            fn fitrim(
                &self,
                mount: &Mount,
                minimum: u64,
            ) -> Result<crate::kernel::Trimmed, KernelError> {
                self.inner.fitrim(mount, minimum)
            }
            fn sync(&self) {
                self.inner.sync();
            }
            fn reboot(&self, cmd: crate::kernel::RebootCommand) -> Result<(), KernelError> {
                self.inner.reboot(cmd)
            }
        }
        let store4 = Arc::new(InMemoryOwnershipStore::new());
        let inner4 = Arc::new(FakeKernel::new());
        inner4.track_freeze_depth();
        let open_gate = Gate::new();
        let _guard = open_gate.release_on_drop();
        let clock4 = ManualClock::new();
        let dir4 = tempfile::tempdir().unwrap();
        let ctx4 = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir4.path().join("frozen")).unwrap(),
            )
            .with_kernel(Arc::new(GatedOpenKernel {
                inner: inner4.clone(),
                gate: open_gate.clone(),
            }))
            .with_mounts(Arc::new(StaticMounts(
                "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n".to_owned(),
            )))
            .with_hooks(Arc::new(NoHooks))
            .with_freeze_clock(Arc::new(clock4.clone()))
            .with_ownership(store4.clone()),
        );
        let ctx4_bg = Arc::clone(&ctx4);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx4_bg, &req).await
        });
        while open_gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(store4.owner_of((8, 1)).as_deref(), Some(QEMINGA_OWNER));
        clock4.advance(Duration::from_secs(600));
        while ctx4
            .freeze_op()
            .is_some_and(|op| op.progress().phase == crate::freeze_op::Phase::Freezing)
        {
            tokio::task::yield_now().await;
        }
        open_gate.release();
        assert!(task.await.unwrap().is_err());
        while ctx4.state.current() != FreezeState::Thawed {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            store4.owner_of((8, 1)),
            None,
            "fresh claim must be released on NotAuthorized abort"
        );
        assert_eq!(inner4.tracked_frozen_superblocks(), 0);
    }

    #[tokio::test]
    async fn cooperative_thaw_from_thawed_preserves_foreign_freezes_with_zero_fithaw() {
        use crate::ownership::InMemoryOwnershipStore;

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
        );
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            store.clone(),
            Arc::new(NoHooks),
        );

        store.claim_foreign((8, 1), "guest-integrity");
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        kernel.fifreeze(&mb).unwrap();
        kernel.clear_calls();

        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let reply = thaw(&ctx, &thaw_req).await.unwrap();
        assert_eq!(reply, json!(0));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(
            kernel.calls().is_empty(),
            "idle thaw with zero self claims must issue zero kernel calls: {:?}",
            kernel.calls()
        );
        assert_eq!(kernel.tracked_frozen_superblocks(), 2);
        assert_eq!(store.owner_of((8, 1)).as_deref(), Some("guest-integrity"));
    }

    #[tokio::test(start_paused = true)]
    async fn cooperative_watchdog_and_restart_marker_recovery_drain_only_self_owned_targets() {
        use crate::ownership::InMemoryOwnershipStore;

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /c rw - ext4 /dev/sdc1 rw\n",
        );

        // 1. Automatic idle watchdog thaw: drains /a, keeps foreign /b frozen.
        let store1 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx1, kernel1, _clock1, _dir1) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            store1.clone(),
            Arc::new(LifecycleHooks),
        );
        store1.claim_foreign((8, 2), "guest-integrity");
        let mb = kernel1.open_mount(Path::new("/b"), (8, 2)).unwrap();
        let mc = kernel1.open_mount(Path::new("/c"), (8, 3)).unwrap();
        kernel1.fifreeze(&mb).unwrap();
        kernel1.fifreeze(&mc).unwrap();
        kernel1.script_freeze_error("/c", Errno::EBUSY);
        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        assert_eq!(freeze(&ctx1, &freeze_req).await.unwrap(), json!(1));
        assert_eq!(ctx1.state.current(), FreezeState::Frozen);
        kernel1.clear_calls();

        tokio::time::advance(Duration::from_secs(
            ctx1.config.agent.fsfreeze_idle_timeout_secs + 1,
        ))
        .await;
        wait_until_thawed(&ctx1).await;
        assert_eq!(ctx1.state.current(), FreezeState::Thawed);
        assert!(!ctx1.marker.exists());
        assert_eq!(store1.owner_of((8, 1)), None);
        assert_eq!(store1.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(kernel1.tracked_frozen_superblocks(), 2);
        assert!(
            !kernel1.calls().iter().any(
                |c| matches!(c, Call::Fithaw(p) if p == Path::new("/b") || p == Path::new("/c"))
            ),
            "watchdog thaw must never touch foreign /b or /c: {:?}",
            kernel1.calls()
        );

        // 2. Simulated restart with /run/qeminga/frozen present (Frozen + Discovery):
        //    (8,1) owned by qeminga, (8,2) owned by guest-integrity, (8,3) unclaimed.
        let store2 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx2, kernel2, _clock2, _dir2) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            store2.clone(),
            Arc::new(NoHooks),
        );
        ctx2.marker.create().unwrap();
        store2.seed_self_claim((8, 1));
        store2.claim_foreign((8, 2), "guest-integrity");
        let ma2 = kernel2.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb2 = kernel2.open_mount(Path::new("/b"), (8, 2)).unwrap();
        let mc2 = kernel2.open_mount(Path::new("/c"), (8, 3)).unwrap();
        kernel2.fifreeze(&ma2).unwrap();
        kernel2.fifreeze(&mb2).unwrap();
        kernel2.fifreeze(&mc2).unwrap();
        kernel2.clear_calls();

        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        assert_eq!(thaw(&ctx2, &thaw_req).await.unwrap(), json!(1));
        assert_eq!(ctx2.state.current(), FreezeState::Thawed);
        assert!(!ctx2.marker.exists());
        assert_eq!(store2.owner_of((8, 1)), None);
        assert_eq!(store2.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(kernel2.tracked_frozen_superblocks(), 2);
        assert!(
            !kernel2.calls().iter().any(
                |c| matches!(c, Call::Fithaw(p) if p == Path::new("/b") || p == Path::new("/c"))
            ),
            "restart recovery must never touch foreign /b or unclaimed /c: {:?}",
            kernel2.calls()
        );
    }

    #[tokio::test]
    async fn cooperative_ambiguous_and_failing_ownership_fails_closed_while_draining_reachable_self_targets()
     {
        use crate::audit::Mode;
        use crate::ownership::{InMemoryOwnershipStore, QEMINGA_OWNER};

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
        );
        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // 1. Freeze encountering Ambiguous claim on /a rolls back /b (releasing (8,2)),
        //    retains recovery state (Frozen + Discovery + marker + watchdog armed),
        //    and returns fixed host-safe reason without leaking paths/devices/details.
        let store1 = Arc::new(InMemoryOwnershipStore::new());
        let hooks1 = Arc::new(Recorder::default());
        let (ctx1, kernel1, _clock1, _dir1) =
            cooperative_rig(FreezeState::Thawed, mounts, store1.clone(), hooks1.clone());
        store1.inject_ambiguous_entry((8, 1), "spoofed-uid-secret-detail");
        let err1 = freeze(&ctx1, &freeze_req).await.unwrap_err().to_string();
        assert!(
            err1.contains("freeze ownership is ambiguous; cannot claim target"),
            "{err1}"
        );
        assert!(
            err1.contains("freeze ownership is ambiguous; cannot confirm complete recovery"),
            "{err1}"
        );
        assert!(err1.contains("1 target(s) thawed"), "{err1}");
        assert!(err1.contains("state frozen, marker retained"), "{err1}");
        assert!(!err1.contains("spoofed-uid-secret-detail"), "{err1}");
        assert!(!err1.contains("/a"), "{err1}");
        assert!(!err1.contains("8:1"), "{err1}");
        assert_eq!(ctx1.state.current(), FreezeState::Frozen);
        assert_eq!(ctx1.thaw_scope(), ThawScope::Discovery);
        assert!(ctx1.marker.exists());
        assert_eq!(hooks1.events().last().copied(), Some("frozen"));
        assert_eq!(store1.owner_of((8, 2)), None);
        assert_eq!(kernel1.tracked_frozen_superblocks(), 0);
        // Once the ambiguous entry is removed, discovery thaw clears recovery cleanly.
        assert!(store1.release((8, 1)).is_err());
        let err1_retry = thaw(&ctx1, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err1_retry.contains("freeze ownership is ambiguous"),
            "{err1_retry}"
        );
        assert_eq!(ctx1.state.current(), FreezeState::Frozen);
        assert!(ctx1.marker.exists());

        // 2. Restart recovery with ambiguous entry STILL drains reachable qeminga /a,
        //    never touches foreign /b, retains marker and Frozen state.
        let store2 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx2, kernel2, _clock2, _dir2) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            store2.clone(),
            Arc::new(NoHooks),
        );
        ctx2.marker.create().unwrap();
        store2.seed_self_claim((8, 1));
        store2.claim_foreign((8, 2), "guest-integrity");
        store2.inject_stray_ambiguous("corrupt-entry-secret");
        let ma2 = kernel2.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb2 = kernel2.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel2.fifreeze(&ma2).unwrap();
        kernel2.fifreeze(&mb2).unwrap();
        kernel2.clear_calls();

        let err2 = thaw(&ctx2, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err2.contains("freeze ownership is ambiguous; cannot confirm complete recovery"),
            "{err2}"
        );
        assert!(err2.contains("1 target(s) thawed"), "{err2}");
        assert!(!err2.contains("corrupt-entry-secret"), "{err2}");
        assert!(!err2.contains("guest-integrity"), "{err2}");
        assert_eq!(ctx2.state.current(), FreezeState::Frozen);
        assert!(ctx2.marker.exists());
        assert_eq!(store2.owner_of((8, 1)), None);
        assert_eq!(store2.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(kernel2.tracked_frozen_superblocks(), 1);

        // 3. Restart recovery with unreadable ownership store (inspect_all Err) fails
        //    closed without touching foreign /b.
        let store3 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx3, kernel3, _clock3, _dir3) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            store3.clone(),
            Arc::new(NoHooks),
        );
        ctx3.marker.create().unwrap();
        store3.claim_foreign((8, 2), "guest-integrity");
        let mb3 = kernel3.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel3.fifreeze(&mb3).unwrap();
        kernel3.clear_calls();
        store3.script_inspect_error(Some(Errno::EIO));
        let err3 = thaw(&ctx3, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err3.contains("cannot update freeze ownership state"),
            "{err3}"
        );
        assert_eq!(ctx3.state.current(), FreezeState::Frozen);
        assert!(ctx3.marker.exists());
        assert!(kernel3.calls().is_empty());

        // 4. Restart recovery with an OwnedBySelf claim missing from mountinfo
        //    retains the missing claim and marker.
        let store4 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx4, _kernel4, _clock4, _dir4) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            store4.clone(),
            Arc::new(NoHooks),
        );
        ctx4.marker.create().unwrap();
        store4.seed_self_claim((8, 99));
        let err4 = thaw(&ctx4, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err4.contains("target unreachable; no FITHAW issued"),
            "{err4}"
        );
        assert!(!err4.contains("8:99"), "{err4}");
        assert_eq!(ctx4.state.current(), FreezeState::Frozen);
        assert!(ctx4.marker.exists());
        assert_eq!(store4.owner_of((8, 99)).as_deref(), Some(QEMINGA_OWNER));

        // 5. Claim release failure on thaw fails closed and switches to Discovery so
        //    retry succeeds via inspect_all once the transient error clears.
        let store5 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx5, kernel5, _clock5, _dir5) = cooperative_rig(
            FreezeState::Thawed,
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            store5.clone(),
            Arc::new(NoHooks),
        );
        assert_eq!(freeze(&ctx5, &freeze_req).await.unwrap(), json!(1));
        store5.script_release_error(Some(Errno::EIO));
        let err5 = thaw(&ctx5, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err5.contains("cannot update freeze ownership state"),
            "{err5}"
        );
        assert_eq!(ctx5.state.current(), FreezeState::Frozen);
        assert!(ctx5.marker.exists());
        assert_eq!(ctx5.thaw_scope(), ThawScope::Discovery);
        assert_eq!(kernel5.tracked_frozen_superblocks(), 0);
        // Clear release error and retry: discovery sees (8,1) claim, releases it, settles Thawed.
        store5.script_release_error(None);
        assert_eq!(thaw(&ctx5, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(ctx5.state.current(), FreezeState::Thawed);
        assert!(!ctx5.marker.exists());
        assert_eq!(store5.owner_of((8, 1)), None);

        // 6. Claim release failure on freshly acquired claim during freeze (unannounced EBUSY)
        //    retains Frozen state and marker instead of settling Thawed with a stray claim.
        let store6 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx6, kernel6, _clock6, _dir6) = cooperative_rig(
            FreezeState::Thawed,
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            store6.clone(),
            Arc::new(NoHooks),
        );
        let ma6 = kernel6.open_mount(Path::new("/a"), (8, 1)).unwrap();
        kernel6.fifreeze(&ma6).unwrap();
        kernel6.script_freeze_error("/a", Errno::EBUSY);
        store6.script_release_error(Some(Errno::EIO));
        let err6 = freeze(&ctx6, &freeze_req).await.unwrap_err().to_string();
        assert!(
            err6.contains("cannot update freeze ownership state"),
            "{err6}"
        );
        assert_eq!(ctx6.state.current(), FreezeState::Frozen);
        assert!(ctx6.marker.exists());
        assert_eq!(ctx6.thaw_scope(), ThawScope::Discovery);

        // 7. Live Thawed thaw encountering an ambiguous entry escalates to Frozen,
        //    enters audit Ring mode, and arms the watchdog.
        let store7 = Arc::new(InMemoryOwnershipStore::new());
        let (ctx7, _kernel7, _clock7, _dir7) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            store7.clone(),
            Arc::new(LifecycleHooks),
        );
        store7.inject_stray_ambiguous("unexpected-entry");
        let err7 = thaw(&ctx7, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err7.contains("freeze ownership is ambiguous; cannot confirm complete recovery"),
            "{err7}"
        );
        assert_eq!(ctx7.state.current(), FreezeState::Frozen);
        assert_eq!(ctx7.audit.mode(), Mode::Ring);
        assert!(ctx7.watchdog_slot().is_some());
        if let Some(wd) = ctx7.watchdog_slot().take() {
            wd.cancel();
        }
    }

    #[tokio::test]
    async fn cooperative_edge_cases_cover_release_errors_unreachable_and_aborted_recovery() {
        use crate::ownership::{InMemoryOwnershipStore, OwnershipError, OwnershipStore};

        // 1. All four OwnershipError variants map to the expected RecoveryReason.
        assert_eq!(
            recovery_reason_for_ownership_error(&OwnershipError::OpenDir {
                path: PathBuf::from("/run/x"),
                errno: Errno::EACCES,
            }),
            RecoveryReason::OwnershipError
        );
        assert_eq!(
            recovery_reason_for_ownership_error(&OwnershipError::Io {
                dev: Some((8, 1)),
                op: "unlink",
                errno: Errno::EIO,
            }),
            RecoveryReason::OwnershipError
        );
        assert_eq!(
            recovery_reason_for_ownership_error(&OwnershipError::TooManyEntries { limit: 4096 }),
            RecoveryReason::OwnershipAmbiguous
        );
        assert_eq!(
            recovery_reason_for_ownership_error(&OwnershipError::NotOwnedBySelf { dev: (8, 1) }),
            RecoveryReason::OwnershipAmbiguous
        );

        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let mounts2 = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
        );

        // 2. try_claim Io error retains Frozen + Discovery + marker + watchdog
        //    and returns fixed host-safe FreezeStop::OwnershipError.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let hooks = Arc::new(Recorder::default());
        let (ctx, _kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            store.clone(),
            hooks.clone(),
        );
        store.script_claim_error(Some(Errno::EIO));
        let err = freeze(&ctx, &freeze_req).await.unwrap_err().to_string();
        assert!(
            err.contains("cannot update freeze ownership state"),
            "{err}"
        );
        assert!(err.contains("state frozen, marker retained"), "{err}");
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert!(ctx.marker.exists());
        assert_eq!(hooks.events().last().copied(), Some("frozen"));
        // Once the transient ownership I/O error clears, discovery thaw settles Thawed.
        store.script_claim_error(None);
        assert_eq!(thaw(&ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!ctx.marker.exists());

        // 3. open_target failure after fresh claim releases the claim cleanly.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            store.clone(),
            Arc::new(NoHooks),
        );
        kernel.script_open_error("/a", Errno::ENOENT);
        assert!(freeze(&ctx, &freeze_req).await.is_err());
        assert_eq!(store.owner_of((8, 1)), None);
        assert_eq!(ctx.state.current(), FreezeState::Thawed);

        // 4. Rollback via drain_held failing store.release retains Frozen + Discovery.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        // Freeze order: /b (8:2) succeeds, then /a (8:1) fails with EIO ->
        // rollback drains /b cleanly, then release((8,2)) fails with EIO.
        // Note: /a fresh claim also fails release, so fail /b release only by
        // gating /a's freeze error AFTER scripting release error on rollback?
        // Instead: pre-seed /a as AlreadyOwnedBySelf so /a does NOT call release
        // on EIO, and only drain_held on /b calls store.release((8,2))!
        store.seed_self_claim((8, 1));
        kernel.script_freeze_error("/a", Errno::EIO);
        store.script_release_error(Some(Errno::EIO));
        let err = freeze(&ctx, &freeze_req).await.unwrap_err().to_string();
        assert!(
            err.contains("cannot update freeze ownership state"),
            "{err}"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert_eq!(kernel.tracked_frozen_superblocks(), 0);

        // 5a. Aborted freeze mid-FIFREEZE: late Frozen(mount) drained and claim released.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            store.clone(),
            Arc::new(NoHooks),
        );
        let gate = kernel.script_freeze_gate("/a");
        let _guard = gate.release_on_drop();
        let ctx_bg = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        clock.advance(Duration::from_secs(600));
        while ctx
            .freeze_op()
            .is_some_and(|op| op.progress().phase == crate::freeze_op::Phase::Freezing)
        {
            tokio::task::yield_now().await;
        }
        gate.release();
        assert!(task.await.unwrap().is_err());
        while ctx.state.current() != FreezeState::Thawed {
            tokio::task::yield_now().await;
        }
        assert_eq!(store.owner_of((8, 1)), None);
        assert_eq!(kernel.tracked_frozen_superblocks(), 0);

        // 5b. Same aborted recovery when drain_held's release fails -> settles Frozen + Discovery.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            store.clone(),
            Arc::new(NoHooks),
        );
        let gate = kernel.script_freeze_gate("/a");
        let _guard = gate.release_on_drop();
        let ctx_bg = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        store.script_release_error(Some(Errno::EIO));
        clock.advance(Duration::from_secs(600));
        while ctx
            .freeze_op()
            .is_some_and(|op| op.progress().phase == crate::freeze_op::Phase::Freezing)
        {
            tokio::task::yield_now().await;
        }
        gate.release();
        assert!(task.await.unwrap().is_err());
        while ctx.freeze_op().is_some() {
            tokio::task::yield_now().await;
        }
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert!(ctx.marker.exists());

        // 6. Cooperative discovery: open_target EACCES on OwnedBySelf /a fails closed.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        store.seed_self_claim((8, 1));
        kernel.script_open_error("/a", Errno::EACCES);
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("target open permission denied; no FITHAW issued"),
            "{err}"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());

        // 7. Cooperative discovery with inspect_all error STILL drains in-process held handles.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        store.seed_self_claim((8, 1));
        store.claim_foreign((8, 2), "guest-integrity");
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        kernel.fifreeze(&mb).unwrap();
        ctx.hold_frozen_mounts(vec![HeldMount {
            mount: ma,
            countable: true,
        }]);
        store.script_inspect_error(Some(Errno::EIO));
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(err.contains("1 target(s) thawed"), "{err}");
        assert!(
            err.contains("cannot update freeze ownership state"),
            "{err}"
        );
        assert_eq!(store.owner_of((8, 1)), None);
        assert_eq!(store.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);

        // 8. Cooperative discovery with mountinfo error STILL drains held self-owned handles.
        struct FailingMounts;
        impl MountSource for FailingMounts {
            fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
                Err(Error::Internal("EMFILE".into()))
            }
        }
        let store = Arc::new(InMemoryOwnershipStore::new());
        let dir = tempfile::tempdir().unwrap();
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Frozen)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(FailingMounts))
            .with_ownership(store.clone()),
        );
        ctx.marker.create().unwrap();
        store.seed_self_claim((8, 1));
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        ctx.hold_frozen_mounts(vec![HeldMount {
            mount: ma,
            countable: true,
        }]);
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("cannot build thaw plan (1 target(s) thawed)"),
            "{err}"
        );
        assert_eq!(store.owner_of((8, 1)), None);
        assert_eq!(kernel.tracked_frozen_superblocks(), 0);

        // 9. Retained handle whose ownership was replaced by a foreign owner before
        //    discovery retry refuses FITHAW and reports OwnershipAmbiguous.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        store.seed_self_claim((8, 1));
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        ctx.hold_frozen_mounts(vec![HeldMount {
            mount: ma,
            countable: true,
        }]);
        // Simulate external handoff of (8, 1) to foreign owner before retry.
        store.release((8, 1)).unwrap();
        store.claim_foreign((8, 1), "guest-integrity");
        kernel.clear_calls();
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("freeze ownership is ambiguous; cannot confirm complete recovery"),
            "{err}"
        );
        assert!(
            kernel.calls().is_empty(),
            "must refuse FITHAW when retained handle is now foreign-owned: {:?}",
            kernel.calls()
        );
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);
        assert_eq!(store.owner_of((8, 1)).as_deref(), Some("guest-integrity"));
    }

    #[tokio::test]
    async fn cooperative_pre_thaw_ownership_check_protects_foreign_and_retains_uncertain_handles() {
        use crate::ownership::InMemoryOwnershipStore;
        let mounts2 = "27 1 8:1 / /a rw - ext4 /dev/sda1 rw\n\
                       28 27 8:2 / /b rw - ext4 /dev/sdb1 rw\n";
        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // 1. Tracked thaw after foreign handoff: refuse FITHAW, keep foreign
        //    freeze intact, retain marker + Frozen, switch to Discovery.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        assert_eq!(freeze(&ctx, &freeze_req).await.unwrap(), json!(2));
        assert_eq!(ctx.thaw_scope(), ThawScope::Tracked);
        // External handoff of (8, 1) to guest-integrity while (8, 2) remains qeminga.
        store.release((8, 1)).unwrap();
        store.claim_foreign((8, 1), "guest-integrity");
        kernel.clear_calls();
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("freeze ownership is ambiguous; cannot confirm complete recovery"),
            "{err}"
        );
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/a"))),
            "tracked thaw must NEVER issue FITHAW on foreign-owned /a: {:?}",
            kernel.calls()
        );
        assert!(
            kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/b"))),
            "still-owned /b must still be drained: {:?}",
            kernel.calls()
        );
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);
        assert_eq!(store.owner_of((8, 1)).as_deref(), Some("guest-integrity"));
        assert_eq!(store.owner_of((8, 2)), None);
        assert_eq!(ctx.frozen_mount_count(), 0);
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert!(ctx.marker.exists());

        // 2. Unavailable directory scan (`inspect_all` EIO) after foreign handoff:
        //    must verify per-target ownership before FITHAW, leaving foreign /a frozen
        //    while still draining verified self-owned /b.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        store.claim_foreign((8, 1), "guest-integrity");
        store.seed_self_claim((8, 2));
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        kernel.fifreeze(&mb).unwrap();
        ctx.hold_frozen_mounts(vec![
            HeldMount {
                mount: mb,
                countable: true,
            },
            HeldMount {
                mount: ma,
                countable: true,
            },
        ]);
        store.script_inspect_error(Some(Errno::EIO));
        kernel.clear_calls();
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("1 target(s) thawed"),
            "self-owned /b should drain cleanly: {err}"
        );
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/a"))),
            "unavailable directory scan must NEVER issue FITHAW on foreign-owned /a: {:?}",
            kernel.calls()
        );
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);
        assert_eq!(store.owner_of((8, 1)).as_deref(), Some("guest-integrity"));
        assert_eq!(store.owner_of((8, 2)), None);
        assert_eq!(ctx.frozen_mount_count(), 0);
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());

        // 3. Rollback after foreign handoff: /b is frozen, then /a blocks at its
        //    gate while /b's claim is handed off to guest-integrity before /a
        //    fails with EIO -> rollback must NOT issue FITHAW on /b, leaving
        //    foreign freeze intact and settling Frozen + Discovery.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        let gate = kernel.script_freeze_gate("/a");
        let _guard = gate.release_on_drop();
        kernel.script_freeze_error("/a", Errno::EIO);
        let ctx_bg = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        // /b is frozen and held; hand (8, 2) off to foreign owner before /a errors.
        store.release((8, 2)).unwrap();
        store.claim_foreign((8, 2), "guest-integrity");
        gate.release();
        let err = task.await.unwrap().unwrap_err().to_string();
        assert!(
            err.contains("freeze ownership is ambiguous"),
            "rollback must report ownership ambiguity: {err}"
        );
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/b"))),
            "rollback must NEVER issue FITHAW on handed-off /b: {:?}",
            kernel.calls()
        );
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);
        assert_eq!(store.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(ctx.frozen_mount_count(), 0);
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert!(ctx.marker.exists());

        // 4. Abort recovery after foreign handoff: /b is frozen, /a blocks at its
        //    gate while /b's claim is handed off and timeout aborts -> abort drain
        //    must NOT FITHAW /b and must settle Frozen + Discovery with foreign
        //    freeze intact.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        let gate = kernel.script_freeze_gate("/a");
        let _guard = gate.release_on_drop();
        let ctx_bg = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        // Hand (8, 2) off to foreign owner before abort fires.
        store.release((8, 2)).unwrap();
        store.claim_foreign((8, 2), "guest-integrity");
        clock.advance(Duration::from_secs(600));
        while ctx
            .freeze_op()
            .is_some_and(|op| op.progress().phase == crate::freeze_op::Phase::Freezing)
        {
            tokio::task::yield_now().await;
        }
        gate.release();
        assert!(task.await.unwrap().is_err());
        while ctx.freeze_op().is_some() {
            tokio::task::yield_now().await;
        }
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/b"))),
            "abort recovery must NEVER issue FITHAW on handed-off /b: {:?}",
            kernel.calls()
        );
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);
        assert_eq!(store.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(ctx.frozen_mount_count(), 0);
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert!(ctx.marker.exists());

        // 5. Uncertain per-target ownership (inspect Err and Ambiguous) keeps the
        //    retained handle for retry without issuing FITHAW, then drains cleanly
        //    once ownership becomes verifiable again.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        assert_eq!(freeze(&ctx, &freeze_req).await.unwrap(), json!(2));
        // 5a. Transient inspect I/O error during tracked thaw retains both handles.
        store.script_inspect_target_error(Some(Errno::EIO));
        kernel.clear_calls();
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("cannot update freeze ownership state"),
            "{err}"
        );
        assert!(kernel.calls().is_empty(), "must not FITHAW when uncertain");
        assert_eq!(
            ctx.frozen_mount_count(),
            2,
            "uncertain handles must be retained for retry"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);

        // 5b. Entry (8, 1) becomes ambiguous while (8, 2) is readable -> drains (8, 2)
        //     and keeps (8, 1) retained for retry without touching it.
        store.script_inspect_target_error(None);
        store.inject_ambiguous_entry((8, 1), "momentary corruption");
        kernel.clear_calls();
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(err.contains("1 target(s) thawed"), "{err}");
        assert!(
            err.contains("freeze ownership is ambiguous; cannot confirm complete recovery"),
            "{err}"
        );
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/a"))),
            "must not FITHAW ambiguous /a"
        );
        assert_eq!(
            ctx.frozen_mount_count(),
            1,
            "ambiguous /a handle must stay retained for retry"
        );

        // 5c. Once (8, 1) is restored to qeminga ownership, retry drains it cleanly
        //     and returns to Thawed with zero claims and marker removed.
        store.seed_self_claim((8, 1));
        assert_eq!(thaw(&ctx, &thaw_req).await.unwrap(), json!(1));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert_eq!(ctx.frozen_mount_count(), 0);
        assert!(store.owned_by_self().is_empty());
        assert!(!ctx.marker.exists());

        // 6. Uncertain rollback (inspect Err during rollback) retains /b's handle
        //    for retry without FITHAW, then recovers cleanly once error clears.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        let gate = kernel.script_freeze_gate("/a");
        let _guard = gate.release_on_drop();
        kernel.script_freeze_error("/a", Errno::EIO);
        let ctx_bg = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });
        while gate.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        store.script_inspect_target_error(Some(Errno::EIO));
        gate.release();
        let err = task.await.unwrap().unwrap_err().to_string();
        assert!(
            err.contains("cannot update freeze ownership state"),
            "{err}"
        );
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/b"))),
            "uncertain rollback must not FITHAW /b"
        );
        assert_eq!(
            ctx.frozen_mount_count(),
            1,
            "uncertain rollback must keep /b handle for retry"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        store.script_inspect_target_error(None);
        assert_eq!(thaw(&ctx, &thaw_req).await.unwrap(), json!(1));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert_eq!(ctx.frozen_mount_count(), 0);
        assert!(store.owned_by_self().is_empty());

        // 7. Retained handle whose claim vanished (Unclaimed) before tracked thaw:
        //    refuses FITHAW, reports OwnershipAmbiguous, drops the unowned handle,
        //    and retains marker + Frozen + Discovery.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts2,
            store.clone(),
            Arc::new(NoHooks),
        );
        assert_eq!(freeze(&ctx, &freeze_req).await.unwrap(), json!(2));
        store.release((8, 1)).unwrap();
        kernel.clear_calls();
        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("freeze ownership is ambiguous; cannot confirm complete recovery"),
            "{err}"
        );
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/a"))),
            "must not FITHAW unclaimed /a: {:?}",
            kernel.calls()
        );
        assert_eq!(
            ctx.frozen_mount_count(),
            0,
            "confirmed-unclaimed handle is dropped after refusal"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert!(ctx.marker.exists());
    }

    #[tokio::test]
    async fn cooperative_thawed_drain_removes_stale_recovery_marker_with_empty_ownership_store() {
        use crate::ownership::InMemoryOwnershipStore;

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
        );
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, _kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        assert!(ctx.marker.exists());
        assert_eq!(thaw(&ctx, &thaw_req).await.unwrap(), json!(0));
        assert!(
            !ctx.marker.exists(),
            "stale recovery marker must be removed on Thawed cooperative thaw"
        );
    }

    #[tokio::test]
    async fn cooperative_discovery_matches_multiple_retained_handles_by_device_in_forward_order() {
        use crate::ownership::InMemoryOwnershipStore;

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
        );
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        store.seed_self_claim((8, 1));
        store.seed_self_claim((8, 2));
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        kernel.fifreeze(&mb).unwrap();
        // Hold in deepest-first order [mb (8:2), ma (8:1)] while blocking path opens.
        ctx.hold_frozen_mounts(vec![
            HeldMount {
                mount: mb,
                countable: true,
            },
            HeldMount {
                mount: ma,
                countable: true,
            },
        ]);
        kernel.script_open_error("/a", Errno::EACCES);
        kernel.script_open_error("/b", Errno::EACCES);
        kernel.clear_calls();
        assert_eq!(thaw(&ctx, &thaw_req).await.unwrap(), json!(2));
        let thaw_order: Vec<std::path::PathBuf> = kernel
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Fithaw(p) => Some(p),
                _ => None,
            })
            .collect();
        let first_a = thaw_order
            .iter()
            .position(|p| p == Path::new("/a"))
            .expect("/a thawed");
        let first_b = thaw_order
            .iter()
            .position(|p| p == Path::new("/b"))
            .expect("/b thawed");
        assert!(
            first_a < first_b,
            "retained handles must match target.dev in forward mount order (/a before /b): {thaw_order:?}"
        );
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!ctx.marker.exists());
    }

    #[tokio::test]
    async fn cooperative_restart_recovery_drains_owned_mounted_targets_even_when_directory_scan_fails()
     {
        use crate::ownership::{
            InMemoryOwnershipStore, LinuxOwnershipStore, MAX_OWNERSHIP_ENTRIES,
        };

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /c rw - ext4 /dev/sdc1 rw\n",
            "4 1 8:4 / /d rw - ext4 /dev/sdd1 rw\n",
        );
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // 1. Real LinuxOwnershipStore overflowing MAX_OWNERSHIP_ENTRIES (4096)
        //    after a restart (no retained handles): inspect_all() returns
        //    TooManyEntries, yet recovery must still discover mounted targets,
        //    individually verify their claims via direct openat, drain and
        //    release qeminga-owned /a (8:1), skip foreign /b (8:2), ambiguous
        //    /c (8:3), and unclaimed /d (8:4), and retain the marker + Frozen
        //    state with the inventory error reported.
        let own_dir = tempfile::tempdir().unwrap();
        let linux_store = Arc::new(LinuxOwnershipStore::open(own_dir.path()).unwrap());
        assert_eq!(
            linux_store.try_claim((8, 1)).unwrap(),
            crate::ownership::ClaimOutcome::Acquired
        );
        std::fs::write(own_dir.path().join("8-2"), b"guest-backup\n").unwrap();
        std::fs::write(own_dir.path().join("8-3"), b"").unwrap();
        for i in 0..MAX_OWNERSHIP_ENTRIES {
            std::fs::write(own_dir.path().join(format!("stray-{i:04}")), b"x").unwrap();
        }
        assert!(matches!(
            linux_store.inspect_all(),
            Err(crate::ownership::OwnershipError::TooManyEntries { .. })
        ));

        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            linux_store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        let mc = kernel.open_mount(Path::new("/c"), (8, 3)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        kernel.fifreeze(&mb).unwrap();
        kernel.fifreeze(&mc).unwrap();
        kernel.clear_calls();

        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err.contains("1 target(s) thawed"),
            "reachable qeminga-owned /a must thaw despite TooManyEntries scan failure: {err}"
        );
        assert!(
            err.contains("freeze ownership is ambiguous"),
            "TooManyEntries inventory failure must still be reported: {err}"
        );
        assert!(
            kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/a"))),
            "/a must receive FITHAW: {:?}",
            kernel.calls()
        );
        for untouched in ["/b", "/c", "/d"] {
            assert!(
                !kernel
                    .calls()
                    .iter()
                    .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new(untouched))),
                "{untouched} must NOT receive FITHAW: {:?}",
                kernel.calls()
            );
        }
        assert!(
            !own_dir.path().join("8-1").exists(),
            "drained qeminga claim 8-1 must be released"
        );
        assert!(
            own_dir.path().join("8-2").exists(),
            "foreign claim 8-2 must stay untouched"
        );
        assert!(
            own_dir.path().join("8-3").exists(),
            "ambiguous claim 8-3 must stay untouched"
        );
        assert_eq!(
            kernel.tracked_frozen_superblocks(),
            2,
            "only foreign /b and ambiguous /c remain frozen"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());

        // 2. Directory scan I/O failure (EIO) after restart (empty held) with
        //    per-target inspect still working: drains qeminga-owned /a and
        //    leaves foreign /b and ambiguous /c untouched while reporting the
        //    directory scan error.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        store.seed_self_claim((8, 1));
        store.claim_foreign((8, 2), "guest-backup");
        store.inject_ambiguous_entry((8, 3), "corrupt");
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        let mc = kernel.open_mount(Path::new("/c"), (8, 3)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        kernel.fifreeze(&mb).unwrap();
        kernel.fifreeze(&mc).unwrap();
        store.script_inspect_error(Some(Errno::EIO));
        kernel.clear_calls();

        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(err.contains("1 target(s) thawed"), "{err}");
        assert!(
            err.contains("cannot update freeze ownership state"),
            "{err}"
        );
        assert_eq!(store.owner_of((8, 1)), None);
        assert_eq!(store.owner_of((8, 2)).as_deref(), Some("guest-backup"));
        assert_eq!(kernel.tracked_frozen_superblocks(), 2);
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());

        // 3. When BOTH directory scan AND per-target inspect fail, no mounted
        //    target is opened or thawed and any retained handle stays held.
        let store = Arc::new(InMemoryOwnershipStore::new());
        let (ctx, kernel, _clock, _dir) = cooperative_rig(
            FreezeState::Frozen,
            mounts,
            store.clone(),
            Arc::new(NoHooks),
        );
        ctx.marker.create().unwrap();
        store.seed_self_claim((8, 1));
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        ctx.hold_frozen_mounts(vec![HeldMount {
            mount: ma,
            countable: true,
        }]);
        store.script_inspect_error(Some(Errno::EIO));
        store.script_inspect_target_error(Some(Errno::EIO));
        kernel.clear_calls();

        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(err.contains("0 target(s) thawed"), "{err}");
        assert!(kernel.calls().is_empty(), "{:?}", kernel.calls());
        assert_eq!(ctx.frozen_mount_count(), 1);
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(ctx.marker.exists());
    }

    #[tokio::test]
    async fn cooperative_late_abort_ambiguous_claim_retains_recovery_state() {
        use crate::ownership::{
            ClaimOutcome, InMemoryOwnershipStore, OwnershipError, OwnershipStore,
        };
        use std::sync::{Condvar, Mutex};

        #[derive(Debug)]
        struct GatedClaimStore {
            inner: InMemoryOwnershipStore,
            gate_dev: (u32, u32),
            entered: Mutex<bool>,
            released: Mutex<bool>,
            cv: Condvar,
        }

        impl GatedClaimStore {
            fn new(gate_dev: (u32, u32)) -> Self {
                Self {
                    inner: InMemoryOwnershipStore::new(),
                    gate_dev,
                    entered: Mutex::new(false),
                    released: Mutex::new(false),
                    cv: Condvar::new(),
                }
            }

            fn is_waiting(&self) -> bool {
                *self.entered.lock().unwrap()
            }

            fn release(&self) {
                *self.released.lock().unwrap() = true;
                self.cv.notify_all();
            }
        }

        impl OwnershipStore for GatedClaimStore {
            fn try_claim(&self, dev: (u32, u32)) -> Result<ClaimOutcome, OwnershipError> {
                if dev == self.gate_dev {
                    *self.entered.lock().unwrap() = true;
                    let mut guard = self.released.lock().unwrap();
                    while !*guard {
                        guard = self.cv.wait(guard).unwrap();
                    }
                }
                self.inner.try_claim(dev)
            }

            fn inspect(
                &self,
                dev: (u32, u32),
            ) -> Result<crate::ownership::TargetOwnership, OwnershipError> {
                self.inner.inspect(dev)
            }

            fn release(&self, dev: (u32, u32)) -> Result<(), OwnershipError> {
                self.inner.release(dev)
            }

            fn inspect_all(&self) -> Result<crate::ownership::OwnershipSnapshot, OwnershipError> {
                self.inner.inspect_all()
            }
        }

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
        );
        let store = Arc::new(GatedClaimStore::new((8, 1)));
        store
            .inner
            .inject_ambiguous_entry((8, 1), "corrupt-after-startup");
        let hooks = Arc::new(Recorder::default());
        let (ctx, kernel, clock, _dir) =
            cooperative_rig(FreezeState::Thawed, mounts, store.clone(), hooks.clone());
        let ctx_bg = Arc::clone(&ctx);
        let task = tokio::spawn(async move {
            let req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
            freeze(&ctx_bg, &req).await
        });

        // /b freezes cleanly; /a blocks inside try_claim().
        while !store.is_waiting() {
            tokio::task::yield_now().await;
        }
        // Expire the operation deadline so the abort commits while /a is still
        // inside try_claim(), then release /a to return OwnershipAmbiguous.
        clock.advance(Duration::from_secs(600));
        let err = task.await.unwrap().unwrap_err().to_string();
        assert!(err.contains("freeze aborted"), "{err}");
        store.release();

        // Wait for the aborted freeze operation to settle.
        while ctx.freeze_op().is_some() {
            tokio::task::yield_now().await;
        }
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert_eq!(ctx.thaw_scope(), ThawScope::Discovery);
        assert!(ctx.marker.exists());
        assert_eq!(hooks.events().last().copied(), Some("frozen"));
        // Already-frozen /b was rolled back cleanly and its claim released.
        assert_eq!(store.inner.owner_of((8, 2)), None);
        assert_eq!(kernel.tracked_frozen_superblocks(), 0);
    }

    #[tokio::test]
    async fn cooperative_markerless_thawed_scan_failure_establishes_or_reports_unavailable_marker_and_preserves_foreign()
     {
        use crate::ownership::{LinuxOwnershipStore, MAX_OWNERSHIP_ENTRIES};

        let mounts = concat!(
            "1 0 8:1 / /a rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /b rw - ext4 /dev/sdb1 rw\n",
        );
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // 1. Marker absent on disk while Thawed + directory scan fails
        //    (TooManyEntries): cooperative thaw establishes /run/qeminga/frozen,
        //    drains reachable qeminga-owned /a (8:1), preserves foreign /b (8:2),
        //    and accurately reports "state frozen, marker retained" matching disk.
        let own_dir = tempfile::tempdir().unwrap();
        let linux_store = Arc::new(LinuxOwnershipStore::open(own_dir.path()).unwrap());
        assert_eq!(
            linux_store.try_claim((8, 1)).unwrap(),
            crate::ownership::ClaimOutcome::Acquired
        );
        std::fs::write(own_dir.path().join("8-2"), b"guest-backup\n").unwrap();
        for i in 0..MAX_OWNERSHIP_ENTRIES {
            std::fs::write(own_dir.path().join(format!("stray-{i:04}")), b"x").unwrap();
        }

        let (ctx, kernel, _clock, marker_dir) = cooperative_rig(
            FreezeState::Thawed,
            mounts,
            linux_store.clone(),
            Arc::new(NoHooks),
        );
        assert!(
            !ctx.marker.exists(),
            "precondition: marker absent before thaw"
        );
        let ma = kernel.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb = kernel.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel.fifreeze(&ma).unwrap();
        kernel.fifreeze(&mb).unwrap();
        kernel.clear_calls();

        let err = thaw(&ctx, &thaw_req).await.unwrap_err().to_string();
        assert!(err.contains("1 target(s) thawed"), "{err}");
        assert!(err.contains("freeze ownership is ambiguous"), "{err}");
        assert!(
            err.contains("state frozen, marker retained"),
            "reply must match established on-disk marker: {err}"
        );
        assert!(
            ctx.marker.exists(),
            "recovery marker must actually exist on disk when reply says marker retained"
        );
        assert_eq!(ctx.state.current(), FreezeState::Frozen);
        assert!(!own_dir.path().join("8-1").exists());
        assert!(own_dir.path().join("8-2").exists());
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);
        assert!(
            !kernel
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/b"))),
            "foreign /b must not be touched: {:?}",
            kernel.calls()
        );

        // Simulated restart with the same marker path and ownership directory:
        // marker is present so the restarted instance starts Frozen; once stray
        // entries are cleared, retry removes the marker and preserves foreign /b.
        let restarted_marker = Marker::open(marker_dir.path().join("frozen")).unwrap();
        assert!(
            restarted_marker.exists(),
            "restarted instance must observe the established recovery marker"
        );
        let restarted_store = Arc::new(LinuxOwnershipStore::open(own_dir.path()).unwrap());
        let restarted_ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Frozen)),
                Router::new(Box::new(std::io::sink())),
                restarted_marker,
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(StaticMounts(mounts.to_owned())))
            .with_ownership(restarted_store.clone()),
        );
        for i in 0..MAX_OWNERSHIP_ENTRIES {
            std::fs::remove_file(own_dir.path().join(format!("stray-{i:04}"))).unwrap();
        }
        kernel.clear_calls();
        assert_eq!(thaw(&restarted_ctx, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(restarted_ctx.state.current(), FreezeState::Thawed);
        assert!(!restarted_ctx.marker.exists());
        assert!(own_dir.path().join("8-2").exists());
        assert_eq!(kernel.tracked_frozen_superblocks(), 1);
        assert!(kernel.calls().is_empty(), "{:?}", kernel.calls());

        // 2. Marker absent AND creating the marker fails (pinned parent dir
        //    unlinked before thaw): recovery STILL drains reachable qeminga /a,
        //    preserves foreign /b, retains Frozen state, and reports
        //    "state frozen, marker unavailable" (never falsely claiming
        //    "marker retained"). On restart, startup's ownership-directory probe
        //    still detects the scan failure without relying on the marker.
        let own_dir2 = tempfile::tempdir().unwrap();
        let linux_store2 = Arc::new(LinuxOwnershipStore::open(own_dir2.path()).unwrap());
        assert_eq!(
            linux_store2.try_claim((8, 1)).unwrap(),
            crate::ownership::ClaimOutcome::Acquired
        );
        std::fs::write(own_dir2.path().join("8-2"), b"guest-backup\n").unwrap();
        for i in 0..MAX_OWNERSHIP_ENTRIES {
            std::fs::write(own_dir2.path().join(format!("stray-{i:04}")), b"x").unwrap();
        }
        let ephemeral_dir = tempfile::tempdir().unwrap();
        let ephemeral_sub = ephemeral_dir.path().join("gone");
        std::fs::create_dir(&ephemeral_sub).unwrap();
        let failing_marker = Marker::open(ephemeral_sub.join("frozen")).unwrap();
        std::fs::remove_dir(&ephemeral_sub).unwrap();

        let kernel2 = Arc::new(FakeKernel::new());
        kernel2.track_freeze_depth();
        let ma2 = kernel2.open_mount(Path::new("/a"), (8, 1)).unwrap();
        let mb2 = kernel2.open_mount(Path::new("/b"), (8, 2)).unwrap();
        kernel2.fifreeze(&ma2).unwrap();
        kernel2.fifreeze(&mb2).unwrap();
        kernel2.clear_calls();

        let hooks2 = Arc::new(Recorder::default());
        let ctx2 = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                failing_marker,
            )
            .with_kernel(kernel2.clone())
            .with_mounts(Arc::new(StaticMounts(mounts.to_owned())))
            .with_hooks(hooks2.clone())
            .with_ownership(linux_store2.clone()),
        );
        let err2 = thaw(&ctx2, &thaw_req).await.unwrap_err().to_string();
        assert!(err2.contains("1 target(s) thawed"), "{err2}");
        assert!(err2.contains("freeze ownership is ambiguous"), "{err2}");
        assert!(
            err2.contains("state frozen, marker unavailable"),
            "must report marker unavailable when marker creation fails: {err2}"
        );
        assert!(
            !err2.contains("marker retained"),
            "must never claim marker retained when marker could not be created: {err2}"
        );
        assert!(!ctx2.marker.exists());
        assert_eq!(ctx2.state.current(), FreezeState::Frozen);
        assert_eq!(hooks2.events().last().copied(), Some("frozen"));
        assert!(!own_dir2.path().join("8-1").exists());
        assert!(own_dir2.path().join("8-2").exists());
        assert_eq!(kernel2.tracked_frozen_superblocks(), 1);
        assert!(
            !kernel2
                .calls()
                .iter()
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/b"))),
            "foreign /b must not be touched: {:?}",
            kernel2.calls()
        );
        // Without a marker, a restarted instance inspecting the same ownership
        // directory still detects TooManyEntries and escalates into recovery.
        assert!(matches!(
            LinuxOwnershipStore::open(own_dir2.path())
                .unwrap()
                .inspect_all(),
            Err(crate::ownership::OwnershipError::TooManyEntries { .. })
        ));

        // 3. When marker creation fails AND the ownership store is readable with
        //    no remaining obligations or ambiguity after draining qeminga /a,
        //    the complete drain returns 1, settles Thawed, and preserves foreign /b.
        for i in 0..MAX_OWNERSHIP_ENTRIES {
            std::fs::remove_file(own_dir2.path().join(format!("stray-{i:04}"))).unwrap();
        }
        assert_eq!(
            linux_store2.try_claim((8, 1)).unwrap(),
            crate::ownership::ClaimOutcome::Acquired
        );
        let ma3 = kernel2.open_mount(Path::new("/a"), (8, 1)).unwrap();
        kernel2.fifreeze(&ma3).unwrap();
        kernel2.clear_calls();
        assert_eq!(thaw(&ctx2, &thaw_req).await.unwrap(), json!(1));
        assert_eq!(ctx2.state.current(), FreezeState::Thawed);
        assert!(!ctx2.marker.exists());
        assert!(!own_dir2.path().join("8-1").exists());
        assert!(own_dir2.path().join("8-2").exists());
        assert_eq!(kernel2.tracked_frozen_superblocks(), 1);
    }

    #[tokio::test]
    async fn cooperative_idle_thaw_escalates_on_indeterminate_marker_probe_and_collapses_excluded_recovery_failures()
     {
        use crate::audit::Mode;
        use crate::ownership::InMemoryOwnershipStore;

        let mounts = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
            "3 1 8:3 / /secret rw - ext4 /dev/sdc1 rw\n",
        );
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // 1. Indeterminate Marker::probe() (256-byte filename -> ENAMETOOLONG
        //    deterministically regardless of UID) on an idle cooperative thaw
        //    from `Thawed` MUST NOT fast-path `Ok(0)`: it must enter ring mode,
        //    escalate to cooperative recovery, transition to `Frozen` with
        //    watchdog armed, report `marker unavailable`, and never touch the
        //    foreign-owned allowlisted `/data` freeze.
        let dir1 = tempfile::tempdir().unwrap();
        let store1 = Arc::new(InMemoryOwnershipStore::new());
        store1.claim_foreign((8, 2), "guest-integrity");
        let kernel1 = Arc::new(FakeKernel::new());
        kernel1.track_freeze_depth();
        let md1 = kernel1.open_mount(Path::new("/data"), (8, 2)).unwrap();
        kernel1.fifreeze(&md1).unwrap();
        kernel1.clear_calls();
        let hooks1 = Arc::new(Recorder::default());
        let mut cfg1 = Config::default();
        cfg1.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx1 = Arc::new(
            Context::new(
                Arc::new(cfg1),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir1.path().join("m".repeat(256))).unwrap(),
            )
            .with_kernel(kernel1.clone())
            .with_mounts(Arc::new(StaticMounts(mounts.to_owned())))
            .with_hooks(hooks1.clone())
            .with_ownership(store1.clone()),
        );
        let err1 = thaw(&ctx1, &thaw_req).await.unwrap_err().to_string();
        assert!(
            err1.contains("cannot remove recovery marker")
                && err1.contains("state frozen, marker unavailable"),
            "indeterminate marker probe on idle cooperative thaw must escalate and fail closed: {err1}"
        );
        assert_eq!(ctx1.state.current(), FreezeState::Frozen);
        assert_eq!(ctx1.audit.mode(), Mode::Ring);
        assert_eq!(hooks1.states_at("frozen"), vec![FreezeState::Frozen]);
        assert_eq!(kernel1.tracked_frozen_superblocks(), 1);
        assert!(
            kernel1.calls().is_empty(),
            "foreign /data must never be touched during indeterminate-marker escalation: {:?}",
            kernel1.calls()
        );

        // 2. Fallback per-target scan (when `inspect_all()` fails with EIO)
        //    composed with `freeze_allowed_mountpoints = ["/data"]`: drains
        //    non-allowlisted qeminga-owned `/secret` (8:3) and releases its
        //    claim while reporting `0 target(s) thawed` + store-level
        //    `OwnershipError`, and never touches foreign allowlisted `/data`.
        let dir2 = tempfile::tempdir().unwrap();
        let store2 = Arc::new(InMemoryOwnershipStore::new());
        store2.claim_foreign((8, 2), "guest-integrity");
        store2.seed_self_claim((8, 3));
        store2.script_inspect_error(Some(Errno::EIO));
        let kernel2 = Arc::new(FakeKernel::new());
        kernel2.track_freeze_depth();
        let md2 = kernel2.open_mount(Path::new("/data"), (8, 2)).unwrap();
        let ms2 = kernel2.open_mount(Path::new("/secret"), (8, 3)).unwrap();
        kernel2.fifreeze(&md2).unwrap();
        kernel2.fifreeze(&ms2).unwrap();
        kernel2.clear_calls();
        let mut cfg2 = Config::default();
        cfg2.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx2 = Arc::new(
            Context::new(
                Arc::new(cfg2),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Frozen)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir2.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel2.clone())
            .with_mounts(Arc::new(StaticMounts(mounts.to_owned())))
            .with_hooks(Arc::new(NoHooks))
            .with_ownership(store2.clone()),
        );
        ctx2.marker.create().unwrap();
        let err2 = thaw(&ctx2, &thaw_req).await.unwrap_err().to_string();
        assert_eq!(
            err2,
            "thaw incomplete: cannot update freeze ownership state (0 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(store2.owner_of((8, 3)), None);
        assert_eq!(store2.owner_of((8, 2)).as_deref(), Some("guest-integrity"));
        assert_eq!(kernel2.tracked_frozen_superblocks(), 1);
        assert!(
            !kernel2.calls().iter().any(
                |c| matches!(c, Call::Open(p, _) | Call::Fithaw(p) if p == Path::new("/data"))
            ),
            "fallback cooperative scan must never touch foreign /data: {:?}",
            kernel2.calls()
        );

        // 3. Missing qeminga-owned superblock (8:99 absent from mountinfo)
        //    under `freeze_allowed_mountpoints = ["/data"]` collapses to
        //    `RecoveryReason::RecoveryIncomplete` instead of disclosing
        //    `target mountpoint is unreachable` for an unallowlisted device.
        let dir3 = tempfile::tempdir().unwrap();
        let store3 = Arc::new(InMemoryOwnershipStore::new());
        store3.seed_self_claim((8, 99));
        let kernel3 = Arc::new(FakeKernel::new());
        kernel3.track_freeze_depth();
        let mut cfg3 = Config::default();
        cfg3.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx3 = Arc::new(
            Context::new(
                Arc::new(cfg3),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Frozen)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir3.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel3)
            .with_mounts(Arc::new(StaticMounts(mounts.to_owned())))
            .with_hooks(Arc::new(NoHooks))
            .with_ownership(store3.clone()),
        );
        ctx3.marker.create().unwrap();
        let err3 = thaw(&ctx3, &thaw_req).await.unwrap_err().to_string();
        assert_eq!(
            err3,
            "thaw incomplete: recovery did not complete; filesystem may still be frozen (0 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(
            store3.owner_of((8, 99)).as_deref(),
            Some(crate::ownership::QEMINGA_OWNER)
        );
        assert_eq!(ctx3.state.current(), FreezeState::Frozen);
        assert!(ctx3.marker.exists());
    }

    #[tokio::test]
    async fn cooperative_tracked_thaw_and_empty_claim_discovery_respect_mountinfo_boundaries() {
        use crate::ownership::InMemoryOwnershipStore;

        let table = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
        );
        let freeze_req = parse_request(br#"{"execute":"guest-fsfreeze-freeze"}"#).unwrap();
        let thaw_req = parse_request(br#"{"execute":"guest-fsfreeze-thaw"}"#).unwrap();

        // 1. Tracked cooperative thaw (`ThawScope::Tracked`, `discover == false`)
        //    must drain held descriptors via per-target `inspect()` + `release()`
        //    without calling `inspect_all()` or reading `/proc/self/mountinfo`.
        let dir1 = tempfile::tempdir().unwrap();
        let store1 = Arc::new(InMemoryOwnershipStore::new());
        let mounts1 = Arc::new(SwitchableMounts::new(table));
        let kernel1 = Arc::new(FakeKernel::new());
        kernel1.track_freeze_depth();
        let mut cfg1 = Config::default();
        cfg1.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx1 = Arc::new(
            Context::new(
                Arc::new(cfg1),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir1.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel1.clone())
            .with_mounts(mounts1.clone())
            .with_hooks(Arc::new(NoHooks))
            .with_ownership(store1.clone()),
        );
        assert_eq!(freeze(&ctx1, &freeze_req).await.unwrap(), json!(1));
        assert_eq!(ctx1.thaw_scope(), ThawScope::Tracked);
        mounts1.fail_reads(true);
        store1.script_inspect_error(Some(Errno::EIO));
        assert_eq!(thaw(&ctx1, &thaw_req).await.unwrap(), json!(1));
        assert_eq!(ctx1.state.current(), FreezeState::Thawed);
        assert!(!ctx1.marker.exists());
        assert_eq!(store1.owner_of((8, 2)), None);
        assert_eq!(kernel1.tracked_frozen_superblocks(), 0);

        // 2. Restricted cooperative discovery with empty `owned_by_self` and
        //    empty `retained` must NOT read `/proc/self/mountinfo`: it removes
        //    the stale marker and settles `Thawed` with count 0 even when
        //    mountinfo reads fail.
        let dir2 = tempfile::tempdir().unwrap();
        let store2 = Arc::new(InMemoryOwnershipStore::new());
        let mounts2 = Arc::new(SwitchableMounts::new(table));
        mounts2.fail_reads(true);
        let kernel2 = Arc::new(FakeKernel::new());
        let mut cfg2 = Config::default();
        cfg2.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx2 = Arc::new(
            Context::new(
                Arc::new(cfg2),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Frozen)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir2.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel2)
            .with_mounts(mounts2)
            .with_hooks(Arc::new(NoHooks))
            .with_ownership(store2),
        );
        ctx2.marker.create().unwrap();
        assert_eq!(thaw(&ctx2, &thaw_req).await.unwrap(), json!(0));
        assert_eq!(ctx2.state.current(), FreezeState::Thawed);
        assert!(!ctx2.marker.exists());

        // 3. Restricted cooperative discovery with empty `owned_by_self` and a
        //    non-empty allowlisted `retained` handle DOES read mountinfo so the
        //    allowlisted target's lost-ownership error reports `OwnershipAmbiguous`
        //    rather than collapsing to `RecoveryIncomplete`.
        let dir3 = tempfile::tempdir().unwrap();
        let store3 = Arc::new(InMemoryOwnershipStore::new());
        let kernel3 = Arc::new(FakeKernel::new());
        kernel3.track_freeze_depth();
        let md3 = kernel3.open_mount(Path::new("/data"), (8, 2)).unwrap();
        kernel3.fifreeze(&md3).unwrap();
        let mut cfg3 = Config::default();
        cfg3.agent.freeze_allowed_mountpoints = Some(vec!["/data".into()]);
        let ctx3 = Arc::new(
            Context::new(
                Arc::new(cfg3),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Frozen)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir3.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel3.clone())
            .with_mounts(Arc::new(StaticMounts(table.to_owned())))
            .with_hooks(Arc::new(NoHooks))
            .with_ownership(store3),
        );
        ctx3.marker.create().unwrap();
        ctx3.hold_frozen_mounts(vec![HeldMount {
            mount: md3,
            countable: true,
        }]);
        let err3 = thaw(&ctx3, &thaw_req).await.unwrap_err().to_string();
        assert_eq!(
            err3,
            "thaw incomplete: freeze ownership is ambiguous; cannot confirm complete recovery (0 target(s) thawed); state frozen, marker retained"
        );
        assert_eq!(ctx3.state.current(), FreezeState::Frozen);
        assert_eq!(kernel3.tracked_frozen_superblocks(), 1);
    }
}
