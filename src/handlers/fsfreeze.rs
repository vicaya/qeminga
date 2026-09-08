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
//!    [`FreezeHooks::on_thawed`]. An aborted operation ends in `Thawed`
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

use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dispatch::Context;
use crate::freeze_plan::{FreezePlan, Target};
use crate::handlers::NoArgs;
use crate::kernel::{KernelError, KernelOps, Mount};
use crate::marker::{Marker, MarkerError};
use crate::mountinfo::MountSource;
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
            Some(op) => return join_operation(&op).await,
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

/// A thaw that joins the freeze operation in progress.
async fn join_operation(op: &crate::freeze_op::FreezeOp) -> Result<Value, Error> {
    op.request_abort();
    let progress = op.wait_for_recovery_pass().await;
    match progress.settled {
        Some(FreezeState::Thawed) => Ok(json!(progress.recovered)),
        Some(state) => Err(Error::Internal(format!(
            "thaw joined the aborted freeze: {} target(s) thawed; {}; state {state}, marker retained",
            progress.recovered,
            progress
                .unrecoverable
                .unwrap_or_else(|| "recovery incomplete".to_owned())
        ))),
        None => Err(Error::Internal(format!(
            "thaw joined the aborted freeze: {} target(s) thawed; FIFREEZE of {} still in flight; marker retained until it returns",
            progress.recovered,
            progress.in_flight.unwrap_or_else(|| "a target".to_owned())
        ))),
    }
}

/// The freeze algorithm shared by `freeze` and `freeze-list`: claim
/// `Thawed → Freezing`, start the operation (`freeze_op`), and relay its
/// single reply. The operation outlives this request: a deadline or a
/// thaw request aborts it and the reply is the error, while the recovery
/// of the targets frozen so far continues on the coordinator.
async fn run_freeze(ctx: &Arc<Context>, restrict: Option<Vec<String>>) -> Result<Value, Error> {
    let token = ctx
        .state
        .begin_freeze()
        .map_err(|err| Error::Internal(format!("cannot freeze: {err}")))?;
    ctx.hooks.on_freezing(ctx);
    let reply = crate::freeze_op::start(Arc::clone(ctx), token, restrict);
    match reply.await {
        Ok(Ok(frozen)) => Ok(json!(frozen)),
        Ok(Err(failure)) => Err(Error::Internal(failure.to_string())),
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
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let held = ctx.take_frozen_mounts();
    let (outcome, held) = tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            let mut held = held;
            // Discovery and drain are separate: the handles this process
            // holds are drained whether or not the mount table can be
            // read (`thaw_blocking`).
            let plan = build_plan::<ThawFailure>(mounts.as_ref(), None);
            let outcome = thaw_blocking(kernel.as_ref(), &marker, plan, &mut held);
            (outcome, held)
        })
    })
    .await
    .unwrap_or_else(|err| (Err(ThawFailure::Task(err.to_string())), Vec::new()));
    // Whatever could not be drained keeps its handle for the next attempt.
    ctx.hold_frozen_mounts(held);

    match outcome {
        Ok(thawed) => {
            // Finalise (audit flush) while still `Thawing`, then publish
            // `Thawed`: a freeze accepted after the publication can never
            // have its logging mode changed by this thaw's completion.
            ctx.hooks.on_thawed(ctx);
            ctx.state.thaw_succeeded(token);
            tracing::info!(event = "fsfreeze_thawed", thawed, "filesystems thawed");
            Ok(thawed)
        }
        Err(failure) if token.is_recovery_drain() => {
            // Nothing was frozen by this agent (the drain started from
            // `Thawed`), so there is no frozen state to retain: return to
            // `Thawed` and report the error (OQ-3).
            ctx.hooks.on_thawed(ctx);
            ctx.state.thaw_succeeded(token);
            tracing::warn!(event = "fsfreeze_recovery_drain_failed", error = %failure, "recovery drain failed; still thawed");
            Err(Error::Internal(failure.to_string()))
        }
        Err(failure) => {
            // `Thawing → Frozen` (§4.2): the state is `Frozen` again, so
            // the watchdog is re-armed like on any entry into `Frozen`
            // (§4.4); without it a failed thaw would be unbounded.
            ctx.state.thaw_failed(token);
            ctx.hooks.on_frozen(ctx);
            tracing::error!(event = "fsfreeze_thaw_failed", error = %failure, "thaw failed; marker retained");
            Err(Error::Internal(failure.to_string()))
        }
    }
}

/// What stopped a freeze at a target: the kernel's answer to `FIFREEZE`,
/// or no pathname of the target leading to its superblock.
#[derive(Debug)]
pub enum FreezeStop {
    /// `FIFREEZE` failed with this error.
    Ioctl(KernelError),
    /// None of the target's mount points opens on its planned device (the
    /// attempts, in order); no ioctl was issued.
    Unreachable(String),
}

impl std::fmt::Display for FreezeStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FreezeStop::Ioctl(err) => write!(f, "{err}"),
            FreezeStop::Unreachable(attempts) => {
                write!(
                    f,
                    "no mount point leads to it ({attempts}); no FIFREEZE issued"
                )
            }
        }
    }
}

/// Why a freeze failed; the `Display` text is the wire description.
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
    #[error("freeze of {mountpoint} failed: {cause}; rolled back")]
    Hard {
        /// The target that failed.
        mountpoint: String,
        /// What stopped it.
        cause: FreezeStop,
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
        /// Why the drain did not complete.
        reason: String,
    },
    /// The rollback thawed every processed target but the marker could not
    /// be removed: the state stays `Frozen` and the marker is retained.
    #[error(
        "freeze of {failed} failed: {cause}; rolled back but cannot remove recovery marker: {marker}"
    )]
    MarkerRetained {
        /// The target that stopped the freeze.
        failed: String,
        /// What stopped it.
        cause: FreezeStop,
        /// The removal error.
        marker: MarkerError,
    },
    /// The blocking task could not be joined.
    #[error("freeze task failed: {0}")]
    Task(String),
    /// The operation was aborted (§4.4): its deadline expired or a thaw was
    /// requested while a `FIFREEZE` was still in flight. The targets frozen
    /// so far are being thawed by the coordinator; the marker and the
    /// frozen gate stay until the in-flight call returns.
    #[error(
        "freeze aborted: {}{}; {frozen} target(s) frozen so far are being thawed; marker retained",
        cause.describe(*timeout_secs),
        in_flight.as_deref().map(|mp| format!(" with FIFREEZE of {mp} in flight")).unwrap_or_default()
    )]
    Aborted {
        /// What aborted it.
        cause: crate::freeze_op::AbortCause,
        /// The operation deadline in seconds.
        timeout_secs: u64,
        /// Successful `FIFREEZE` calls before the abort.
        frozen: u64,
        /// The target whose call was in flight, if any.
        in_flight: Option<String>,
    },
}

impl FreezeFailure {
    /// `true` when the failure leaves a filesystem possibly frozen or the
    /// marker in place, so the agent must stay `Frozen` (design §4.2).
    pub fn retains_frozen_state(&self) -> bool {
        matches!(
            self,
            FreezeFailure::RollbackIncomplete { .. } | FreezeFailure::MarkerRetained { .. }
        )
    }
}

/// Why a thaw failed unrecoverably (the state returns to `Frozen`).
#[derive(Debug, thiserror::Error)]
pub enum ThawFailure {
    /// The mount table could not be read.
    #[error("cannot build thaw plan: {0}")]
    Plan(String),
    /// A target may still be frozen after its drain (OQ-3): a denied or
    /// failed `FITHAW`, a superblock none of whose mount points opens on
    /// it any more (no `FITHAW` issued), or a drain that never converged.
    /// The marker and the frozen gate are retained.
    #[error("thaw of {mountpoint} incomplete: {reason}; marker retained")]
    Incomplete {
        /// The target that may still be frozen.
        mountpoint: String,
        /// Why the drain did not complete.
        reason: String,
    },
    /// The marker could not be removed after the drain.
    #[error("drain complete but cannot remove recovery marker: {0}")]
    Marker(MarkerError),
    /// The blocking task could not be joined.
    #[error("thaw task failed: {0}")]
    Task(String),
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

impl From<String> for FreezeFailure {
    fn from(message: String) -> Self {
        FreezeFailure::Plan(message)
    }
}

impl From<String> for ThawFailure {
    fn from(message: String) -> Self {
        ThawFailure::Plan(message)
    }
}

/// Opens `target` on its planned device through the first of its mount
/// points that still leads there (the kernel shim verifies each opened
/// directory, so a mount placed over a pathname is seen, not frozen or
/// thawed by mistake). When none does, the attempts are reported in
/// order: `/data: mountpoint is on 8:3, not on the planned 8:2;
/// /data-alias: cannot open mountpoint: ENOENT`.
pub(crate) fn open_target(kernel: &dyn KernelOps, target: &Target) -> Result<Mount, String> {
    let mut attempts = Vec::new();
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
            Err(err) => attempts.push(format!("{}: {err}", lossy(path))),
        }
    }
    Err(attempts.join("; "))
}

/// Drains every processed target through the handle its freeze opened, in
/// forward mount order, then removes the marker; `held` keeps the handles
/// whose drain did not complete. Every processed target gets its drain,
/// as in [`thaw_blocking`]: one that cannot be thawed is remembered and
/// reported afterwards, and must not leave the later ones frozen until a
/// recovery. Returns the failure to report.
pub(crate) fn rollback(
    kernel: &dyn KernelOps,
    marker: &Marker,
    held: &mut Vec<Mount>,
    failed: &Path,
    cause: FreezeStop,
) -> FreezeFailure {
    let (_, keep, incomplete) = drain_held(kernel, std::mem::take(held));
    *held = keep;
    let failed = lossy(failed);
    if let Some((mountpoint, reason)) = incomplete {
        return FreezeFailure::RollbackIncomplete {
            failed,
            cause,
            mountpoint,
            reason,
        };
    }
    match marker.remove() {
        Ok(()) | Err(MarkerError::Absent { .. }) => FreezeFailure::Hard {
            mountpoint: failed,
            cause,
        },
        Err(marker) => FreezeFailure::MarkerRetained {
            failed,
            cause,
            marker,
        },
    }
}

/// Drains handles a freeze published, in forward mount order (they were
/// pushed deepest-first). Returns the number of targets on which at least
/// one `FITHAW` succeeded, the handles whose drain did not complete (kept
/// for a later attempt), and the first such target with its reason.
pub(crate) fn drain_held(
    kernel: &dyn KernelOps,
    held: Vec<Mount>,
) -> (u64, Vec<Mount>, Option<(String, String)>) {
    let mut recovered = 0;
    let mut incomplete: Option<(String, String)> = None;
    let mut keep = Vec::new();
    for mount in held.into_iter().rev() {
        let drained = drain(kernel, &mount);
        if drained.successes > 0 {
            recovered += 1;
        }
        tracing::warn!(
            event = "fsfreeze_rollback",
            mountpoint = %mount.mountpoint().display(),
            successes = drained.successes,
            "rolled back"
        );
        if let Some(reason) = drained.incomplete() {
            tracing::error!(
                event = "fsfreeze_rollback_incomplete",
                mountpoint = %mount.mountpoint().display(),
                reason,
                "rollback target may still be frozen"
            );
            incomplete.get_or_insert((lossy(mount.mountpoint()), reason));
            keep.push(mount);
        }
    }
    (recovered, keep, incomplete)
}

/// Drains every target in forward order, then removes the marker. Returns
/// the number of targets on which at least one `FITHAW` succeeded.
///
/// A target is drained through the handle its freeze opened when `held`
/// has one for its device (that handle names the frozen filesystem
/// whatever its pathnames lead to now), otherwise through the first of
/// its mount points that still opens on its device. Handles for devices
/// the plan no longer lists are drained too: this process froze them.
/// On return `held` keeps the handles whose drain did not complete.
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
fn thaw_blocking(
    kernel: &dyn KernelOps,
    marker: &Marker,
    plan: Result<FreezePlan, ThawFailure>,
    held: &mut Vec<Mount>,
) -> Result<u64, ThawFailure> {
    let mut state = ThawState::default();
    let mut retained = std::mem::take(held);
    let discovery = match plan {
        Ok(plan) => {
            for target in plan.thaw_order() {
                let mount = match retained.iter().position(|m| m.dev() == target.dev) {
                    Some(index) => retained.remove(index),
                    None => match open_target(kernel, target) {
                        Ok(mount) => mount,
                        Err(attempts) => {
                            let failure = ThawFailure::Incomplete {
                                mountpoint: lossy(&target.mountpoint),
                                reason: format!(
                                    "no mount point leads to {}:{} ({attempts}); no FITHAW issued",
                                    target.dev.0, target.dev.1
                                ),
                            };
                            tracing::error!(
                                event = "fsfreeze_thaw_target_failed",
                                mountpoint = %target.mountpoint.display(),
                                error = %failure,
                                "target cannot be reached; draining the remaining targets"
                            );
                            state.unrecoverable.get_or_insert(failure);
                            continue;
                        }
                    },
                };
                state.drain(kernel, mount);
            }
            None
        }
        Err(failure) => {
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
    for mount in retained.into_iter().rev() {
        if discovery.is_none() {
            tracing::warn!(
                event = "fsfreeze_unplanned_drain",
                mountpoint = %mount.mountpoint().display(),
                "frozen by this process but no longer in the plan; drained"
            );
        }
        state.drain(kernel, mount);
    }
    let ThawState {
        thawed,
        unrecoverable,
        keep,
    } = state;
    *held = keep;
    if let Some(failure) = unrecoverable {
        return Err(failure);
    }
    if let Some(failure) = discovery {
        return Err(failure);
    }
    match marker.remove() {
        Ok(()) | Err(MarkerError::Absent { .. }) => Ok(thawed),
        Err(err) => Err(ThawFailure::Marker(err)),
    }
}

/// The running result of a thaw drain over several targets.
#[derive(Default)]
struct ThawState {
    /// Targets on which at least one `FITHAW` succeeded.
    thawed: u64,
    /// The first failure to report, if any.
    unrecoverable: Option<ThawFailure>,
    /// Handles whose drain did not complete.
    keep: Vec<Mount>,
}

impl ThawState {
    /// Drains one target, keeping its handle when the drain is incomplete.
    fn drain(&mut self, kernel: &dyn KernelOps, mount: Mount) {
        let drained = drain(kernel, &mount);
        if drained.successes > 0 {
            self.thawed += 1;
        }
        if let Some(reason) = drained.incomplete() {
            let failure = ThawFailure::Incomplete {
                mountpoint: lossy(mount.mountpoint()),
                reason,
            };
            tracing::error!(
                event = "fsfreeze_thaw_target_failed",
                mountpoint = %mount.mountpoint().display(),
                error = %failure,
                "target could not be thawed; draining the remaining targets"
            );
            self.unrecoverable.get_or_insert(failure);
            self.keep.push(mount);
        }
    }
}

/// A mount point for an error message or a wire description.
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
    fn incomplete(&self) -> Option<String> {
        if self.capped {
            return Some(format!(
                "drain did not converge after {MAX_THAW_ITERATIONS} FITHAW calls (still succeeding)"
            ));
        }
        let err = self.first_error.as_ref()?;
        if !err.is_ioctl_answer() {
            return Some(format!("{err}: no FITHAW issued"));
        }
        if err.is_invalid() || err.is_not_supported() {
            return None;
        }
        Some(if err.is_permission() && self.successes == 0 {
            format!("first FITHAW denied: {err}")
        } else if err.is_permission() {
            format!("FITHAW denied after {} successes: {err}", self.successes)
        } else {
            format!("FITHAW failed: {err}; the filesystem may still be frozen")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Router;
    use crate::config::Config;
    use crate::kernel::fake::{Call, FakeKernel};
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
        _dir: tempfile::TempDir,
    }

    /// A mount table whose read can be made to fail (`EMFILE`, as when
    /// the retained handles exhausted the descriptors) and to work again.
    struct SwitchableMounts {
        table: String,
        fail: std::sync::atomic::AtomicBool,
    }

    impl SwitchableMounts {
        fn new(table: String) -> Self {
            SwitchableMounts {
                table,
                fail: std::sync::atomic::AtomicBool::new(false),
            }
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
            Ok(self.table.clone().into_bytes())
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
            let ctx = Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(state)),
                Router::new(Box::new(std::io::sink())),
                Marker::open(dir.path().join("frozen")).unwrap(),
            )
            .with_kernel(kernel.clone())
            .with_mounts(mounts)
            .with_hooks(hooks.clone());
            Rig {
                ctx: Arc::new(ctx),
                kernel,
                hooks,
                _dir: dir,
            }
        }

        fn nested() -> Self {
            Self::new(FreezeState::Thawed, "nested.txt")
        }

        /// A rig whose freeze operation deadline is `timeout` (real time).
        fn with_operation_timeout(self, timeout: Duration) -> Self {
            let ctx = Arc::try_unwrap(self.ctx)
                .unwrap_or_else(|_| panic!("unshared"))
                .with_freeze_operation_timeout(timeout);
            Rig {
                ctx: Arc::new(ctx),
                ..self
            }
        }

        /// Polls until `done`; the bound only matters on failure and is
        /// generous for a loaded runner (the mutants job).
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
            crate::audit::subscriber(tracing::Level::WARN, router),
            f,
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
        assert!(
            err.to_string().contains("freeze of /home/data failed"),
            "{err}"
        );
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());
        assert!(text.contains("\"event\":\"fsfreeze_rollback\""), "{text}");
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
            "freeze of /home/data failed: EIO: I/O error; rolled back"
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
            "freeze of /home/data failed: EIO: I/O error; rolled back"
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
        assert!(denied.starts_with("first FITHAW denied: EPERM"), "{denied}");
        // ...or after successes: the remaining depth is unknown.
        let denied = drained(2, e(Errno::EACCES), false).incomplete().unwrap();
        assert!(denied.contains("denied after 2 successes"), "{denied}");
        // Any other errno is uncertain: Linux keeps a filesystem frozen
        // when its unfreeze fails.
        let failed = drained(0, e(Errno::EIO), false).incomplete().unwrap();
        assert!(failed.contains("FITHAW failed: EIO"), "{failed}");
        assert!(drained(1, e(Errno::ENOSPC), false).incomplete().is_some());
        // An error from before the ioctl means no FITHAW was issued, so
        // nothing is known about the filesystem: incomplete, whatever the
        // errno, even one that would end a drain as the ioctl's answer.
        let unopened = drained(0, Some(KernelError::Open(Errno::EMFILE)), false)
            .incomplete()
            .unwrap();
        assert!(
            unopened.contains("cannot open mountpoint: EMFILE"),
            "{unopened}"
        );
        assert!(unopened.contains("no FITHAW issued"), "{unopened}");
        for errno in [
            Errno::EINVAL,
            Errno::EOPNOTSUPP,
            Errno::ENOTTY,
            Errno::ENOSYS,
        ] {
            let reason = drained(0, Some(KernelError::Open(errno)), false)
                .incomplete()
                .unwrap_or_else(|| panic!("Open({errno}) must not complete a drain"));
            assert!(reason.contains("no FITHAW issued"), "{reason}");
            let reason = drained(2, Some(KernelError::Open(errno)), false)
                .incomplete()
                .unwrap_or_else(|| {
                    panic!("Open({errno}) after successes must not complete a drain")
                });
            assert!(reason.contains("no FITHAW issued"), "{reason}");
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
        assert!(elsewhere.contains("not on the planned 8:2"), "{elsewhere}");
        assert!(elsewhere.contains("no FITHAW issued"), "{elsewhere}");
        // A drain that never converged is incomplete whatever else happened.
        let capped = drained(u32::MAX, None, true).incomplete().unwrap();
        assert!(capped.contains("did not converge"), "{capped}");
        assert!(capped.contains("still succeeding"), "{capped}");
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
        assert!(
            err.to_string()
                .contains("rollback of /home/data incomplete (FITHAW failed: EIO"),
            "{err}"
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
        // Zero targets is still a successful freeze: the marker exists
        // and the state is Frozen until thawed.
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
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
        assert!(
            err.to_string()
                .contains("thaw of / incomplete: FITHAW failed: EIO"),
            "{err}"
        );
        assert!(err.to_string().contains("marker retained"), "{err}");
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
        assert!(
            err.to_string()
                .contains("no mount point leads to 8:2 (/home: cannot open mountpoint: EMFILE"),
            "{err}"
        );
        assert!(err.to_string().contains("no FITHAW issued"), "{err}");
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
        assert!(
            err.to_string()
                .contains("thaw of / incomplete: first FITHAW denied"),
            "{err}"
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
        assert!(
            err.to_string()
                .contains("did not converge after 1024 FITHAW calls"),
            "{err}"
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
        assert!(
            err.to_string()
                .contains("rollback of /home/data incomplete (first FITHAW denied"),
            "{err}"
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
        assert!(
            err.to_string()
                .contains("rollback of /home/data/deep incomplete"),
            "{err}"
        );
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists(), "marker retained");
        assert_eq!(rig.hooks.events(), ["freezing", "frozen"]);
        // The frozen gate now applies until a thaw drains it.
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("denied: EPERM"), "{err}");
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
        assert!(
            err.to_string()
                .contains("rolled back but cannot remove recovery marker"),
            "{err}"
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
                .any(|c| matches!(c, Call::Fithaw(p) if p == Path::new("/home"))),
            "the watchdog drain still thaws what it can"
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
        // marker and the frozen gate are retained, and the reason names
        // every attempt.
        let rig = Rig::new(FreezeState::Frozen, "bind_mounts.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_mount_device("/data", (8, 9));
        rig.kernel.script_open_error("/srv/exports", Errno::ENOENT);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("thaw of /data incomplete"), "{text}");
        assert!(
            text.contains(
                "no mount point leads to 8:2 (/data: mountpoint is on 8:9, not on the planned 8:2; /srv/exports: cannot open mountpoint: ENOENT"
            ),
            "{text}"
        );
        assert!(text.contains("); no FITHAW issued"), "{text}");
        assert!(text.contains("marker retained"), "{text}");
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
        assert!(
            text.starts_with(
                "freeze of / failed: no mount point leads to it (/: cannot open mountpoint: EACCES"
            ),
            "{text}"
        );
        assert!(
            text.contains("; /var/www: cannot open mountpoint: EACCES"),
            "{text}"
        );
        assert!(
            text.contains("; /mnt/rootbind: cannot open mountpoint: EACCES"),
            "{text}"
        );
        assert!(
            text.ends_with("); no FIFREEZE issued; rolled back"),
            "{text}"
        );
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
        assert!(text.contains("freeze of /home/data failed"), "{text}");
        assert!(
            text.contains("cannot open mountpoint: EOPNOTSUPP"),
            "{text}"
        );
        assert!(text.contains("rolled back"), "{text}");
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
        // The next thaw drains /home through that handle (no reopen) and
        // reopens the targets whose drain completed, since a pathname is
        // all that is left for those.
        rig.kernel.clear_calls();
        let _ = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#)).await;
        let opens = rig.opens();
        assert!(!opens.contains(&PathBuf::from("/home")), "{opens:?}");
        assert!(opens.contains(&PathBuf::from("/")), "{opens:?}");
        assert!(rig.fithaws().contains(&PathBuf::from("/home")));
        assert_eq!(rig.held(), 1);
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
        mounts.fail_reads(true);
        rig.kernel.clear_calls();
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(
            err.to_string().starts_with("cannot build thaw plan: ")
                && err.to_string().contains("Too many open files"),
            "{err}"
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
        assert!(
            err.to_string().starts_with("cannot build thaw plan: "),
            "{err}"
        );
        assert!(rig.kernel.calls().is_empty());
        assert_eq!(rig.state(), FreezeState::Frozen);
        assert!(rig.marker().exists());
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
        mounts.fail_reads(true);
        rig.kernel.script_thaw_error("/home", Errno::EACCES);
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("thaw of /home incomplete: first FITHAW denied: EACCES"),
            "{err}"
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
        assert!(
            err.to_string()
                .starts_with("cannot build thaw plan: cannot read /proc/self/mountinfo:")
                && err.to_string().contains("os error 24"),
            "{err}"
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_completed_target_is_thawed_while_a_later_fifreeze_is_still_blocked() {
        // nested.txt freezes deepest-first: /home/data/deep (A), /home/data
        // (B), /home (C), /. B blocks in the kernel. When the operation
        // deadline expires, A is drained through its handle while B is
        // still blocked, C is never authorised, the request fails, and the
        // marker, the frozen gate and the ring stay until B settles.
        let rig = Rig::nested().with_operation_timeout(Duration::from_millis(200));
        let gate = rig.kernel.script_freeze_gate("/home/data");
        let _release = gate.release_on_drop();
        let started = std::time::Instant::now();
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        assert!(
            err.to_string().contains("deadline")
                && err.to_string().contains("/home/data")
                && err.to_string().contains("marker retained"),
            "{err}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        // The recovery pass over A runs on independent capacity while B
        // is still blocked at the gate.
        rig.wait_for("A drained", |r| {
            r.fithaws() == paths(&["/home/data/deep", "/home/data/deep"])
        })
        .await;
        assert_eq!(gate.waiting(), 1, "B is still inside FIFREEZE");
        assert_eq!(rig.fifreezes(), paths(&["/home/data/deep", "/home/data"]));
        assert_eq!(
            rig.opens(),
            paths(&["/home/data/deep", "/home/data"]),
            "C never authorised"
        );
        assert_eq!(rig.held(), 0, "A's handle was released by its drain");
        assert!(rig.marker().exists(), "unresolved: B may still freeze");
        assert_eq!(rig.state(), FreezeState::Thawing);
        assert!(rig.state().is_frozen_for_gate());
        let value = status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!("frozen"), "status is served meanwhile");
        // A second freeze is refused; nothing new is authorised or spawned.
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot freeze"), "{err}");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed"]);
        // B completes late, successfully: it is accounted to the aborted
        // operation and drained through its own handle, then the marker
        // goes and `Thawed` is published; no `frozen` hook ever fired.
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(
            rig.fithaws(),
            paths(&[
                "/home/data/deep",
                "/home/data/deep",
                "/home/data",
                "/home/data"
            ])
        );
        assert_eq!(
            rig.opens().len(),
            2,
            "no pathname was consulted for the drains"
        );
        assert!(!rig.marker().exists());
        assert_eq!(rig.held(), 0);
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        assert!(rig.ctx.freeze_op().is_none(), "the operation is released");
        // And a new freeze is accepted again.
        let value = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(4));
    }

    /// A mount table whose read blocks at a gate (a slow `/proc` read).
    struct GatedMounts {
        table: String,
        gate: crate::kernel::fake::Gate,
    }

    impl MountSource for GatedMounts {
        fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
            self.gate.wait();
            Ok(self.table.clone().into_bytes())
        }
    }

    /// Freezes nested.txt with B (`/home/data`) blocked at a gate and the
    /// operation deadline at 200 ms; returns the rig, B's gate and the
    /// request's error once the abort has replied.
    async fn aborted_at_b() -> (Rig, crate::kernel::fake::Gate, Error) {
        let rig = Rig::nested().with_operation_timeout(Duration::from_millis(200));
        let gate = rig.kernel.script_freeze_gate("/home/data");
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        rig.wait_for("A drained", |r| {
            r.fithaws() == paths(&["/home/data/deep", "/home/data/deep"])
        })
        .await;
        (rig, gate, err)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_error_after_the_abort_needs_no_recovery_and_ebusy_is_drained() {
        // B fails after the abort: nothing of B is frozen, so nothing is
        // drained for it, and the operation settles `Thawed`.
        let (rig, gate, _) = aborted_at_b().await;
        let _release = gate.release_on_drop();
        rig.kernel.script_freeze_error("/home/data", Errno::EIO);
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data/deep", "/home/data/deep"])
        );
        assert!(!rig.marker().exists());
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        // B answers EBUSY after the abort: retained and drained like any
        // EBUSY target (§4.2), then `Thawed`.
        let (rig, gate, _) = aborted_at_b().await;
        let _release = gate.release_on_drop();
        rig.kernel.script_freeze_error("/home/data", Errno::EBUSY);
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(
            rig.fithaws(),
            paths(&[
                "/home/data/deep",
                "/home/data/deep",
                "/home/data",
                "/home/data"
            ])
        );
        assert!(!rig.marker().exists());
        assert_eq!(rig.held(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expiry_during_preparation_freezes_nothing_and_leaves_no_marker() {
        // The deadline expires while the mount table is still being read:
        // the preparation stays owned to its end, no target is ever
        // authorised, the marker it created is removed, and `Thawed` is
        // published after the finalisation hook.
        let gate = crate::kernel::fake::Gate::new();
        let _release = gate.release_on_drop();
        let mounts = Arc::new(GatedMounts {
            table: fixture("nested.txt"),
            gate: gate.clone(),
        });
        let rig = Rig::with_mounts(FreezeState::Thawed, mounts)
            .with_operation_timeout(Duration::from_millis(100));
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("(preparing)"), "{err}");
        assert_eq!(gate.waiting(), 1, "the preparation is still running");
        assert_eq!(rig.state(), FreezeState::Thawing);
        assert!(rig.kernel.calls().is_empty());
        gate.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert!(rig.kernel.calls().is_empty(), "no ioctl at all");
        assert!(!rig.marker().exists(), "the late marker was removed");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "thawed"]);
        assert!(rig.ctx.freeze_op().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_blocked_recovery_drain_keeps_status_served_and_spawns_nothing_more() {
        // A's FITHAW blocks during the recovery pass: status is still
        // answered, a thaw joins the same pass (no second drain), a freeze
        // is refused, and once the drain returns the joined thaw reports
        // the in-flight target. Resource use stays at one worker and one
        // drain.
        let rig = Rig::nested().with_operation_timeout(Duration::from_millis(200));
        let b = rig.kernel.script_freeze_gate("/home/data");
        let _release_b = b.release_on_drop();
        let a_thaw = rig.kernel.script_thaw_gate("/home/data/deep");
        let _release_a = a_thaw.release_on_drop();
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        rig.wait_for("drain blocked", |_| a_thaw.waiting() == 1)
            .await;
        let value = status(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-status"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!("frozen"));
        let joined = {
            let ctx = Arc::clone(&rig.ctx);
            tokio::spawn(
                async move { thaw(&ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#)).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!joined.is_finished(), "the joined thaw waits for the pass");
        let err = freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot freeze"), "{err}");
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data/deep"]),
            "one drain, blocked"
        );
        assert_eq!(rig.fifreezes().len(), 2, "no new worker");
        a_thaw.release();
        let err = joined.await.unwrap().unwrap_err();
        assert!(
            err.to_string()
                .contains("FIFREEZE of /home/data still in flight")
                && err.to_string().contains("1 target(s) thawed"),
            "{err}"
        );
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data/deep", "/home/data/deep"])
        );
        assert_eq!(b.waiting(), 1);
        b.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert!(!rig.marker().exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_thaw_during_the_walk_aborts_it_and_joins_the_recovery() {
        // No deadline pressure (10 s): the host gives up and sends a thaw
        // while B is still inside FIFREEZE. The thaw aborts the walk, A is
        // drained once, C is never authorised, and both requests report
        // the outcome; a second thaw joins without draining anything again.
        let rig = Rig::nested().with_operation_timeout(Duration::from_secs(10));
        let b = rig.kernel.script_freeze_gate("/home/data");
        let _release_b = b.release_on_drop();
        let freezing = {
            let ctx = Arc::clone(&rig.ctx);
            tokio::spawn(async move {
                freeze(&ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#)).await
            })
        };
        rig.wait_for("B blocked", |_| b.waiting() == 1).await;
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("still in flight"), "{err}");
        let err = freezing.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("thaw requested"), "{err}");
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data/deep", "/home/data/deep"])
        );
        assert_eq!(rig.opens(), paths(&["/home/data/deep", "/home/data"]));
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("still in flight"), "{err}");
        assert_eq!(rig.fithaws().len(), 2, "no duplicate drain");
        assert!(rig.marker().exists());
        b.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Thawed)
            .await;
        assert_eq!(rig.fithaws().len(), 4);
        assert!(!rig.marker().exists());
        // Once settled, a thaw is an ordinary recovery drain again (by
        // pathname over the whole plan; the fake answers one success on
        // the two targets that were never frozen).
        thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(rig.state(), FreezeState::Thawed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_incomplete_recovery_drain_settles_frozen_with_the_marker_and_the_watchdog() {
        // A's FITHAW is denied: the recovery is incomplete, so when B
        // settles the operation publishes `Frozen` (the watchdog hook
        // fires), keeps the marker, and keeps A's handle for the next
        // drain; B itself was thawed.
        let rig = Rig::nested().with_operation_timeout(Duration::from_millis(200));
        let b = rig.kernel.script_freeze_gate("/home/data");
        let _release_b = b.release_on_drop();
        rig.kernel
            .script_thaw_error("/home/data/deep", Errno::EACCES);
        freeze(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-freeze"}"#))
            .await
            .unwrap_err();
        rig.wait_for("A's drain attempted", |r| {
            r.fithaws() == paths(&["/home/data/deep"])
        })
        .await;
        b.release();
        rig.wait_for("settled", |r| r.state() == FreezeState::Frozen)
            .await;
        assert_eq!(
            rig.fithaws(),
            paths(&["/home/data/deep", "/home/data", "/home/data"])
        );
        assert!(rig.marker().exists());
        assert_eq!(rig.held(), 1, "A's handle is kept for the next drain");
        assert_eq!(rig.hooks.events(), ["freezing", "thaw_claimed", "frozen"]);
        assert!(rig.ctx.freeze_op().is_none());
        // The next thaw is an ordinary one from `Frozen`: it retries A
        // through the kept handle (still denied here) and reports it.
        let err = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("/home/data/deep"), "{err}");
        assert_eq!(rig.state(), FreezeState::Frozen);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_commands_during_an_unresolved_operation_add_no_work() {
        let (rig, gate, _) = aborted_at_b().await;
        let _release = gate.release_on_drop();
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
}
