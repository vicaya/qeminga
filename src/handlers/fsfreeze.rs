//! `guest-fsfreeze-freeze`, `guest-fsfreeze-freeze-list`,
//! `guest-fsfreeze-thaw`, `guest-fsfreeze-status` (design §3, §4.2, §4.4;
//! AC2, AC9, AC10, AC17; OQ-3; C-12).
//!
//! # Freeze
//!
//! 1. Claim `Thawed → Freezing` (a token proves ownership).
//! 2. [`FreezeHooks::on_freezing`] (T3.6 switches audit output to the
//!    freeze-safe ring here; synchronous, no I/O).
//! 3. On the blocking pool: build the plan from `mountinfo`, create the
//!    recovery marker (`O_EXCL` + `fsync`), then for each target in
//!    reverse mount order open it on its planned device (the first of its
//!    mount points that still leads there; the kernel shim verifies the
//!    descriptor) and `FIFREEZE` it. Marker failure → no ioctl at all.
//!    - `EOPNOTSUPP`: skipped, not counted, not rolled back.
//!    - `EBUSY`: not counted, but its handle is kept for rollback/thaw.
//!    - any other errno, or no mount point leading to the target: hard
//!      error → every processed target is drained through its handle in
//!      forward order, then the marker is removed.
//!
//!    The handles of the frozen targets are held in the [`Context`] until
//!    their drain completes: a handle names the filesystem it was opened
//!    on, whatever its pathnames lead to later.
//! 4. Success: `Freezing → Frozen`, [`FreezeHooks::on_frozen`] (T3.5 arms
//!    the watchdog). Failure: `Freezing → Thawed`,
//!    [`FreezeHooks::on_thawed`].
//!
//! # Thaw
//!
//! `claim_thaw` (from `Frozen`, or from `Thawed` as a recovery drain),
//! [`FreezeHooks::on_thaw_claimed`] (T3.5 cancels the watchdog), then on
//! the blocking pool: rebuild the plan and, for every target in forward
//! order, issue `FITHAW` until it fails, counting the target once when at
//! least one call succeeded; the marker is removed only after every
//! drain. A target is drained through the handle its freeze opened when
//! this process holds one, otherwise (recovery after a restart) through
//! the first of its mount points that still opens on its device. Any
//! drain that does not end on the kernel's "not frozen" answer, a target
//! that cannot be reached, or a marker removal failure is unrecoverable
//! (OQ-3): `Thawing → Frozen`, marker kept. Otherwise `Thawing → Thawed`
//! and [`FreezeHooks::on_thawed`] (T3.6 flushes the ring).
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

/// `guest-fsfreeze-thaw`: drains every planned filesystem.
pub async fn thaw(ctx: &Arc<Context>, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    let token = ctx
        .state
        .claim_thaw()
        .map_err(|err| Error::Internal(format!("cannot thaw: {err}")))?;
    let count = run_thaw(ctx, token).await?;
    Ok(json!(count))
}

/// The freeze algorithm shared by `freeze` and `freeze-list`.
async fn run_freeze(ctx: &Arc<Context>, restrict: Option<Vec<String>>) -> Result<Value, Error> {
    let token = ctx
        .state
        .begin_freeze()
        .map_err(|err| Error::Internal(format!("cannot freeze: {err}")))?;
    ctx.hooks.on_freezing(ctx);

    let kernel = Arc::clone(&ctx.kernel);
    let mounts = Arc::clone(&ctx.mounts);
    let marker = ctx.marker.clone();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let (outcome, held) = tokio::task::spawn_blocking(move || {
        // Records emitted on the blocking thread go to the same subscriber
        // as the request that started the freeze.
        tracing::dispatcher::with_default(&dispatch, || {
            let mut held = Vec::new();
            let outcome = build_plan::<FreezeFailure>(mounts.as_ref(), restrict.as_deref())
                .and_then(|plan| freeze_blocking(kernel.as_ref(), &marker, &plan, &mut held));
            (outcome, held)
        })
    })
    .await
    .unwrap_or_else(|err| (Err(FreezeFailure::Task(err.to_string())), Vec::new()));
    // The handles the freeze opened are what a later thaw drains: each
    // names the filesystem it was opened on, whatever its pathnames lead
    // to by then. Kept before any state is published.
    ctx.hold_frozen_mounts(held);

    match outcome {
        Ok(frozen) => {
            ctx.state.freeze_succeeded(token);
            ctx.hooks.on_frozen(ctx);
            tracing::info!(event = "fsfreeze_frozen", frozen, "filesystems frozen");
            Ok(json!(frozen))
        }
        Err(failure) if failure.retains_frozen_state() => {
            // A filesystem may still be frozen (the rollback was denied or
            // stopped at the drain bound) or the marker could not be
            // removed: keep the frozen gate and the marker so a later
            // thaw, the watchdog or a restart in recovery mode drains it.
            ctx.state.freeze_succeeded(token);
            ctx.hooks.on_frozen(ctx);
            tracing::error!(event = "fsfreeze_failed_frozen", error = %failure, "freeze failed and the rollback is incomplete; staying frozen");
            Err(Error::Internal(failure.to_string()))
        }
        Err(failure) => {
            // Finalise first, publish `Thawed` last (see `on_thawed`).
            ctx.hooks.on_thawed(ctx);
            ctx.state.freeze_failed(token);
            tracing::warn!(event = "fsfreeze_failed", error = %failure, "freeze failed");
            Err(Error::Internal(failure.to_string()))
        }
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
            let outcome = build_plan::<ThawFailure>(mounts.as_ref(), None)
                .and_then(|plan| thaw_blocking(kernel.as_ref(), &marker, &plan, &mut held));
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

fn build_plan<E: From<String>>(
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
fn open_target(kernel: &dyn KernelOps, target: &Target) -> Result<Mount, String> {
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

/// Marker, then `FIFREEZE` in reverse mount order, with rollback on a hard
/// error. Returns the number of successful `FIFREEZE` calls; `held`
/// receives the handles of every processed target (successes and
/// `EBUSY`), which the thaw drains later, or after a rollback only those
/// whose drain did not complete.
fn freeze_blocking(
    kernel: &dyn KernelOps,
    marker: &Marker,
    plan: &FreezePlan,
    held: &mut Vec<Mount>,
) -> Result<u64, FreezeFailure> {
    marker.create()?;
    let mut frozen: u64 = 0;
    for target in plan.freeze_order() {
        let mountpoint = target.mountpoint.as_path();
        let mount = match open_target(kernel, target) {
            Ok(mount) => mount,
            Err(attempts) => {
                let stop = FreezeStop::Unreachable(attempts);
                return Err(rollback(kernel, marker, held, mountpoint, stop));
            }
        };
        match kernel.fifreeze(&mount) {
            Ok(()) => {
                frozen += 1;
                held.push(mount);
            }
            Err(err) if err.is_not_supported() => {
                tracing::info!(event = "fsfreeze_skipped", mountpoint = %mountpoint.display(), errno = %err, "freeze not supported; skipped");
            }
            Err(err) if err.is_busy() => {
                tracing::warn!(
                    event = "fsfreeze_busy",
                    mountpoint = %mountpoint.display(),
                    "already frozen by another freezer; retained for thaw"
                );
                held.push(mount);
            }
            Err(err) => {
                return Err(rollback(
                    kernel,
                    marker,
                    held,
                    mountpoint,
                    FreezeStop::Ioctl(err),
                ));
            }
        }
    }
    Ok(frozen)
}

/// Drains every processed target through the handle its freeze opened, in
/// forward mount order, then removes the marker; `held` keeps the handles
/// whose drain did not complete. Every processed target gets its drain,
/// as in [`thaw_blocking`]: one that cannot be thawed is remembered and
/// reported afterwards, and must not leave the later ones frozen until a
/// recovery. Returns the failure to report.
fn rollback(
    kernel: &dyn KernelOps,
    marker: &Marker,
    held: &mut Vec<Mount>,
    failed: &Path,
    cause: FreezeStop,
) -> FreezeFailure {
    let mut incomplete: Option<(String, String)> = None;
    let mut keep = Vec::new();
    // `held` was filled in reverse mount order, so reverse it back.
    for mount in std::mem::take(held).into_iter().rev() {
        let drained = drain(kernel, &mount);
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
/// An unrecoverable failure on one target (OQ-3: anything but the
/// kernel's "not frozen" answer, see [`Drained::incomplete`], or a
/// superblock that cannot be reached at all) does not stop the drain of
/// the later targets: everything that can be thawed is thawed first
/// (§4.2), then the first such failure is reported and the marker is
/// retained.
fn thaw_blocking(
    kernel: &dyn KernelOps,
    marker: &Marker,
    plan: &FreezePlan,
    held: &mut Vec<Mount>,
) -> Result<u64, ThawFailure> {
    let mut state = ThawState::default();
    let mut retained = std::mem::take(held);
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
    for mount in retained {
        tracing::warn!(
            event = "fsfreeze_unplanned_drain",
            mountpoint = %mount.mountpoint().display(),
            "frozen by this process but no longer in the plan; drained"
        );
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

    impl Rig {
        fn new(state: FreezeState, mountinfo: &str) -> Self {
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
            .with_mounts(Arc::new(StaticMounts(fixture(mountinfo))))
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
}
