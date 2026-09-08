//! The freeze operation coordinator (design §4.4 "Operation deadline";
//! OQ-8, T6.1).
//!
//! A `guest-fsfreeze-freeze` request no longer runs its whole walk inside
//! one blocking closure whose result the request waits for. It starts an
//! *operation* that owns the walk independently of the request and of the
//! channel:
//!
//! 1. Preparation (mount table, marker) runs as a tracked blocking task.
//! 2. Targets are frozen one at a time, each `FIFREEZE` on its own tracked
//!    blocking task; a completed target's verified handle is published to
//!    the [`Context`] before the next target is authorised. A worker
//!    re-checks the abort flag right before its ioctl, so work queued at
//!    the moment of an abort never freezes anything.
//! 3. The operation has an immutable deadline, `fsfreeze_operation_timeout_secs`
//!    from the moment the request entered `Freezing`; heartbeats do not
//!    extend it. When it expires, or when a thaw is requested while the
//!    walk is under way, the abort commits exactly once: no further
//!    target is authorised, the freeze token becomes a thaw token
//!    (`Freezing → Thawing`, so a late completion can never publish
//!    `Frozen`), the request gets its one reply (an error), and the
//!    targets frozen so far are drained on a blocking task of their own,
//!    independent of the worker still blocked in `FIFREEZE`.
//! 4. Every authorised worker is awaited to its end. A late success (or
//!    `EBUSY`) is drained through the handle it opened; a late error needs
//!    nothing; a worker that panicked leaves its target uncertain.
//! 5. The operation settles only when no worker is outstanding and every
//!    published handle has been drained: complete → marker removed,
//!    finalisation hook, `Thawed`; a drain incomplete or the marker not
//!    removable → `Frozen`, marker retained, the watchdog armed as on any
//!    entry into that state, the incomplete handles kept for it. Until
//!    then the marker, the frozen gate and the freeze-safe audit mode stay.
//!
//! Capacity is explicit: per operation at most one freeze worker, one
//! recovery drain and the preparation task exist at any time, and the state
//! machine admits one operation at a time. No coordinator mutex is held
//! across an `.await` or a blocking call: the driver task owns its state
//! and publishes snapshots through a `watch` channel.
//!
//! The thaw walk itself is not bounded here: a `FITHAW` that blocks holds
//! its drain (and the operation) until it returns; see §4.4.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::{Instant, sleep_until};
use tracing::instrument::WithSubscriber;

use crate::dispatch::Context;
use crate::freeze_plan::{FreezePlan, Target};
use crate::handlers::fsfreeze::{
    FreezeFailure, FreezeStop, build_plan, drain_held, open_target, rollback,
};
use crate::kernel::{KernelOps, Mount};
use crate::marker::{Marker, MarkerError};
use crate::state::{FreezeState, FreezeToken, ThawToken};

/// Where an operation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Targets are being authorised and frozen.
    Freezing,
    /// The abort committed: no further target is authorised; completed
    /// targets are being drained while outstanding work settles.
    Recovering,
    /// Everything settled; `settled` names the state that was published.
    Settled,
}

/// Why an operation was aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortCause {
    /// The operation deadline expired.
    Deadline,
    /// A `guest-fsfreeze-thaw` arrived while the walk was under way.
    ThawRequested,
}

impl std::fmt::Display for AbortCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AbortCause::Deadline => "operation deadline expired",
            AbortCause::ThawRequested => "thaw requested",
        })
    }
}

/// A snapshot of an operation, published to waiters after every change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Where the operation stands.
    pub phase: Phase,
    /// Successful `FIFREEZE` calls so far.
    pub frozen: u64,
    /// The target whose `FIFREEZE` is outstanding (`"(preparing)"` while
    /// the plan and the marker are being prepared).
    pub in_flight: Option<String>,
    /// `true` while a recovery drain is running.
    pub draining: bool,
    /// Published handles not yet handed to a drain.
    pub awaiting_drain: usize,
    /// Targets on which a recovery drain succeeded at least once.
    pub recovered: u64,
    /// A drain that did not complete (target and reason).
    pub unrecoverable: Option<String>,
    /// The state published when the operation settled.
    pub settled: Option<FreezeState>,
}

impl Progress {
    fn initial() -> Self {
        Progress {
            phase: Phase::Freezing,
            frozen: 0,
            in_flight: Some("(preparing)".to_owned()),
            draining: false,
            awaiting_drain: 0,
            recovered: 0,
            unrecoverable: None,
            settled: None,
        }
    }

    /// `true` once the completed targets have had their recovery drain
    /// (nothing held, no drain running) or the operation has settled: what
    /// a thaw that joins the operation waits for.
    pub fn recovery_pass_done(&self) -> bool {
        self.settled.is_some()
            || (self.phase == Phase::Recovering && !self.draining && self.awaiting_drain == 0)
    }
}

/// One freeze operation, shared between the driver task, the request that
/// started it and any thaw that joins it. Held in the [`Context`] until it
/// settles.
#[derive(Debug)]
pub struct FreezeOp {
    deadline: Instant,
    abort_requested: Notify,
    aborted: Arc<AtomicBool>,
    progress: watch::Sender<Progress>,
}

impl FreezeOp {
    /// Asks the operation to stop authorising targets and to recover the
    /// ones frozen so far (a thaw request). Idempotent; a request that
    /// arrives before the driver waits is not lost.
    pub fn request_abort(&self) {
        self.abort_requested.notify_one();
    }

    /// The latest snapshot.
    pub fn progress(&self) -> Progress {
        self.progress.borrow().clone()
    }

    /// `true` once the operation has settled and released its slot.
    pub fn is_settled(&self) -> bool {
        self.progress.borrow().settled.is_some()
    }

    /// Waits until the recovery pass over the completed targets is done
    /// or the operation has settled (see [`Progress::recovery_pass_done`]).
    pub async fn wait_for_recovery_pass(&self) -> Progress {
        let mut rx = self.progress.subscribe();
        match rx.wait_for(Progress::recovery_pass_done).await {
            Ok(progress) => progress.clone(),
            Err(_) => self.progress(),
        }
    }

    /// Waits until the operation has settled.
    pub async fn wait_for_settlement(&self) -> Progress {
        let mut rx = self.progress.subscribe();
        match rx.wait_for(|p| p.settled.is_some()).await {
            Ok(progress) => progress.clone(),
            Err(_) => self.progress(),
        }
    }

    fn publish(&self, update: impl FnOnce(&mut Progress)) {
        self.progress.send_modify(update);
    }
}

/// Starts an operation: installs it in `ctx`, spawns the driver, and
/// returns the receiver of the request's single reply. `token` proves the
/// caller moved the machine into `Freezing`; the driver consumes it.
pub(crate) fn start(
    ctx: Arc<Context>,
    token: FreezeToken,
    restrict: Option<Vec<String>>,
) -> oneshot::Receiver<Result<u64, FreezeFailure>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let (progress, _) = watch::channel(Progress::initial());
    let op = Arc::new(FreezeOp {
        deadline: Instant::now() + ctx.freeze_operation_timeout(),
        abort_requested: Notify::new(),
        aborted: Arc::new(AtomicBool::new(false)),
        progress,
    });
    ctx.set_freeze_op(Some(Arc::clone(&op)));
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let driver = Driver {
        kernel: Arc::clone(&ctx.kernel),
        marker: ctx.marker.clone(),
        ctx,
        op,
        dispatch: dispatch.clone(),
        token: Some(token),
        thaw_token: None,
        reply: Some(reply_tx),
        frozen: 0,
        recovered: 0,
        recovery: None,
        kept: Vec::new(),
        unrecoverable: None,
        abort: None,
        timeout: Duration::ZERO,
    };
    tokio::spawn(driver.drive(restrict).with_subscriber(dispatch));
    reply_rx
}

/// What one target's worker found.
enum TargetOutcome {
    /// `FIFREEZE` succeeded; the handle is to be drained later.
    Frozen(Mount),
    /// `EBUSY`: frozen by another freezer; retained for the drain (§4.2).
    Busy(Mount),
    /// `EOPNOTSUPP`: skipped.
    Skipped,
    /// The abort committed before the ioctl: nothing was issued.
    NotAuthorized,
    /// A hard error, or no mount point leads to the target.
    Failed(FreezeStop),
}

/// The result of a recovery drain over published handles.
struct RecoveryPass {
    recovered: u64,
    keep: Vec<Mount>,
    incomplete: Option<(String, String)>,
}

/// What ended a tracked wait.
enum Event<T> {
    Done(Result<T, JoinError>),
    Recovered(Result<RecoveryPass, JoinError>),
    Abort(AbortCause),
}

struct Driver {
    ctx: Arc<Context>,
    op: Arc<FreezeOp>,
    kernel: Arc<dyn KernelOps>,
    marker: Marker,
    dispatch: tracing::Dispatch,
    token: Option<FreezeToken>,
    thaw_token: Option<ThawToken>,
    reply: Option<oneshot::Sender<Result<u64, FreezeFailure>>>,
    frozen: u64,
    recovered: u64,
    /// The recovery drain in flight, if any (at most one).
    recovery: Option<JoinHandle<RecoveryPass>>,
    /// Handles whose drain did not complete, kept for the watchdog.
    kept: Vec<Mount>,
    unrecoverable: Option<(String, String)>,
    abort: Option<AbortCause>,
    timeout: Duration,
}

impl Driver {
    async fn drive(mut self, restrict: Option<Vec<String>>) {
        self.timeout = self.ctx.freeze_operation_timeout();
        // Preparation: the plan, then the marker; both tracked.
        let mounts = Arc::clone(&self.ctx.mounts);
        let marker = self.marker.clone();
        let prep = self.spawn_blocking(move || {
            let plan = build_plan::<FreezeFailure>(mounts.as_ref(), restrict.as_deref())?;
            marker.create()?;
            Ok::<FreezePlan, FreezeFailure>(plan)
        });
        let plan = match self.await_tracked(prep, true).await {
            Ok(Ok(plan)) => plan,
            Ok(Err(failure)) => return self.settle_before_ioctl(failure).await,
            Err(err) => {
                // Whether the marker was created is unknown; its removal
                // below tolerates its absence.
                return self
                    .settle_before_ioctl(FreezeFailure::Task(err.to_string()))
                    .await;
            }
        };
        if self.abort.is_some() {
            return self.settle_aborted().await;
        }
        for target in plan.freeze_order() {
            if self.abort.is_some() {
                break;
            }
            let mountpoint = target.mountpoint.to_string_lossy().into_owned();
            self.op.publish(|p| p.in_flight = Some(mountpoint.clone()));
            let worker = self.spawn_freeze(target.clone());
            let outcome = self.await_tracked(worker, true).await;
            self.op.publish(|p| p.in_flight = None);
            match outcome {
                Ok(TargetOutcome::Frozen(mount)) => {
                    self.frozen += 1;
                    self.ctx.hold_frozen_mounts(vec![mount]);
                    let frozen = self.frozen;
                    self.op.publish(|p| {
                        p.frozen = frozen;
                        p.awaiting_drain += 1;
                    });
                }
                Ok(TargetOutcome::Busy(mount)) => {
                    tracing::warn!(
                        event = "fsfreeze_busy",
                        mountpoint = %mountpoint,
                        "already frozen by another freezer; retained for thaw"
                    );
                    self.ctx.hold_frozen_mounts(vec![mount]);
                    self.op.publish(|p| p.awaiting_drain += 1);
                }
                Ok(TargetOutcome::Skipped) => {
                    tracing::info!(event = "fsfreeze_skipped", mountpoint = %mountpoint, "freeze not supported; skipped");
                }
                Ok(TargetOutcome::NotAuthorized) => {
                    tracing::debug!(event = "fsfreeze_not_authorized", mountpoint = %mountpoint, "abort committed before the ioctl; nothing issued");
                }
                Ok(TargetOutcome::Failed(stop)) => {
                    if self.abort.is_none() {
                        return self.settle_hard_error(mountpoint, stop).await;
                    }
                    tracing::warn!(event = "fsfreeze_late_failure", mountpoint = %mountpoint, cause = %stop, "target failed after the abort; nothing to recover for it");
                }
                Err(err) => {
                    // The worker panicked or was cancelled with the runtime:
                    // the target may or may not be frozen and no handle
                    // survived. Conservative: unrecoverable, so the
                    // operation settles `Frozen` and the watchdog's drain
                    // by pathname reaches it.
                    tracing::error!(event = "fsfreeze_worker_lost", mountpoint = %mountpoint, error = %err, "freeze worker lost; target uncertain");
                    self.unrecoverable.get_or_insert((
                        mountpoint.clone(),
                        format!("freeze worker lost ({err}); FIFREEZE outcome unknown"),
                    ));
                    if self.abort.is_none() {
                        self.commit_abort(AbortCause::Deadline);
                        break;
                    }
                }
            }
        }
        if self.abort.is_some() {
            return self.settle_aborted().await;
        }
        // Every target processed without a hard error: `Frozen`.
        if let Some(token) = self.token.take() {
            self.ctx.state.freeze_succeeded(token);
        }
        self.ctx.hooks.on_frozen(&self.ctx);
        tracing::info!(
            event = "fsfreeze_frozen",
            frozen = self.frozen,
            "filesystems frozen"
        );
        self.reply(Ok(self.frozen));
        self.finish(FreezeState::Frozen);
    }

    /// Spawns a blocking task whose records go to the request's subscriber.
    fn spawn_blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> JoinHandle<T> {
        let dispatch = self.dispatch.clone();
        tokio::task::spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, f))
    }

    /// The worker for one target: open it on its planned device, re-check
    /// the abort flag, then `FIFREEZE`.
    fn spawn_freeze(&self, target: Target) -> JoinHandle<TargetOutcome> {
        let kernel = Arc::clone(&self.kernel);
        let aborted = Arc::clone(&self.op.aborted);
        self.spawn_blocking(move || {
            let mount = match open_target(kernel.as_ref(), &target) {
                Ok(mount) => mount,
                Err(attempts) => {
                    return TargetOutcome::Failed(FreezeStop::Unreachable(attempts));
                }
            };
            // The last check before the destructive call: an abort that
            // committed while this worker was queued freezes nothing.
            if aborted.load(Ordering::SeqCst) {
                return TargetOutcome::NotAuthorized;
            }
            match kernel.fifreeze(&mount) {
                Ok(()) => TargetOutcome::Frozen(mount),
                Err(err) if err.is_not_supported() => TargetOutcome::Skipped,
                Err(err) if err.is_busy() => TargetOutcome::Busy(mount),
                Err(err) => TargetOutcome::Failed(FreezeStop::Ioctl(err)),
            }
        })
    }

    /// Awaits a tracked task to its end. Meanwhile, when `abortable`, the
    /// deadline or a thaw request commits the abort (once), and a running
    /// recovery drain is collected and, if more handles were published,
    /// followed by another. The task itself is never abandoned.
    async fn await_tracked<T>(
        &mut self,
        mut task: JoinHandle<T>,
        abortable: bool,
    ) -> Result<T, JoinError> {
        loop {
            let event = {
                let recovery = &mut self.recovery;
                let op = &self.op;
                let armed = abortable && self.abort.is_none();
                tokio::select! {
                    biased;
                    res = &mut task => Event::Done(res),
                    res = async {
                        match recovery.as_mut() {
                            Some(drain) => drain.await,
                            None => std::future::pending().await,
                        }
                    } => Event::Recovered(res),
                    cause = abort_signal(op), if armed => Event::Abort(cause),
                }
            };
            match event {
                Event::Done(res) => return res,
                Event::Recovered(res) => {
                    self.recovery = None;
                    self.record_recovery(res);
                    self.start_recovery_if_needed();
                }
                Event::Abort(cause) => self.commit_abort(cause),
            }
        }
    }

    /// The abort commits: no further target is authorised, the freeze
    /// token becomes the recovery's thaw token, the request gets its one
    /// reply, and the completed targets get their drain now.
    fn commit_abort(&mut self, cause: AbortCause) {
        if self.abort.is_some() {
            return;
        }
        self.abort = Some(cause);
        self.op.aborted.store(true, Ordering::SeqCst);
        if let Some(token) = self.token.take() {
            self.thaw_token = Some(self.ctx.state.abort_freeze(token));
        }
        self.ctx.hooks.on_thaw_claimed(&self.ctx);
        let in_flight = self.op.progress().in_flight;
        tracing::error!(
            event = "fsfreeze_aborted",
            cause = %cause,
            frozen = self.frozen,
            in_flight = in_flight.as_deref().unwrap_or("-"),
            "freeze aborted; recovering the targets frozen so far"
        );
        self.reply(Err(FreezeFailure::Aborted {
            cause,
            timeout_secs: self.timeout.as_secs(),
            frozen: self.frozen,
            in_flight,
        }));
        self.op.publish(|p| p.phase = Phase::Recovering);
        self.start_recovery_if_needed();
    }

    /// Starts a recovery drain over the published handles unless one is
    /// running or there is nothing to drain. At most one drain exists.
    fn start_recovery_if_needed(&mut self) {
        if self.recovery.is_some() {
            return;
        }
        let held = self.ctx.take_frozen_mounts();
        if held.is_empty() {
            return;
        }
        let kernel = Arc::clone(&self.kernel);
        self.op.publish(|p| {
            p.draining = true;
            p.awaiting_drain = 0;
        });
        self.recovery = Some(self.spawn_blocking(move || {
            let (recovered, keep, incomplete) = drain_held(kernel.as_ref(), held);
            RecoveryPass {
                recovered,
                keep,
                incomplete,
            }
        }));
    }

    fn record_recovery(&mut self, res: Result<RecoveryPass, JoinError>) {
        match res {
            Ok(pass) => {
                self.recovered += pass.recovered;
                if let Some(incomplete) = pass.incomplete {
                    self.unrecoverable.get_or_insert(incomplete);
                }
                self.kept.extend(pass.keep);
            }
            Err(err) => {
                // The drain's handles are lost with it; the targets stay
                // uncertain and the watchdog's drain by pathname follows.
                tracing::error!(event = "fsfreeze_drain_lost", error = %err, "recovery drain lost; targets uncertain");
                self.unrecoverable.get_or_insert((
                    "(recovery drain)".to_owned(),
                    format!("recovery drain lost ({err})"),
                ));
            }
        }
        let recovered = self.recovered;
        let unrecoverable = self
            .unrecoverable
            .as_ref()
            .map(|(mountpoint, reason)| format!("{mountpoint}: {reason}"));
        self.op.publish(|p| {
            p.draining = false;
            p.recovered = recovered;
            p.unrecoverable = unrecoverable;
        });
    }

    /// Nothing was frozen (the plan or the marker failed, or the
    /// preparation was lost): `Thawed` after finalisation, the marker
    /// removed if it exists; aborted or not.
    async fn settle_before_ioctl(mut self, failure: FreezeFailure) {
        tracing::warn!(event = "fsfreeze_failed", error = %failure, "freeze failed before any ioctl");
        if self.abort.is_some() {
            self.settle_aborted().await;
            return;
        }
        // No ioctl was issued, so the marker exists only if its creation
        // succeeded and something later failed; `Task` is the one such
        // case, and a marker that cannot be removed retains the state.
        if matches!(failure, FreezeFailure::Task(_)) {
            let marker = self.marker.clone();
            let removed = self
                .await_tracked(self.spawn_blocking(move || marker.remove()), false)
                .await;
            if let Ok(Err(err)) = removed
                && !matches!(err, MarkerError::Absent { .. })
            {
                self.settle_frozen(FreezeFailure::MarkerRetained {
                    failed: "(preparation)".to_owned(),
                    cause: FreezeStop::Unreachable(failure.to_string()),
                    marker: err,
                });
                return;
            }
        }
        self.ctx.hooks.on_thawed(&self.ctx);
        if let Some(token) = self.token.take() {
            self.ctx.state.freeze_failed(token);
        }
        self.reply(Err(failure));
        self.finish(FreezeState::Thawed);
    }

    /// A hard error while not aborted: roll back the published handles,
    /// then `Thawed`, or `Frozen` when the rollback is incomplete or the
    /// marker stays (§4.2).
    async fn settle_hard_error(mut self, failed: String, stop: FreezeStop) {
        let kernel = Arc::clone(&self.kernel);
        let marker = self.marker.clone();
        let mut held = self.ctx.take_frozen_mounts();
        let rolled = self
            .await_tracked(
                self.spawn_blocking(move || {
                    let failure = rollback(
                        kernel.as_ref(),
                        &marker,
                        &mut held,
                        std::path::Path::new(&failed),
                        stop,
                    );
                    (failure, held)
                }),
                false,
            )
            .await;
        let failure = match rolled {
            Ok((failure, keep)) => {
                self.ctx.hold_frozen_mounts(keep);
                failure
            }
            Err(err) => FreezeFailure::Task(format!("rollback lost: {err}")),
        };
        if failure.retains_frozen_state() || matches!(failure, FreezeFailure::Task(_)) {
            tracing::error!(event = "fsfreeze_failed_frozen", error = %failure, "freeze failed and the rollback is incomplete; staying frozen");
            self.settle_frozen(failure);
            return;
        }
        // Finalise first, publish `Thawed` last (see `FreezeHooks::on_thawed`).
        self.ctx.hooks.on_thawed(&self.ctx);
        if let Some(token) = self.token.take() {
            self.ctx.state.freeze_failed(token);
        }
        tracing::warn!(event = "fsfreeze_failed", error = %failure, "freeze failed");
        self.reply(Err(failure));
        self.finish(FreezeState::Thawed);
    }

    /// `Frozen` with the marker retained, from `Freezing` (token) or from
    /// the aborted recovery (thaw token); the watchdog is armed as on any
    /// entry into `Frozen`.
    fn settle_frozen(mut self, failure: FreezeFailure) {
        if let Some(token) = self.token.take() {
            self.ctx.state.freeze_succeeded(token);
        } else if let Some(thaw) = self.thaw_token.take() {
            self.ctx.state.thaw_failed(thaw);
        }
        self.ctx.hooks.on_frozen(&self.ctx);
        self.reply(Err(failure));
        self.finish(FreezeState::Frozen);
    }

    /// The abort committed and every worker has settled: drain what was
    /// published since the last pass, then finalise.
    async fn settle_aborted(mut self) {
        loop {
            if let Some(drain) = self.recovery.take() {
                let res = drain.await;
                self.record_recovery(res);
            }
            self.start_recovery_if_needed();
            if self.recovery.is_none() {
                break;
            }
        }
        if let Some((mountpoint, reason)) = self.unrecoverable.take() {
            tracing::error!(event = "fsfreeze_recovery_incomplete", mountpoint = %mountpoint, reason = %reason, "recovery incomplete; marker retained");
            let kept = std::mem::take(&mut self.kept);
            self.ctx.hold_frozen_mounts(kept);
            if let Some(thaw) = self.thaw_token.take() {
                self.ctx.state.thaw_failed(thaw);
            }
            self.ctx.hooks.on_frozen(&self.ctx);
            self.finish(FreezeState::Frozen);
            return;
        }
        let marker = self.marker.clone();
        let removed = self
            .await_tracked(self.spawn_blocking(move || marker.remove()), false)
            .await;
        match removed {
            Ok(Ok(())) | Ok(Err(MarkerError::Absent { .. })) => {
                self.ctx.hooks.on_thawed(&self.ctx);
                if let Some(thaw) = self.thaw_token.take() {
                    self.ctx.state.thaw_succeeded(thaw);
                }
                tracing::info!(
                    event = "fsfreeze_recovered",
                    recovered = self.recovered,
                    "aborted freeze recovered; thawed"
                );
                self.finish(FreezeState::Thawed);
            }
            Ok(Err(err)) => {
                tracing::error!(event = "fsfreeze_marker_retained", error = %err, "recovery drained but the marker cannot be removed; staying frozen");
                if let Some(thaw) = self.thaw_token.take() {
                    self.ctx.state.thaw_failed(thaw);
                }
                self.ctx.hooks.on_frozen(&self.ctx);
                self.finish(FreezeState::Frozen);
            }
            Err(err) => {
                tracing::error!(event = "fsfreeze_marker_retained", error = %err, "marker removal lost; staying frozen");
                if let Some(thaw) = self.thaw_token.take() {
                    self.ctx.state.thaw_failed(thaw);
                }
                self.ctx.hooks.on_frozen(&self.ctx);
                self.finish(FreezeState::Frozen);
            }
        }
    }

    /// Sends the request's single reply; later calls are no-ops.
    fn reply(&mut self, outcome: Result<u64, FreezeFailure>) {
        if let Some(tx) = self.reply.take() {
            // The requester may be gone (channel lost): nothing to deliver.
            let _ = tx.send(outcome);
        }
    }

    /// Releases the operation's slot and publishes its settlement.
    fn finish(&mut self, state: FreezeState) {
        self.ctx.set_freeze_op(None);
        self.op.publish(|p| {
            p.phase = Phase::Settled;
            p.in_flight = None;
            p.settled = Some(state);
        });
    }
}

/// Resolves when the deadline passes or an abort is requested.
async fn abort_signal(op: &FreezeOp) -> AbortCause {
    tokio::select! {
        biased;
        () = op.abort_requested.notified() => AbortCause::ThawRequested,
        () = sleep_until(op.deadline) => AbortCause::Deadline,
    }
}
