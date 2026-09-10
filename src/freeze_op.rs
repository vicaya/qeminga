//! The freeze operation coordinator (design §4.4 "Operation deadline";
//! OQ-8, T6.1).
//!
//! A `guest-fsfreeze-freeze` request does not run its walk inside one
//! blocking closure whose result the request waits for. It starts an
//! *operation* that owns the walk independently of the request and of the
//! channel:
//!
//! 1. Preparation (mount table, marker) runs as a tracked blocking task.
//! 2. Targets are frozen one at a time, each `FIFREEZE` on its own tracked
//!    blocking task; a completed target's verified handle is published to
//!    the [`Context`] before the next target is authorised.
//! 3. The operation has an immutable deadline, `fsfreeze_operation_timeout_secs`
//!    from the moment the request entered `Freezing`, read from an
//!    injected [`FreezeClock`]; heartbeats do not extend it. The abort
//!    decision (deadline passed, or a thaw requested) is taken at every
//!    boundary, not only while waiting: before each target is authorised,
//!    by the worker right before its ioctl, while a worker is awaited
//!    (the abort branch is polled ahead of a completion, so a chain of
//!    ready completions cannot postpone a pending abort), and before a
//!    successful completion is committed. The worker's check is its last
//!    opportunity, not a boundary with the syscall: a worker past it is
//!    owned, and whatever it returns is recovered.
//! 4. When the abort commits (exactly once): no further target is
//!    authorised, the freeze token becomes a thaw token (`Freezing →
//!    Thawing`, so a late completion can never publish `Frozen`), the
//!    request gets its one reply (an error), and the targets frozen so far
//!    are drained on a blocking task of their own, independent of the
//!    worker still blocked in `FIFREEZE`. A thaw that arrives meanwhile
//!    requests the abort and is answered at once (see the thaw handler).
//! 5. Every authorised worker is awaited to its end. A late success (or
//!    `EBUSY`) is drained through the handle it opened; a late error needs
//!    nothing; a worker that panicked leaves its target uncertain.
//! 6. The operation settles through one path (`Driver::conclude`) only
//!    when no worker is outstanding and every published handle has been
//!    drained: complete → marker removed, finalisation hook, `Thawed`; a
//!    drain incomplete or the marker not removable → `Frozen`, marker
//!    retained, the watchdog armed as on any entry into that state, the
//!    incomplete handles kept for it; nothing frozen and nothing held
//!    (an empty or entirely skipped plan) → marker removed, `Thawed`,
//!    reply `0` (#43 §2). The operation retires its
//!    registration (by identity: a successor is never touched) before the
//!    state is published, so whoever observes the terminal state finds
//!    the slot released; the settlement is announced and the reply sent
//!    after that. Until then the marker, the frozen gate and the
//!    freeze-safe audit mode stay.
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
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, oneshot, watch};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;
use tracing::instrument::WithSubscriber;

use crate::dispatch::{Context, ThawScope};
use crate::freeze_plan::{FreezePlan, Target};
use crate::handlers::fsfreeze::{
    FreezeFailure, FreezeStop, build_plan, drain_held, open_target, rollback,
};
use crate::kernel::{KernelOps, Mount};
use crate::marker::{Marker, MarkerError};
use crate::state::{FreezeState, FreezeToken, ThawToken};
use crate::watchdog::BoxFuture;

/// The clock the operation deadline is measured against, shared by the
/// coordinator and its workers so every decision boundary reads the same
/// time. Production is [`TokioClock`]; tests inject a [`ManualClock`].
pub trait FreezeClock: Send + Sync + std::fmt::Debug {
    /// The current time.
    fn now(&self) -> Instant;
    /// Resolves once `now() >= deadline`.
    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()>;
}

/// The runtime's clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioClock;

impl FreezeClock for TokioClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep_until(deadline))
    }
}

/// A clock that only moves when a test moves it, so a deadline expires
/// exactly where the test puts it and nowhere else.
#[derive(Debug, Clone)]
pub struct ManualClock {
    inner: Arc<ManualClockInner>,
}

#[derive(Debug)]
struct ManualClockInner {
    now: std::sync::Mutex<Instant>,
    changed: Notify,
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ManualClock {
    /// A clock stopped at the current runtime time.
    pub fn new() -> Self {
        ManualClock {
            inner: Arc::new(ManualClockInner {
                now: std::sync::Mutex::new(Instant::now()),
                changed: Notify::new(),
            }),
        }
    }

    /// Moves the clock forward and wakes every sleeper.
    pub fn advance(&self, by: Duration) {
        {
            let mut now = self
                .inner
                .now
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *now += by;
        }
        self.inner.changed.notify_waiters();
    }
}

impl FreezeClock for ManualClock {
    fn now(&self) -> Instant {
        *self
            .inner
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn sleep_until(&self, deadline: Instant) -> BoxFuture<'static, ()> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            loop {
                // Register before reading the time, so an advance between
                // the read and the wait is not missed.
                let notified = inner.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let now = *inner
                    .now
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if now >= deadline {
                    return;
                }
                notified.await;
            }
        })
    }
}

/// The `in_flight` value while the plan and the marker are being prepared.
pub const PREPARING: &str = "(preparing)";

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
    /// A freeze worker was lost (it panicked): its target is uncertain,
    /// so the walk stops and the operation settles `Frozen`.
    WorkerLost,
}

impl AbortCause {
    /// The cause for a reply, with the deadline where it applies.
    pub fn describe(self, timeout_secs: u64) -> String {
        match self {
            AbortCause::Deadline => format!("operation deadline of {timeout_secs} s expired"),
            AbortCause::ThawRequested => "thaw requested".to_owned(),
            AbortCause::WorkerLost => "freeze worker lost".to_owned(),
        }
    }
}

impl std::fmt::Display for AbortCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AbortCause::Deadline => "deadline",
            AbortCause::ThawRequested => "thaw_requested",
            AbortCause::WorkerLost => "worker_lost",
        })
    }
}

/// A snapshot of an operation, published to waiters after every change.
/// Snapshots describe the driver's state; they are never written by
/// anyone else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Progress {
    /// Where the operation stands.
    pub phase: Phase,
    /// Successful `FIFREEZE` calls so far.
    pub frozen: u64,
    /// The target whose `FIFREEZE` is outstanding (`"(preparing)"` while
    /// the plan and the marker are being prepared).
    pub in_flight: Option<String>,
    /// `true` once the abort has committed and every handle published so
    /// far has been drained (no drain running, nothing held): the targets
    /// frozen before the abort are recovered, whatever the in-flight call
    /// does later. Reset when a late completion publishes another handle.
    pub recovery_pass_done: bool,
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
            in_flight: Some(PREPARING.to_owned()),
            recovery_pass_done: false,
            recovered: 0,
            unrecoverable: None,
            settled: None,
        }
    }

    /// `true` once the completed targets have had their recovery drain or
    /// the operation has settled.
    pub fn recovery_pass_done(&self) -> bool {
        self.settled.is_some() || self.recovery_pass_done
    }
}

/// The answer to [`FreezeOp::request_abort`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortRequest {
    /// The abort is accepted (now or already): the operation will not
    /// commit a successful freeze, and recovery of the targets frozen so
    /// far is, or will be, under way.
    Accepted,
    /// The operation had already committed its outcome (a successful
    /// freeze, or a settlement of its own): nothing is aborted, and the
    /// thaw belongs to the ordinary path once the state is published.
    Committed,
}

/// The one transition abort and completion compete on: open, aborting,
/// or committed (see [`FreezeOp::request_abort`] and `try_commit`).
const OUTCOME_OPEN: u8 = 0;
const OUTCOME_ABORTING: u8 = 1;
const OUTCOME_COMMITTED: u8 = 2;

/// One freeze operation, shared between the driver task, the request that
/// started it and any thaw that joins it. Registered in the [`Context`]
/// until it settles.
#[derive(Debug)]
pub struct FreezeOp {
    deadline: Instant,
    clock: Arc<dyn FreezeClock>,
    abort_requested: Notify,
    /// `OUTCOME_OPEN` until either an abort is accepted (`ABORTING`, by a
    /// thaw request or by the driver at a decision boundary) or the driver
    /// commits the operation's outcome (`COMMITTED`); the two compete on
    /// this one atomic, so a thaw request can never be told "recovery
    /// pending" by an operation that then commits a successful freeze.
    outcome: AtomicU8,
    /// The abort committed in the driver (read by workers before their
    /// ioctl).
    aborted: AtomicBool,
    progress: watch::Sender<Progress>,
    /// The driver task, once spawned, for [`abort_driver`](Self::abort_driver).
    driver: std::sync::OnceLock<tokio::task::AbortHandle>,
}

impl FreezeOp {
    /// Aborts the driver task where it waits, as the process's death
    /// would end it: no state is published, no marker written and no
    /// reply sent by it afterwards; a worker's ioctl already in the kernel
    /// completes on its own thread. For harnesses modelling a crash
    /// ([`Context::abort_tasks`]); the daemon never aborts its own driver,
    /// and nothing else should: the operation is left unsettled.
    #[doc(hidden)]
    pub fn abort_driver(&self) {
        if let Some(driver) = self.driver.get() {
            driver.abort();
        }
    }

    /// Asks the operation to stop authorising targets and to recover the
    /// ones frozen so far (a thaw request). Idempotent; a request that
    /// arrives before the driver waits is not lost. The answer says
    /// whether the abort is accepted or the operation had already
    /// committed its outcome.
    pub fn request_abort(&self) -> AbortRequest {
        match self.outcome.compare_exchange(
            OUTCOME_OPEN,
            OUTCOME_ABORTING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) | Err(OUTCOME_ABORTING) => {
                self.abort_requested.notify_one();
                AbortRequest::Accepted
            }
            Err(_) => AbortRequest::Committed,
        }
    }

    /// The driver's side of the transition: claims the outcome for a
    /// settlement. `false` when an abort was accepted first, in which case
    /// the driver must recover instead of committing.
    fn try_commit(&self) -> bool {
        self.outcome
            .compare_exchange(
                OUTCOME_OPEN,
                OUTCOME_COMMITTED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// The driver accepting the abort itself (deadline, lost worker).
    fn mark_aborting(&self) {
        let _ = self.outcome.compare_exchange(
            OUTCOME_OPEN,
            OUTCOME_ABORTING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    /// The latest snapshot.
    pub fn progress(&self) -> Progress {
        self.progress.borrow().clone()
    }

    /// The operation deadline.
    pub fn deadline(&self) -> Instant {
        self.deadline
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

    /// The abort decision at a boundary: an accepted request, else the
    /// deadline.
    fn abort_due(&self) -> Option<AbortCause> {
        if self.outcome.load(Ordering::SeqCst) == OUTCOME_ABORTING {
            Some(AbortCause::ThawRequested)
        } else if self.clock.now() >= self.deadline {
            Some(AbortCause::Deadline)
        } else {
            None
        }
    }

    /// A worker's last check before its destructive call: not aborted and
    /// not past the deadline. A worker that passed it is owned regardless.
    fn authorises(&self) -> bool {
        !self.aborted.load(Ordering::SeqCst) && self.clock.now() < self.deadline
    }

    fn publish(&self, update: impl FnOnce(&mut Progress)) {
        self.progress.send_modify(update);
    }

    /// An operation that is not driven: for registration tests.
    #[cfg(test)]
    pub(crate) fn detached_for_tests() -> Arc<FreezeOp> {
        Self::detached_with_deadline(
            Arc::new(TokioClock),
            Instant::now() + Duration::from_secs(3600),
        )
    }

    /// An operation that is not driven, on `clock` with `deadline`.
    #[cfg(test)]
    pub(crate) fn detached_with_deadline(
        clock: Arc<dyn FreezeClock>,
        deadline: Instant,
    ) -> Arc<FreezeOp> {
        let (progress, _) = watch::channel(Progress::initial());
        Arc::new(FreezeOp {
            deadline,
            clock,
            abort_requested: Notify::new(),
            outcome: AtomicU8::new(OUTCOME_OPEN),
            aborted: AtomicBool::new(false),
            progress,
            driver: std::sync::OnceLock::new(),
        })
    }
}

/// Starts an operation: registers it in `ctx`, spawns the driver, and
/// returns the receiver of the request's single reply. `token` proves the
/// caller moved the machine into `Freezing`; the driver consumes it.
pub(crate) fn start(
    ctx: Arc<Context>,
    token: FreezeToken,
    restrict: Option<Vec<String>>,
) -> oneshot::Receiver<Result<u64, FreezeFailure>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    let (progress, _) = watch::channel(Progress::initial());
    let clock = ctx.freeze_clock();
    let timeout = ctx.freeze_operation_timeout();
    let op = Arc::new(FreezeOp {
        deadline: clock.now() + timeout,
        clock,
        abort_requested: Notify::new(),
        outcome: AtomicU8::new(OUTCOME_OPEN),
        aborted: AtomicBool::new(false),
        progress,
        driver: std::sync::OnceLock::new(),
    });
    ctx.set_freeze_op(Some(Arc::clone(&op)));
    let spawned = Arc::clone(&op);
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
        uncertain: false,
        unrecoverable: None,
        abort: None,
        timeout,
    };
    let task = tokio::spawn(driver.drive(restrict).with_subscriber(dispatch));
    // Set once, here; `abort_driver` before this point aborts nothing,
    // which is right: the driver has not run yet either.
    let _ = spawned.driver.set(task.abort_handle());
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
    /// The abort had committed, or the deadline had passed, before the
    /// ioctl: nothing was issued.
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

/// The state an operation settles in.
#[derive(Clone, Copy)]
enum Terminal {
    Frozen,
    Thawed,
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
    /// A target's outcome is unknown and no descriptor shows for it (a
    /// worker, a drain or a rollback lost): the thaw of what this
    /// operation leaves must discover its targets (§4.2 "Thaw scope").
    uncertain: bool,
    abort: Option<AbortCause>,
    timeout: Duration,
}

impl Driver {
    async fn drive(mut self, restrict: Option<Vec<String>>) {
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
                // tolerates its absence.
                return self
                    .settle_before_ioctl(FreezeFailure::Task(err.to_string()))
                    .await;
            }
        };
        self.op.publish(|p| p.in_flight = None);
        for target in plan.freeze_order() {
            // Decision boundary: authorisation.
            self.decide();
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
                    self.op.publish(|p| p.frozen = frozen);
                    self.refresh_pass_done();
                }
                Ok(TargetOutcome::Busy(mount)) => {
                    tracing::warn!(
                        event = "fsfreeze_busy",
                        mountpoint = %mountpoint,
                        "already frozen by another freezer; retained for thaw"
                    );
                    self.ctx.hold_frozen_mounts(vec![mount]);
                    self.refresh_pass_done();
                }
                Ok(TargetOutcome::Skipped) => {
                    tracing::info!(event = "fsfreeze_skipped", mountpoint = %mountpoint, "freeze not supported; skipped");
                }
                Ok(TargetOutcome::NotAuthorized) => {
                    tracing::debug!(event = "fsfreeze_not_authorized", mountpoint = %mountpoint, "abort or deadline before the ioctl; nothing issued");
                    // The worker saw the deadline before the driver did.
                    self.decide();
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
                    self.uncertain = true;
                    self.unrecoverable.get_or_insert((
                        mountpoint.clone(),
                        format!("freeze worker lost ({err}); FIFREEZE outcome unknown"),
                    ));
                    self.commit_abort(AbortCause::WorkerLost);
                    break;
                }
            }
        }
        // Decision boundary: a completion arriving after the deadline (or
        // after a request) enters recovery, never a successful `Frozen`.
        self.decide();
        if self.abort.is_some() {
            return self.settle_aborted().await;
        }
        // The commit itself competes with a thaw request on one transition:
        // a request accepted between the decision above and this claim
        // wins, and the operation recovers instead of publishing `Frozen`.
        if !self.op.try_commit() {
            self.commit_abort(AbortCause::ThawRequested);
            return self.settle_aborted().await;
        }
        // Zero work (#43 §2): nothing frozen, nothing held for a drain
        // (no `EBUSY` target), nothing uncertain and no worker
        // outstanding leaves nothing to recover, so the operation settles
        // `Thawed` with the marker removed, never `Frozen` with an armed
        // watchdog and a gate closed on nothing. `frozen == 0` alone is
        // not the test: a held handle keeps the conservative state.
        if self.frozen == 0 && self.ctx.frozen_mount_count() == 0 && self.unrecoverable.is_none() {
            return self.settle_nothing_frozen().await;
        }
        tracing::info!(
            event = "fsfreeze_frozen",
            frozen = self.frozen,
            "filesystems frozen"
        );
        let frozen = self.frozen;
        self.conclude(Terminal::Frozen, Ok(frozen));
    }

    /// The operation committed with nothing frozen and nothing held: the
    /// marker is removed (tracked) and the operation settles `Thawed`
    /// with the reply `0`; a marker that cannot be removed keeps the
    /// conservative state and the reply is an error.
    async fn settle_nothing_frozen(mut self) {
        let marker = self.marker.clone();
        let removed = self
            .await_tracked(self.spawn_blocking(move || marker.remove()), false)
            .await;
        match removed {
            Ok(Ok(())) | Ok(Err(MarkerError::Absent { .. })) => {
                tracing::info!(
                    event = "fsfreeze_nothing_frozen",
                    "no target frozen (empty or entirely skipped plan); thawed"
                );
                self.conclude(Terminal::Thawed, Ok(0));
            }
            Ok(Err(err)) => {
                tracing::error!(event = "fsfreeze_marker_retained", error = %err, "nothing frozen but the marker cannot be removed; staying frozen");
                self.conclude(
                    Terminal::Frozen,
                    Err(FreezeFailure::NothingFrozenMarkerRetained(err)),
                );
            }
            Err(err) => {
                tracing::error!(event = "fsfreeze_marker_retained", error = %err, "marker removal lost; staying frozen");
                self.conclude(
                    Terminal::Frozen,
                    Err(FreezeFailure::Task(format!("marker removal lost: {err}"))),
                );
            }
        }
    }

    /// Takes the abort decision at a boundary (no-op once committed).
    fn decide(&mut self) {
        if self.abort.is_none()
            && let Some(cause) = self.op.abort_due()
        {
            self.commit_abort(cause);
        }
    }

    /// Spawns a blocking task whose records go to the request's subscriber.
    fn spawn_blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> JoinHandle<T> {
        let dispatch = self.dispatch.clone();
        tokio::task::spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, f))
    }

    /// The worker for one target: open it on its planned device, take the
    /// last check, then `FIFREEZE`.
    fn spawn_freeze(&self, target: Target) -> JoinHandle<TargetOutcome> {
        let kernel = Arc::clone(&self.kernel);
        let op = Arc::clone(&self.op);
        self.spawn_blocking(move || {
            let mount = match open_target(kernel.as_ref(), &target) {
                Ok(mount) => mount,
                Err(attempts) => {
                    return TargetOutcome::Failed(FreezeStop::Unreachable(attempts));
                }
            };
            if !op.authorises() {
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

    /// Awaits a tracked task to its end. Meanwhile, when `abortable`, a
    /// pending abort (request or deadline) commits first, ahead of any
    /// completion; a running recovery drain is collected and, if more
    /// handles were published, followed by another. The task itself is
    /// never abandoned.
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
                    cause = abort_signal(op), if armed => Event::Abort(cause),
                    res = async {
                        match recovery.as_mut() {
                            Some(drain) => drain.await,
                            None => std::future::pending().await,
                        }
                    } => Event::Recovered(res),
                    res = &mut task => Event::Done(res),
                }
            };
            match event {
                Event::Done(res) => return res,
                Event::Recovered(res) => {
                    self.recovery = None;
                    self.record_recovery(res);
                    self.start_recovery_if_needed();
                    self.refresh_pass_done();
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
        self.op.mark_aborting();
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
        self.start_recovery_if_needed();
        self.op.publish(|p| p.phase = Phase::Recovering);
        self.refresh_pass_done();
    }

    /// Publishes whether the targets frozen before the abort have all been
    /// drained (see [`Progress::recovery_pass_done`]).
    fn refresh_pass_done(&mut self) {
        let done =
            self.abort.is_some() && self.recovery.is_none() && self.ctx.frozen_mount_count() == 0;
        self.op.publish(|p| p.recovery_pass_done = done);
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
                self.uncertain = true;
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
            p.recovered = recovered;
            p.unrecoverable = unrecoverable;
        });
    }

    /// Nothing was frozen (the plan or the marker failed, or the
    /// preparation was lost): `Thawed`, the marker removed if it exists;
    /// an aborted operation settles through the aborted path instead.
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
                self.conclude(
                    Terminal::Frozen,
                    Err(FreezeFailure::MarkerRetained {
                        failed: "(preparation)".to_owned(),
                        cause: FreezeStop::Unreachable(failure.to_string()),
                        marker: err,
                    }),
                );
                return;
            }
        }
        self.conclude(Terminal::Thawed, Err(failure));
    }

    /// A hard error while not aborted: roll back the published handles,
    /// then `Thawed`, or `Frozen` when the rollback is incomplete or the
    /// marker stays (§4.2). The rollback is itself the recovery: the
    /// deadline does not interrupt it.
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
            Err(err) => {
                self.uncertain = true;
                FreezeFailure::Task(format!("rollback lost: {err}"))
            }
        };
        if failure.retains_frozen_state() || matches!(failure, FreezeFailure::Task(_)) {
            tracing::error!(event = "fsfreeze_failed_frozen", error = %failure, "freeze failed and the rollback is incomplete; staying frozen");
            self.conclude(Terminal::Frozen, Err(failure));
            return;
        }
        tracing::warn!(event = "fsfreeze_failed", error = %failure, "freeze failed");
        self.conclude(Terminal::Thawed, Err(failure));
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
            self.refresh_pass_done();
            if self.recovery.is_none() {
                break;
            }
        }
        // The reply went out when the abort committed; the value here only
        // matters if it did not (it never reaches anyone).
        let aborted = FreezeFailure::Task("aborted".to_owned());
        if let Some((mountpoint, reason)) = self.unrecoverable.take() {
            tracing::error!(event = "fsfreeze_recovery_incomplete", mountpoint = %mountpoint, reason = %reason, "recovery incomplete; marker retained");
            let kept = std::mem::take(&mut self.kept);
            self.ctx.hold_frozen_mounts(kept);
            self.conclude(Terminal::Frozen, Err(aborted));
            return;
        }
        let marker = self.marker.clone();
        let removed = self
            .await_tracked(self.spawn_blocking(move || marker.remove()), false)
            .await;
        match removed {
            Ok(Ok(())) | Ok(Err(MarkerError::Absent { .. })) => {
                tracing::info!(
                    event = "fsfreeze_recovered",
                    recovered = self.recovered,
                    "aborted freeze recovered; thawed"
                );
                self.conclude(Terminal::Thawed, Err(aborted));
            }
            Ok(Err(err)) => {
                tracing::error!(event = "fsfreeze_marker_retained", error = %err, "recovery drained but the marker cannot be removed; staying frozen");
                self.conclude(Terminal::Frozen, Err(aborted));
            }
            Err(err) => {
                tracing::error!(event = "fsfreeze_marker_retained", error = %err, "marker removal lost; staying frozen");
                self.conclude(Terminal::Frozen, Err(aborted));
            }
        }
    }

    /// The one settlement path, in this order: finalise (the audit flush
    /// runs while the state still refuses a new freeze), retire the
    /// registration by identity, publish the terminal state through
    /// whichever token the driver holds, announce the settlement, then
    /// send the reply if none went out yet. Retiring before the state is
    /// published means whoever observes the terminal state finds the
    /// slot released and a successor can only be admitted afterwards;
    /// the identity check keeps the retirement harmless even so.
    fn conclude(mut self, terminal: Terminal, reply: Result<u64, FreezeFailure>) {
        // Every settlement commits the outcome (a no-op once aborting): a
        // thaw request from here on is told the operation is committed and
        // takes the ordinary path once the state is published.
        let _ = self.op.try_commit();
        if matches!(terminal, Terminal::Thawed) {
            self.ctx.hooks.on_thawed(&self.ctx);
        }
        self.ctx.retire_freeze_op(&self.op);
        // What the thaw of this operation's leftovers must do (§4.2 "Thaw
        // scope"): drain the descriptors published, unless a target's
        // outcome is unknown, in which case it discovers its targets.
        self.ctx.set_thaw_scope(match terminal {
            Terminal::Frozen if !self.uncertain => ThawScope::Tracked,
            Terminal::Frozen | Terminal::Thawed => ThawScope::Discovery,
        });
        let state = match terminal {
            Terminal::Thawed => {
                if let Some(token) = self.token.take() {
                    self.ctx.state.freeze_failed(token);
                } else if let Some(thaw) = self.thaw_token.take() {
                    self.ctx.state.thaw_succeeded(thaw);
                }
                FreezeState::Thawed
            }
            Terminal::Frozen => {
                if let Some(token) = self.token.take() {
                    self.ctx.state.freeze_succeeded(token);
                } else if let Some(thaw) = self.thaw_token.take() {
                    self.ctx.state.thaw_failed(thaw);
                }
                self.ctx.hooks.on_frozen(&self.ctx);
                FreezeState::Frozen
            }
        };
        self.op.publish(|p| {
            p.phase = Phase::Settled;
            p.in_flight = None;
            p.settled = Some(state);
        });
        self.reply(reply);
    }

    /// Sends the request's single reply; later calls are no-ops.
    fn reply(&mut self, outcome: Result<u64, FreezeFailure>) {
        if let Some(tx) = self.reply.take() {
            // The requester may be gone (channel lost): nothing to deliver.
            let _ = tx.send(outcome);
        }
    }
}

/// Resolves when an abort is requested or the deadline passes.
async fn abort_signal(op: &FreezeOp) -> AbortCause {
    tokio::select! {
        biased;
        () = op.abort_requested.notified() => AbortCause::ThawRequested,
        () = op.clock.sleep_until(op.deadline) => AbortCause::Deadline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_deadline_instant_itself_authorises_nothing() {
        // The worker's last check and the driver's decision agree on the
        // boundary: one tick before the deadline authorises, the deadline
        // instant does not.
        let clock = ManualClock::new();
        let deadline = clock.now() + Duration::from_secs(1);
        let op = FreezeOp::detached_with_deadline(Arc::new(clock.clone()), deadline);
        assert!(op.authorises());
        assert_eq!(op.abort_due(), None);
        clock.advance(Duration::from_millis(999));
        assert!(op.authorises());
        assert_eq!(op.abort_due(), None);
        clock.advance(Duration::from_millis(1));
        assert!(!op.authorises(), "the deadline instant is expired");
        assert_eq!(op.abort_due(), Some(AbortCause::Deadline));
    }

    #[test]
    fn abort_and_commit_compete_on_one_transition() {
        // A request accepted first makes the commit fail; a commit first
        // makes the request come back as committed; both are idempotent.
        let op = FreezeOp::detached_for_tests();
        assert_eq!(op.request_abort(), AbortRequest::Accepted);
        assert_eq!(op.request_abort(), AbortRequest::Accepted);
        assert!(!op.try_commit(), "an accepted abort wins");
        assert_eq!(op.abort_due(), Some(AbortCause::ThawRequested));
        let op = FreezeOp::detached_for_tests();
        assert!(op.try_commit());
        assert!(!op.try_commit(), "committed once");
        assert_eq!(op.request_abort(), AbortRequest::Committed);
        assert_eq!(op.abort_due(), None, "nothing to abort any more");
        // The driver's own abort is the same transition.
        let op = FreezeOp::detached_for_tests();
        op.mark_aborting();
        assert!(!op.try_commit());
        assert_eq!(op.request_abort(), AbortRequest::Accepted);
    }

    #[tokio::test]
    async fn the_manual_clock_wakes_sleepers_only_when_advanced() {
        let clock = ManualClock::new();
        let deadline = clock.now() + Duration::from_secs(10);
        let sleeper = {
            let clock = clock.clone();
            tokio::spawn(async move { clock.sleep_until(deadline).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!sleeper.is_finished(), "real time does not move it");
        clock.advance(Duration::from_secs(9));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!sleeper.is_finished(), "still short of the deadline");
        clock.advance(Duration::from_secs(1));
        tokio::time::timeout(Duration::from_secs(5), sleeper)
            .await
            .unwrap()
            .unwrap();
        // A sleep that starts past its deadline resolves at once.
        clock.sleep_until(deadline).await;
    }
}
