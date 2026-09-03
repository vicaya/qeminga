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
//!    recovery marker (`O_EXCL` + `fsync`), then `FIFREEZE` each target in
//!    reverse mount order. Marker failure → no ioctl at all.
//!    - `EOPNOTSUPP`: skipped, not counted, not rolled back.
//!    - `EBUSY`: not counted, but retained for rollback/thaw.
//!    - any other errno: hard error → every processed target is drained
//!      in forward order, then the marker is removed.
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
//! drain. A first `FITHAW` failing with `EPERM`/`EACCES`, or a marker
//! removal failure, is unrecoverable (OQ-3 interim): `Thawing → Frozen`,
//! marker kept. Otherwise `Thawing → Thawed` and
//! [`FreezeHooks::on_thawed`] (T3.6 flushes the ring).
//!
//! The state mutex is never held across an `.await`; all ioctls run under
//! `spawn_blocking`.
#![forbid(unsafe_code)]

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dispatch::Context;
use crate::freeze_plan::FreezePlan;
use crate::handlers::NoArgs;
use crate::kernel::{KernelError, KernelOps};
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
    /// After the state returned to `Thawed` (thaw success or freeze
    /// rollback).
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
    let outcome = tokio::task::spawn_blocking(move || {
        let plan = build_plan::<FreezeFailure>(mounts.as_ref(), restrict.as_deref())?;
        freeze_blocking(kernel.as_ref(), &marker, &plan)
    })
    .await
    .unwrap_or_else(|err| Err(FreezeFailure::Task(err.to_string())));

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
            ctx.state.freeze_failed(token);
            ctx.hooks.on_thawed(ctx);
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
    let outcome = tokio::task::spawn_blocking(move || {
        let plan = build_plan::<ThawFailure>(mounts.as_ref(), None)?;
        thaw_blocking(kernel.as_ref(), &marker, &plan)
    })
    .await
    .unwrap_or_else(|err| Err(ThawFailure::Task(err.to_string())));

    match outcome {
        Ok(thawed) => {
            ctx.state.thaw_succeeded(token);
            ctx.hooks.on_thawed(ctx);
            tracing::info!(event = "fsfreeze_thawed", thawed, "filesystems thawed");
            Ok(thawed)
        }
        Err(failure) => {
            ctx.state.thaw_failed(token);
            tracing::error!(event = "fsfreeze_thaw_failed", error = %failure, "thaw failed; marker retained");
            Err(Error::Internal(failure.to_string()))
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
    /// `FIFREEZE` failed with a hard error; processed targets were rolled
    /// back.
    #[error("freeze of {mountpoint} failed: {errno}; rolled back")]
    Hard {
        /// The target that failed.
        mountpoint: String,
        /// The errno.
        errno: KernelError,
    },
    /// `FIFREEZE` failed with a hard error and the rollback could not thaw
    /// `mountpoint` (first `FITHAW` denied, or the drain bound reached):
    /// the filesystem may still be frozen, so the state stays `Frozen`
    /// and the marker is retained.
    #[error(
        "freeze of {failed} failed: {errno}; rollback of {mountpoint} incomplete ({reason}); marker retained"
    )]
    RollbackIncomplete {
        /// The target whose `FIFREEZE` failed.
        failed: String,
        /// Its errno.
        errno: KernelError,
        /// The processed target that could not be thawed.
        mountpoint: String,
        /// Why the drain did not complete.
        reason: String,
    },
    /// The rollback thawed every processed target but the marker could not
    /// be removed: the state stays `Frozen` and the marker is retained.
    #[error(
        "freeze of {failed} failed: {errno}; rolled back but cannot remove recovery marker: {marker}"
    )]
    MarkerRetained {
        /// The target whose `FIFREEZE` failed.
        failed: String,
        /// Its errno.
        errno: KernelError,
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
    /// A first `FITHAW` on a planned mountpoint was denied (OQ-3).
    #[error("thaw of {mountpoint} denied: {errno}; marker retained")]
    Denied {
        /// The target that failed.
        mountpoint: String,
        /// The errno.
        errno: KernelError,
    },
    /// `FITHAW` still succeeded at the defensive bound: the nesting depth
    /// is unknown and at least one hold may remain, so the drain is
    /// incomplete and the marker is retained.
    #[error(
        "thaw of {mountpoint} did not converge after {iterations} FITHAW calls; marker retained"
    )]
    Unbounded {
        /// The target that kept accepting `FITHAW`.
        mountpoint: String,
        /// The bound that was reached.
        iterations: u32,
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

/// Marker, then `FIFREEZE` in reverse mount order, with rollback on a hard
/// error. Returns the number of successful `FIFREEZE` calls.
fn freeze_blocking(
    kernel: &dyn KernelOps,
    marker: &Marker,
    plan: &FreezePlan,
) -> Result<u64, FreezeFailure> {
    marker.create()?;
    let mut frozen: u64 = 0;
    // Targets that must be thawed on rollback: successes and EBUSY.
    let mut processed: Vec<&str> = Vec::new();
    for target in plan.freeze_order() {
        let mountpoint = target.mountpoint.as_str();
        match kernel.fifreeze(std::path::Path::new(mountpoint)) {
            Ok(()) => {
                frozen += 1;
                processed.push(mountpoint);
            }
            Err(err) if err.is_not_supported() => {
                tracing::info!(event = "fsfreeze_skipped", mountpoint, errno = %err, "freeze not supported; skipped");
            }
            Err(err) if err.is_busy() => {
                tracing::warn!(
                    event = "fsfreeze_busy",
                    mountpoint,
                    "already frozen by another freezer; retained for thaw"
                );
                processed.push(mountpoint);
            }
            Err(errno) => {
                // Forward order: `processed` was filled in reverse mount
                // order, so reverse it back.
                for done in processed.iter().rev() {
                    let drained = drain(kernel, done);
                    tracing::warn!(
                        event = "fsfreeze_rollback",
                        mountpoint = *done,
                        successes = drained.successes,
                        "rolled back"
                    );
                    if let Some(reason) = drained.incomplete() {
                        return Err(FreezeFailure::RollbackIncomplete {
                            failed: mountpoint.to_owned(),
                            errno,
                            mountpoint: (*done).to_owned(),
                            reason,
                        });
                    }
                }
                match marker.remove() {
                    Ok(()) | Err(MarkerError::Absent { .. }) => {}
                    Err(marker) => {
                        return Err(FreezeFailure::MarkerRetained {
                            failed: mountpoint.to_owned(),
                            errno,
                            marker,
                        });
                    }
                }
                return Err(FreezeFailure::Hard {
                    mountpoint: mountpoint.to_owned(),
                    errno,
                });
            }
        }
    }
    Ok(frozen)
}

/// Drains every target in forward order, then removes the marker. Returns
/// the number of targets on which at least one `FITHAW` succeeded.
fn thaw_blocking(
    kernel: &dyn KernelOps,
    marker: &Marker,
    plan: &FreezePlan,
) -> Result<u64, ThawFailure> {
    let mut thawed: u64 = 0;
    for target in plan.thaw_order() {
        let mountpoint = target.mountpoint.as_str();
        let drained = drain(kernel, mountpoint);
        if drained.capped {
            return Err(ThawFailure::Unbounded {
                mountpoint: mountpoint.to_owned(),
                iterations: MAX_THAW_ITERATIONS,
            });
        }
        if drained.successes > 0 {
            thawed += 1;
        } else if let Some(errno) = drained.first_error.filter(KernelError::is_permission) {
            return Err(ThawFailure::Denied {
                mountpoint: mountpoint.to_owned(),
                errno,
            });
        }
    }
    match marker.remove() {
        Ok(()) | Err(MarkerError::Absent { .. }) => Ok(thawed),
        Err(err) => Err(ThawFailure::Marker(err)),
    }
}

/// `FITHAW` until the first error or the iteration bound. Returns the
/// number of successes and the error that ended the drain, if any.
fn drain(kernel: &dyn KernelOps, mountpoint: &str) -> Drained {
    let path = std::path::Path::new(mountpoint);
    let mut successes = 0;
    for _ in 0..MAX_THAW_ITERATIONS {
        match kernel.fithaw(path) {
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
        mountpoint,
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
    /// Why the target may still be frozen, if it may: a first `FITHAW`
    /// that was denied, or a drain that never converged.
    fn incomplete(&self) -> Option<String> {
        if self.capped {
            return Some(format!(
                "FITHAW still succeeding after {MAX_THAW_ITERATIONS} calls"
            ));
        }
        match &self.first_error {
            Some(err) if self.successes == 0 && err.is_permission() => {
                Some(format!("first FITHAW denied: {err}"))
            }
            _ => None,
        }
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

    #[derive(Default)]
    struct Recorder(Mutex<Vec<&'static str>>);

    impl Recorder {
        fn events(&self) -> Vec<&'static str> {
            self.0.lock().unwrap().clone()
        }
        fn push(&self, e: &'static str) {
            self.0.lock().unwrap().push(e);
        }
    }

    impl FreezeHooks for Recorder {
        fn on_freezing(&self, _: &Arc<Context>) {
            self.push("freezing");
        }
        fn on_frozen(&self, _: &Arc<Context>) {
            self.push("frozen");
        }
        fn on_thaw_claimed(&self, _: &Arc<Context>) {
            self.push("thaw_claimed");
        }
        fn on_thawed(&self, _: &Arc<Context>) {
            self.push("thawed");
        }
        fn on_heartbeat(&self, _: &Arc<Context>) {
            self.push("heartbeat");
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
            )
            .with_kernel(kernel.clone())
            .with_mounts(Arc::new(StaticMounts(fixture(mountinfo))))
            .with_marker(Marker::new(dir.path().join("frozen")))
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
        let ctx = Arc::new(
            Context::new(
                rig.ctx.config.clone(),
                rig.ctx.state.clone(),
                Router::new(Box::new(std::io::sink())),
            )
            .with_kernel(rig.kernel.clone())
            .with_mounts(rig.ctx.mounts.clone())
            .with_marker(Marker::new("/nonexistent/qeminga/frozen"))
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
        assert_eq!(rig.hooks.events(), ["thaw_claimed"], "no `thawed` hook");
        // The host can retry; a now-permitted drain completes.
        let rig2 = Rig::new(FreezeState::Frozen, "simple.txt");
        rig2.marker().create().unwrap();
        let value = thaw(&rig2.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));

        // Any other errno on a first FITHAW just ends that target's drain.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        rig.kernel.script_thaw_error("/home", Errno::EIO);
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(1));
        assert_eq!(rig.state(), FreezeState::Thawed);
        assert!(!rig.marker().exists());

        // EPERM after at least one success is also just the end of the drain.
        let rig = Rig::new(FreezeState::Frozen, "simple.txt");
        rig.marker().create().unwrap();
        let value = thaw(&rig.ctx, &req(r#"{"execute":"guest-fsfreeze-thaw"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!(2));

        // A marker that cannot be removed is unrecoverable too.
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        let marker = Marker::new(ro.join("frozen"));
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
                )
                .with_kernel(rig.kernel.clone())
                .with_mounts(rig.ctx.mounts.clone())
                .with_marker(marker.clone()),
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
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
            )
            .with_marker(Marker::new(dir.path().join("frozen"))),
        );
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
