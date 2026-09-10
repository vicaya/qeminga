//! The reference snapshot controller of design §4.5 (#43 §1, T6.3): the
//! executable form of the controller protocol, driven against the
//! production dispatcher, coordinator and watchdog with the scripted
//! kernel (freeze depth tracked, so a `FITHAW` succeeds exactly as often
//! as a `FIFREEZE` did) on paused time.
//!
//! [`Cycle`] is the algorithm: one freeze per cycle, heartbeats while the
//! consistency points are cut, one thaw, and a verdict that is
//! `Quiesced` only when the freeze covered every required superblock and
//! the thaw found every one of them still frozen. Everything else is a
//! [`Verdict::Rejected`] with the reason; a rejected cycle sends a thaw
//! and waits for `thawed` before the controller may start another.
//!
//! The scenarios are the rows of #43: a normal cycle, expiry before or
//! during the cut, expiry between two volumes, a delayed reply, an agent
//! restart and a guest reboot, a crash before the reply, thaw/refreeze,
//! an external thaw behind a `frozen` status, and a request that is not
//! fully covered.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qeminga::audit::Router;
use qeminga::config::Config;
use qeminga::dispatch::{Context, Dispatcher};
use qeminga::framing::DecodeEvent;
use qeminga::freeze_op::ManualClock;
use qeminga::handlers::fsfreeze;
use qeminga::kernel::KernelOps;
use qeminga::kernel::fake::{Call, FakeKernel, ReleaseOnDrop};
use qeminga::marker::Marker;
use qeminga::mountinfo::StaticMounts;
use qeminga::state::{FreezeState, FreezeStateMachine};
use serde_json::{Value, json};
use tokio::sync::Notify;

/// `/` (8:1) and `/home` (8:2), both ext4.
const A: &str = "/";
const B: &str = "/home";
const IDLE_SECS: u64 = 30;
const MAX_SECS: u64 = 120;
/// The controller's cycle budget: under the hard cap by a margin covering
/// the freeze walk (bounded by the operation deadline) and the thaw
/// (§4.5 "Timing assumptions").
const BUDGET_SECS: u64 = MAX_SECS - OPERATION_SECS - 5;
/// The freeze operation deadline (§4.4), on the manual clock.
const OPERATION_SECS: u64 = 10;
/// The controller's own timeout on the freeze reply (§4.5 step 2).
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mountinfo")
            .join(name),
    )
    .unwrap()
}

/// A guest: its kernel (freeze depth persists across an agent restart,
/// not across a reboot), the marker's directory, and the running agent
/// instance, if any.
struct Guest {
    kernel: Arc<FakeKernel>,
    dir: tempfile::TempDir,
    clock: ManualClock,
    agent: Mutex<Option<Arc<Dispatcher>>>,
    /// Signalled when the connection to the agent is lost (a crash, a
    /// reboot): an in-flight request fails instead of waiting for ever.
    lost: Notify,
    /// The guest's mount table (a fixture name).
    mounts: &'static str,
}

impl Guest {
    /// `/` (8:1) and `/home` (8:2), both freezable.
    fn new() -> Arc<Guest> {
        Self::with_mounts("simple.txt")
    }

    fn with_mounts(mounts: &'static str) -> Arc<Guest> {
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let guest = Arc::new(Guest {
            kernel,
            dir: tempfile::tempdir().unwrap(),
            clock: ManualClock::new(),
            agent: Mutex::new(None),
            lost: Notify::new(),
            mounts,
        });
        guest.start_agent();
        guest
    }

    /// Starts an agent instance: in recovery mode when the marker of a
    /// previous instance is present (§4.4), exactly as `main` does.
    fn start_agent(&self) {
        let marker = Marker::open(self.dir.path().join("frozen")).unwrap();
        let recovery = marker.exists();
        let mut config = Config::default();
        config.agent.fsfreeze_idle_timeout_secs = IDLE_SECS;
        config.agent.fsfreeze_max_timeout_secs = MAX_SECS;
        let state = if recovery {
            FreezeStateMachine::starting_frozen()
        } else {
            FreezeStateMachine::new()
        };
        let ctx = Arc::new(
            Context::new(
                Arc::new(config),
                Arc::new(state),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(self.kernel.clone() as Arc<dyn KernelOps>)
            .with_mounts(Arc::new(StaticMounts(fixture(self.mounts))))
            .with_freeze_clock(Arc::new(self.clock.clone()))
            .with_freeze_operation_timeout(Duration::from_secs(OPERATION_SECS)),
        );
        if recovery {
            fsfreeze::start_recovery(&ctx).unwrap();
        }
        *self.agent.lock().unwrap() = Some(Arc::new(Dispatcher::new(ctx)));
    }

    fn agent(&self) -> Option<Arc<Dispatcher>> {
        self.agent.lock().unwrap().clone()
    }

    fn ctx(&self) -> Arc<Context> {
        Arc::clone(self.agent().expect("an agent is running").context())
    }

    /// The agent process dies (SIGKILL): its watchdog goes with it, the
    /// kernel keeps every freeze, the marker stays. In-flight requests
    /// are lost.
    fn crash_agent(&self) {
        self.lost.notify_waiters();
        if let Some(agent) = self.agent.lock().unwrap().take() {
            // Everything the instance had in flight dies with it: the
            // watchdog, a freeze walk waiting on its workers. An ioctl
            // already in the kernel completes on its own, as it would.
            agent.context().abort_tasks();
        }
    }

    /// The agent restarts (systemd `Restart=always`): recovery mode when
    /// the marker is there.
    fn restart_agent(&self) {
        self.crash_agent();
        self.start_agent();
    }

    /// The whole guest reboots: every freeze is gone with the kernel's
    /// state, `/run` is cleared with the marker, the agent starts thawed.
    fn reboot(&self) {
        self.crash_agent();
        self.kernel.reset_freeze_depths();
        let _ = std::fs::remove_file(self.dir.path().join("frozen"));
        self.start_agent();
    }

    /// One request over the channel; `Err` when the connection is lost
    /// before the reply.
    async fn request(&self, json: &str) -> Result<Value, String> {
        let Some(agent) = self.agent() else {
            return Err("connection lost".to_owned());
        };
        let lost = self.lost.notified();
        tokio::pin!(lost);
        lost.as_mut().enable();
        let handling = agent.handle(DecodeEvent::Frame {
            bytes: json.as_bytes().to_vec(),
            sentinel: false,
        });
        // A connection lost is lost whatever the dead instance's tasks
        // produced as they were torn down: nothing of that reaches a
        // controller across a real crash.
        let reply = tokio::select! {
            biased;
            () = &mut lost => Err("connection lost".to_owned()),
            reply = handling => {
                let reply = reply.ok_or_else(|| "no reply".to_owned())?;
                serde_json::from_slice(&reply[..reply.len() - 1]).map_err(|e| e.to_string())
            }
        };
        // Let the agent's own tasks act on the request at the time it was
        // made (a heartbeat reaches the watchdog on its next poll): on the
        // paused clock a jump straight after the reply would otherwise be
        // applied to a refresh the watchdog has not processed yet, which
        // no real clock does.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        reply
    }

    fn state(&self) -> FreezeState {
        self.ctx().state.current()
    }

    fn fithaws(&self) -> usize {
        self.kernel
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::Fithaw(_)))
            .count()
    }

    /// A third party thaws `mount` behind the agent's back.
    fn external_thaw(&self, mount: &str) {
        let handle = self
            .kernel
            .open_mount(Path::new(mount), if mount == A { (8, 1) } else { (8, 2) })
            .unwrap();
        while self.kernel.fithaw(&handle).is_ok() {}
    }
}

/// The controller's verdict on one cycle (§4.5 step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Every required superblock was frozen by this cycle's operation
    /// when the freeze replied and still frozen when the thaw ran.
    Quiesced {
        /// Consistency points established during the cycle.
        volumes: Vec<String>,
    },
    /// Continuity could not be established; the reason.
    Rejected(String),
}

/// One cycle of the reference controller: freeze, cut with heartbeats,
/// thaw, verdict. The controller measures the lease from the instant it
/// sent the freeze request (§4.5 "Timing assumptions").
struct Cycle {
    guest: Arc<Guest>,
    required: Vec<String>,
    started: tokio::time::Instant,
    volumes: Vec<String>,
}

impl std::fmt::Debug for Cycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cycle")
            .field("required", &self.required)
            .field("volumes", &self.volumes)
            .finish_non_exhaustive()
    }
}

impl Cycle {
    /// Step 2: the freeze. `Err` is the rejection, after the controller
    /// has sent its thaw and waited for `thawed`.
    async fn freeze(guest: Arc<Guest>, required: &[&str]) -> Result<Cycle, Verdict> {
        let required: Vec<String> = required.iter().map(|s| (*s).to_owned()).collect();
        let started = tokio::time::Instant::now();
        let request = json!({
            "execute": "guest-fsfreeze-freeze-list",
            "arguments": {"mountpoints": required},
        })
        .to_string();
        let reply = tokio::time::timeout(CLIENT_TIMEOUT, guest.request(&request)).await;
        let count = match reply {
            Err(_) => {
                return Err(
                    Self::reject(&guest, "no freeze reply within the client timeout").await,
                );
            }
            Ok(Err(lost)) => return Err(Self::reject(&guest, &format!("freeze: {lost}")).await),
            Ok(Ok(reply)) => match reply.get("return").and_then(Value::as_u64) {
                Some(count) => count,
                None => {
                    let desc = reply["error"]["desc"].as_str().unwrap_or("?").to_owned();
                    return Err(Self::reject(&guest, &format!("freeze failed: {desc}")).await);
                }
            },
        };
        if count != required.len() as u64 {
            return Err(Self::reject(
                &guest,
                &format!(
                    "freeze covered {count} of {} required superblocks",
                    required.len()
                ),
            )
            .await);
        }
        Ok(Cycle {
            guest,
            required,
            started,
            volumes: Vec::new(),
        })
    }

    /// The lease budget left, on the controller's own clock.
    fn budget_left(&self) -> Duration {
        Duration::from_secs(BUDGET_SECS).saturating_sub(self.started.elapsed())
    }

    /// Step 3: a heartbeat; every answer must be `frozen`.
    async fn heartbeat(&self) -> Result<(), String> {
        let reply = self
            .guest
            .request(r#"{"execute":"guest-fsfreeze-status"}"#)
            .await?;
        if reply["return"] == "frozen" {
            Ok(())
        } else {
            Err(format!("status answered {reply}"))
        }
    }

    /// Step 3: the consistency point of one volume, established after
    /// `duration` of work with heartbeats every third of the idle
    /// timeout. Stops early, without the point, when the lease budget is
    /// exhausted or a heartbeat fails.
    async fn cut(&mut self, volume: &str, duration: Duration) -> Result<(), String> {
        let step = Duration::from_secs(IDLE_SECS / 3);
        let mut left = duration;
        while !left.is_zero() {
            if self.budget_left().is_zero() {
                return Err(format!("lease budget exhausted before {volume} was cut"));
            }
            let slice = left.min(step);
            tokio::time::sleep(slice).await;
            left -= slice;
            self.heartbeat().await?;
        }
        self.volumes.push(volume.to_owned());
        Ok(())
    }

    /// Step 4 and 5: the thaw and the verdict.
    async fn thaw(self) -> Verdict {
        let reply = match self
            .guest
            .request(r#"{"execute":"guest-fsfreeze-thaw"}"#)
            .await
        {
            Ok(reply) => reply,
            Err(lost) => return Self::reject(&self.guest, &format!("thaw: {lost}")).await,
        };
        let Some(thawed) = reply.get("return").and_then(Value::as_u64) else {
            let desc = reply["error"]["desc"].as_str().unwrap_or("?").to_owned();
            return Self::reject(&self.guest, &format!("thaw failed: {desc}")).await;
        };
        if thawed != self.required.len() as u64 {
            return Verdict::Rejected(format!(
                "thaw found {thawed} of {} required superblocks still frozen",
                self.required.len()
            ));
        }
        // The whole cycle, freeze request to thaw reply, on the
        // controller's clock (§4.5 step 3): the count says the kernel was
        // still frozen, not that it was this cycle's lease that held it.
        let elapsed = self.started.elapsed();
        if elapsed > Duration::from_secs(BUDGET_SECS) {
            return Verdict::Rejected(format!(
                "the thaw replied {}s after the freeze request, beyond the cycle budget of {BUDGET_SECS}s",
                elapsed.as_secs()
            ));
        }
        Verdict::Quiesced {
            volumes: self.volumes,
        }
    }

    /// A rejection: send a thaw whatever happened, wait until the agent
    /// answers `thawed` (bounded), and report the reason.
    async fn reject(guest: &Guest, reason: &str) -> Verdict {
        let _ = guest.request(r#"{"execute":"guest-fsfreeze-thaw"}"#).await;
        for _ in 0..1000 {
            match guest
                .request(r#"{"execute":"guest-fsfreeze-status"}"#)
                .await
            {
                Ok(reply) if reply["return"] == "thawed" => break,
                _ => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
        Verdict::Rejected(reason.to_owned())
    }
}

/// A short yield loop so spawned tasks (the coordinator, the watchdog's
/// drain on the blocking pool) make progress.
async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out: {what}"
        );
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn rejected(verdict: &Verdict, needle: &str) {
    match verdict {
        Verdict::Rejected(reason) => assert!(reason.contains(needle), "{reason}"),
        other => panic!("expected a rejection containing {needle:?}, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_cycle_inside_the_lease_is_quiesced_and_a_long_upload_does_not_revoke_it() {
    let guest = Guest::new();
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(25)).await.unwrap();
    cycle.cut("vol-b", Duration::from_secs(25)).await.unwrap();
    let verdict = cycle.thaw().await;
    assert_eq!(
        verdict,
        Verdict::Quiesced {
            volumes: vec!["vol-a".to_owned(), "vol-b".to_owned()]
        }
    );
    assert_eq!(guest.state(), FreezeState::Thawed);
    // The upload of the established snapshots runs long past the lease:
    // the verdict is a value, nothing revisits it, and the agent has
    // nothing left armed.
    tokio::time::advance(Duration::from_secs(10 * MAX_SECS)).await;
    settle().await;
    assert_eq!(guest.state(), FreezeState::Thawed);
    assert_eq!(
        guest
            .request(r#"{"execute":"guest-fsfreeze-status"}"#)
            .await,
        Ok(json!({"return": "thawed"}))
    );
}

#[tokio::test(start_paused = true)]
async fn a_lease_that_expires_before_the_cut_is_rejected() {
    // Silence for longer than the idle timeout: the watchdog thaws; the
    // snapshot cut afterwards is worthless and the thaw count says so.
    let guest = Guest::new();
    let cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    tokio::time::advance(Duration::from_secs(IDLE_SECS + 1)).await;
    wait_for("watchdog thaw", || guest.state() == FreezeState::Thawed).await;
    // The controller's own heartbeat now says so too, but a controller
    // that only cut and thawed would still be told by the count.
    let err = cycle.heartbeat().await.unwrap_err();
    assert!(err.contains("thawed"), "{err}");
    let verdict = cycle.thaw().await;
    rejected(&verdict, "thaw found 0 of 2");
}

#[tokio::test(start_paused = true)]
async fn a_lease_that_expires_during_the_cut_is_rejected() {
    // Heartbeats keep the idle timeout at bay, but the cut outlasts the
    // hard cap: the controller runs out of budget, stops cutting, and the
    // thaw finds nothing frozen.
    let guest = Guest::new();
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(60)).await.unwrap();
    let err = cycle
        .cut("vol-b", Duration::from_secs(90))
        .await
        .unwrap_err();
    assert!(err.contains("budget exhausted"), "{err}");
    // A controller that is slow to thaw once its budget is gone meets the
    // cap: the agent thawed on its own and the count says so.
    tokio::time::advance(Duration::from_secs(MAX_SECS - BUDGET_SECS + 1)).await;
    wait_for("cap thaw", || guest.state() == FreezeState::Thawed).await;
    let verdict = cycle.thaw().await;
    rejected(&verdict, "thaw found 0 of 2");
}

#[tokio::test(start_paused = true)]
async fn an_expiry_between_two_volume_snapshots_is_rejected() {
    // The first volume is cut inside the lease, the second after the
    // watchdog thawed in between: the verdict covers the cycle, so both
    // are rejected (the first alone is not a consistent set).
    let guest = Guest::new();
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    tokio::time::advance(Duration::from_secs(IDLE_SECS + 1)).await;
    wait_for("watchdog thaw", || guest.state() == FreezeState::Thawed).await;
    // A controller that skipped the heartbeat check would cut vol-b now.
    cycle.volumes.push("vol-b".to_owned());
    let verdict = cycle.thaw().await;
    rejected(&verdict, "thaw found 0 of 2");
}

#[tokio::test(start_paused = true)]
async fn a_freeze_reply_delayed_past_the_client_timeout_is_rejected() {
    // B's FIFREEZE blocks past the controller's timeout: no reply, so the
    // cycle is rejected before any cut; the controller's thaw aborts the
    // operation, and the controller waits for `thawed` before the next
    // cycle, which then succeeds.
    let guest = Guest::new();
    let gate = guest.kernel.script_freeze_gate(B);
    let _release: ReleaseOnDrop = gate.release_on_drop();
    let cycle = tokio::spawn(Cycle::freeze(Arc::clone(&guest), &[A, B]));
    let g = gate.clone();
    wait_for("B blocked", move || g.waiting() == 1).await;
    tokio::time::advance(CLIENT_TIMEOUT + Duration::from_secs(1)).await;
    // The controller has timed out and sent its thaw (an abort); the
    // blocked call still holds the operation.
    wait_for("abort requested", || {
        guest
            .ctx()
            .freeze_op()
            .is_some_and(|op| op.progress().phase == qeminga::freeze_op::Phase::Recovering)
    })
    .await;
    assert!(!cycle.is_finished(), "waiting for thawed");
    gate.release();
    let verdict = cycle.await.unwrap().unwrap_err();
    rejected(&verdict, "no freeze reply within the client timeout");
    assert_eq!(guest.state(), FreezeState::Thawed);
    // A new cycle is sound.
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    assert!(matches!(cycle.thaw().await, Verdict::Quiesced { .. }));
}

#[tokio::test(start_paused = true)]
async fn a_freeze_aborted_by_the_operation_deadline_is_rejected() {
    // The agent gives up first (§4.4): the reply is an error naming the
    // recovery, and the controller rejects and waits for the settlement.
    let guest = Guest::new();
    let gate = guest.kernel.script_freeze_gate(B);
    let _release = gate.release_on_drop();
    let cycle = tokio::spawn(Cycle::freeze(Arc::clone(&guest), &[A, B]));
    let g = gate.clone();
    wait_for("B blocked", move || g.waiting() == 1).await;
    guest.clock.advance(Duration::from_secs(OPERATION_SECS + 1));
    wait_for("aborted", || guest.state() == FreezeState::Thawing).await;
    gate.release();
    let verdict = cycle.await.unwrap().unwrap_err();
    rejected(&verdict, "freeze failed: freeze aborted");
    assert_eq!(guest.state(), FreezeState::Thawed);
}

#[tokio::test(start_paused = true)]
async fn an_agent_restart_while_frozen_keeps_the_verdict_sound() {
    // The agent crashes and restarts mid-cut: the kernel keeps the
    // freezes, the marker puts the new instance into recovery mode, the
    // heartbeats continue over the new connection and the thaw counts
    // the same superblocks. Continuity held, so the cycle is quiesced.
    let guest = Guest::new();
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    guest.restart_agent();
    assert_eq!(guest.state(), FreezeState::Frozen, "recovery mode");
    cycle.cut("vol-b", Duration::from_secs(5)).await.unwrap();
    let verdict = cycle.thaw().await;
    assert!(matches!(verdict, Verdict::Quiesced { .. }), "{verdict:?}");
    assert_eq!(guest.state(), FreezeState::Thawed);
    assert!(!guest.dir.path().join("frozen").exists());
}

#[tokio::test(start_paused = true)]
async fn a_guest_reboot_during_the_cut_is_rejected() {
    // A reboot thaws everything and clears the marker: the new agent
    // starts thawed and the thaw finds nothing frozen.
    let guest = Guest::new();
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    guest.reboot();
    assert_eq!(guest.state(), FreezeState::Thawed);
    let err = cycle.heartbeat().await.unwrap_err();
    assert!(err.contains("thawed"), "{err}");
    let verdict = cycle.thaw().await;
    rejected(&verdict, "thaw found 0 of 2");
}

#[tokio::test(start_paused = true)]
async fn a_crash_before_the_freeze_reply_is_rejected() {
    // The connection is lost while the freeze reply is pending: the
    // controller never learns the count and rejects; over the restarted
    // agent (recovery mode) its thaw drains what the old walk froze.
    let guest = Guest::new();
    let gate = guest.kernel.script_freeze_gate(B);
    let _release = gate.release_on_drop();
    let cycle = tokio::spawn(Cycle::freeze(Arc::clone(&guest), &[A, B]));
    let g = gate.clone();
    wait_for("B blocked", move || g.waiting() == 1).await;
    let dead = guest.ctx();
    guest.restart_agent();
    assert_eq!(guest.state(), FreezeState::Frozen, "marker: recovery mode");
    // The walk freezes the deepest mount first, so B is the target in
    // flight and A was never reached. The controller's thaw over the new
    // agent drains A first: it is held inside FITHAW(A) until the dead
    // walk's FIFREEZE(B) has landed, so the drain provably reaches a B
    // the kernel holds frozen rather than one it froze a moment later.
    let thaw_gate = guest.kernel.script_thaw_gate(A);
    let _release_thaw = thaw_gate.release_on_drop();
    gate.release();
    let k = Arc::clone(&guest.kernel);
    wait_for("B frozen by the dead walk", move || {
        k.tracked_frozen_superblocks() == 1
    })
    .await;
    let g = thaw_gate.clone();
    wait_for("A's thaw blocked", move || g.waiting() == 1).await;
    thaw_gate.release();
    let verdict = cycle.await.unwrap().unwrap_err();
    rejected(&verdict, "freeze: connection lost");
    assert_eq!(guest.state(), FreezeState::Thawed);
    assert_eq!(
        guest.fithaws(),
        3,
        "the recovery thaw drained by pathname: EINVAL on A, a success and EINVAL on B"
    );
    assert_eq!(guest.kernel.tracked_frozen_superblocks(), 0);
    // The dead instance is dead: the FIFREEZE that was in the kernel when
    // it died completed on its own (the recovery thaw above found it), but
    // its walk never concluded, published nothing, wrote no marker and
    // armed no watchdog that could thaw under the next cycle's feet.
    settle().await;
    assert_eq!(dead.state.current(), FreezeState::Freezing);
    assert!(dead.watchdog_slot().is_none());
    assert!(!guest.dir.path().join("frozen").exists());
    let thaws = guest.fithaws();
    tokio::time::advance(Duration::from_secs(10 * MAX_SECS)).await;
    settle().await;
    assert_eq!(guest.fithaws(), thaws, "no ghost watchdog");
}

#[tokio::test(start_paused = true)]
async fn a_thaw_reply_past_the_budget_is_rejected_whatever_the_count() {
    // The agent restarts at t=5 and its recovery re-arms the hard cap from
    // then (§4.4), so the kernel is still frozen at t=115 and the thaw
    // counts both superblocks. The controller's budget runs from its own
    // freeze request: a thaw reply past it cannot be a quiesced cycle,
    // whatever the count says.
    let guest = Guest::new();
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    guest.restart_agent();
    cycle
        .cut("vol-b", Duration::from_secs(BUDGET_SECS - 10))
        .await
        .unwrap();
    // The thaw is sent inside the budget; its FITHAW takes long enough
    // for the reply to land past it.
    let gate = guest.kernel.script_thaw_gate(A);
    let _release: ReleaseOnDrop = gate.release_on_drop();
    let thaw = tokio::spawn(cycle.thaw());
    let g = gate.clone();
    wait_for("A's thaw blocked", move || g.waiting() == 1).await;
    tokio::time::advance(Duration::from_secs(10)).await;
    gate.release();
    let verdict = thaw.await.unwrap();
    rejected(&verdict, "beyond the cycle budget");
    assert_eq!(guest.state(), FreezeState::Thawed);
}

#[tokio::test(start_paused = true)]
async fn a_new_cycle_after_an_expired_one_quiesces_only_its_own_snapshots() {
    // Cycle 1 expires and is rejected by its own thaw count. The retry
    // is a new cycle whose snapshots are taken again: only those are
    // quiesced, and nothing about cycle 2 revisits cycle 1's verdict.
    let guest = Guest::new();
    let mut cycle1 = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle1.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    tokio::time::advance(Duration::from_secs(IDLE_SECS + 1)).await;
    wait_for("watchdog thaw", || guest.state() == FreezeState::Thawed).await;
    let verdict1 = cycle1.thaw().await;
    rejected(&verdict1, "thaw found 0 of 2");
    let mut cycle2 = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle2.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    cycle2.cut("vol-b", Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        cycle2.thaw().await,
        Verdict::Quiesced {
            volumes: vec!["vol-a".to_owned(), "vol-b".to_owned()]
        }
    );
}

#[tokio::test(start_paused = true)]
async fn a_foreign_refreeze_after_the_expiry_is_the_single_controller_assumptions_limit() {
    // Cycle 1 expires; before its thaw, another party freezes the same
    // superblocks (a second controller, or the same one breaking the
    // one-freeze-per-cycle rule). The thaw count is 2 again and cannot
    // tell the substitution apart: this is the boundary of what the
    // existing replies establish (§4.5), stated here as a pinned fact,
    // and the reason OQ-9 proposes an opt-in operation identity for
    // deployments that cannot make the single-controller assumption.
    let guest = Guest::new();
    let cycle1 = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    tokio::time::advance(Duration::from_secs(IDLE_SECS + 1)).await;
    wait_for("watchdog thaw", || guest.state() == FreezeState::Thawed).await;
    let foreign = guest
        .request(
            r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/","/home"]}}"#,
        )
        .await
        .unwrap();
    assert_eq!(foreign, json!({"return": 2}));
    let verdict = cycle1.thaw().await;
    assert!(
        matches!(verdict, Verdict::Quiesced { .. }),
        "the count alone accepts a substituted freeze: {verdict:?}"
    );
    // The agent's side of the rule that prevents this for one controller:
    // while an operation is unresolved, a second freeze is refused, so a
    // controller that never refreezes inside a cycle cannot be fooled by
    // its own agent.
    let cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    let again = guest
        .request(
            r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/","/home"]}}"#,
        )
        .await
        .unwrap();
    assert_eq!(
        again["error"]["desc"],
        "filesystems are frozen; retry after thaw"
    );
    assert!(matches!(cycle.thaw().await, Verdict::Quiesced { .. }));
}

#[tokio::test(start_paused = true)]
async fn an_external_thaw_behind_a_frozen_status_is_rejected() {
    // Someone thaws /home directly. The agent's status keeps answering
    // `frozen` (it is a state, not a certificate) and the heartbeats keep
    // the lease; the thaw count is what tells the controller.
    let guest = Guest::new();
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &[A, B]).await.unwrap();
    cycle.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    guest.external_thaw(B);
    cycle.cut("vol-b", Duration::from_secs(5)).await.unwrap();
    assert_eq!(guest.state(), FreezeState::Frozen);
    let verdict = cycle.thaw().await;
    rejected(&verdict, "thaw found 1 of 2");
}

#[tokio::test(start_paused = true)]
async fn a_request_that_is_not_fully_covered_is_rejected_before_any_cut() {
    // A required mount point outside the plan: the count falls short
    // and the controller thaws and rejects without cutting anything.
    let guest = Guest::new();
    let verdict = Cycle::freeze(Arc::clone(&guest), &[A, "/nope"])
        .await
        .unwrap_err();
    rejected(&verdict, "freeze covered 1 of 2");
    assert_eq!(guest.state(), FreezeState::Thawed);
    assert!(!guest.dir.path().join("frozen").exists());
}

#[tokio::test(start_paused = true)]
async fn a_mount_moved_over_a_newer_one_is_what_a_request_protects() {
    // The external review's follow-up counterexample: A (8:5) was mounted
    // before B (8:2), then moved over B at /data, so A keeps the earlier
    // row while /data leads to A. A cycle requiring /data must protect A:
    // the freeze opens /data on 8:5 and nothing on 8:2 before the thaw,
    // the counts are 1 and 1, and the verdict is quiesced for the right
    // filesystem.
    let guest = Guest::with_mounts("moved_mount.txt");
    let mut cycle = Cycle::freeze(Arc::clone(&guest), &["/data"]).await.unwrap();
    let before_thaw: Vec<Call> = guest
        .kernel
        .calls()
        .into_iter()
        .take_while(|c| !matches!(c, Call::Fithaw(_)))
        .collect();
    assert!(
        before_thaw.contains(&Call::Open("/data".into(), (8, 5))),
        "{before_thaw:?}"
    );
    assert!(
        !before_thaw
            .iter()
            .any(|c| matches!(c, Call::Open(_, dev) if *dev == (8, 2))),
        "B was never touched by the freeze: {before_thaw:?}"
    );
    cycle.cut("vol-a", Duration::from_secs(5)).await.unwrap();
    assert_eq!(
        cycle.thaw().await,
        Verdict::Quiesced {
            volumes: vec!["vol-a".to_owned()]
        }
    );
    assert_eq!(guest.state(), FreezeState::Thawed);
    assert_eq!(guest.kernel.tracked_frozen_superblocks(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_requirement_hidden_by_a_mount_over_its_ancestor_is_rejected() {
    // /data/nested hangs off the mount at /data that a later mount covers:
    // the pathname leads into the covering filesystem, where nothing is
    // mounted, so the name selects nothing and the cycle is rejected
    // before any cut.
    let guest = Guest::with_mounts("hidden_nested.txt");
    let verdict = Cycle::freeze(Arc::clone(&guest), &["/data/nested"])
        .await
        .unwrap_err();
    rejected(&verdict, "freeze covered 0 of 1");
    assert_eq!(guest.state(), FreezeState::Thawed);
    assert!(!guest.dir.path().join("frozen").exists());
}

#[tokio::test(start_paused = true)]
async fn a_superblock_the_cycle_never_froze_cannot_hold_its_thaw() {
    // directory_overmount.txt: A (8:2) at /data/nested is hidden under B
    // (8:3) at /data and reachable by no name; C (8:4) is at the
    // /data/nested B provides. A cycle requiring /data/nested protects C
    // (count 1) and its thaw drains C alone (§4.2 "Thaw scope"): A, never
    // this cycle's obligation, cannot hold the marker; the verdict is
    // quiesced and the next cycle is admitted at once, twice over.
    let guest = Guest::with_mounts("directory_overmount.txt");
    guest.kernel.script_mount_device("/data/nested", (8, 4));
    for cycle_no in 0..2 {
        let mut cycle = Cycle::freeze(Arc::clone(&guest), &["/data/nested"])
            .await
            .unwrap_or_else(|verdict| panic!("cycle {cycle_no}: {verdict:?}"));
        cycle.cut("vol-c", Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            cycle.thaw().await,
            Verdict::Quiesced {
                volumes: vec!["vol-c".to_owned()]
            },
            "cycle {cycle_no}"
        );
        assert_eq!(guest.state(), FreezeState::Thawed);
        assert!(!guest.dir.path().join("frozen").exists());
        assert_eq!(guest.kernel.tracked_frozen_superblocks(), 0);
    }
    // A was never opened, for a freeze or a drain: nothing of this
    // cycle's touched a filesystem it did not freeze.
    let calls = guest.kernel.calls();
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, Call::Open(_, dev) if *dev == (8, 2))),
        "{calls:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_hidden_mount_point_cannot_stand_in_for_an_unprotected_requirement() {
    // The external review's counterexample against the coverage
    // certificate: 8:3 is mounted over 8:2 at /data, and 8:2 keeps /data
    // as its (hidden) first name beside the alias /data-alias it is still
    // reachable at. A controller requiring /data and /required, the
    // latter unfreezable, must be rejected: were the hidden name to
    // select 8:2 too, the freeze would answer 2, the thaw 2, and the
    // cycle would be accepted with /required never protected. A name
    // selects the superblock mounted at that path now, so the count is
    // 1 and the controller fails closed.
    let guest = Guest::with_mounts("hidden_mount.txt");
    let verdict = Cycle::freeze(Arc::clone(&guest), &["/data", "/required"])
        .await
        .unwrap_err();
    rejected(&verdict, "freeze covered 1 of 2");
    // What the freeze reached was 8:3 through /data, and nothing else.
    let frozen: Vec<(std::path::PathBuf, (u32, u32))> = guest
        .kernel
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Open(p, dev) => Some((p, dev)),
            _ => None,
        })
        .take_while(|(_, dev)| *dev != (8, 1))
        .collect();
    assert!(
        frozen.contains(&(std::path::PathBuf::from("/data"), (8, 3))),
        "{frozen:?}"
    );
    assert!(!frozen.iter().any(|(_, dev)| *dev == (8, 2)), "{frozen:?}");
    // The rejection's thaw drained it: nothing left frozen, no marker.
    assert_eq!(guest.state(), FreezeState::Thawed);
    assert_eq!(guest.kernel.tracked_frozen_superblocks(), 0);
    assert!(!guest.dir.path().join("frozen").exists());
}
