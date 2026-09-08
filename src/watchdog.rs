//! The freeze watchdog (design §4.4; AC11; C-14).
//!
//! Armed when the state becomes `Frozen`. It waits, with `tokio::select!`,
//! on the earlier of the idle deadline (`now + idle`, reset by every
//! `guest-fsfreeze-status` heartbeat) and the hard cap (`armed + max`,
//! never extended), a refresh signal, and a cancellation signal. When a
//! deadline wins it first claims the `Frozen → Thawing` transition; only
//! if that claim succeeds does it run the thaw callback, which hands the
//! drain to `spawn_blocking`. A manual thaw that claimed first makes the
//! watchdog exit quietly, and vice versa: exactly one drain ever runs.
//!
//! Cancellation only stops the timer loop. The task is never aborted, so a
//! drain that already started runs to completion.
#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};

use crate::config::AgentConfig;
use crate::state::{FreezeStateMachine, ThawToken};

/// A boxed future returned by the thaw callback.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The drain the watchdog runs after winning the `Thawing` claim.
pub type ThawFn = Arc<dyn Fn(ThawToken) -> BoxFuture<'static, ()> + Send + Sync>;

/// Timeouts from `[agent]` (§8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogConfig {
    /// Auto-thaw after this long without a heartbeat.
    pub idle: Duration,
    /// Auto-thaw this long after arming regardless of heartbeats.
    pub max: Duration,
}

impl From<&AgentConfig> for WatchdogConfig {
    fn from(agent: &AgentConfig) -> Self {
        WatchdogConfig {
            idle: Duration::from_secs(agent.fsfreeze_idle_timeout_secs),
            max: Duration::from_secs(agent.fsfreeze_max_timeout_secs),
        }
    }
}

/// Handle to an armed watchdog.
#[derive(Debug)]
pub struct WatchdogHandle {
    refresh: Arc<Notify>,
    cancel: Arc<Notify>,
    task: JoinHandle<()>,
}

impl WatchdogHandle {
    /// Resets the idle deadline to `now + idle` (a status heartbeat).
    pub fn refresh(&self) {
        self.refresh.notify_one();
    }

    /// Stops the timer loop. A drain that already started is unaffected.
    pub fn cancel(&self) {
        self.cancel.notify_one();
    }

    /// `true` once the watchdog task has exited (cancelled, lost the race,
    /// or finished its drain).
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// The watchdog factory.
#[derive(Debug, Clone, Copy)]
pub struct Watchdog;

impl Watchdog {
    /// Spawns the timer task. Must be called from within a Tokio runtime.
    pub fn arm(
        cfg: WatchdogConfig,
        state: Arc<FreezeStateMachine>,
        thaw: ThawFn,
    ) -> WatchdogHandle {
        let refresh = Arc::new(Notify::new());
        let cancel = Arc::new(Notify::new());
        // The arm time is taken here, not on the task's first poll, so the
        // hard cap is measured from the moment the state became Frozen.
        let armed = Instant::now();
        let task = tokio::spawn(run(
            cfg,
            armed,
            state,
            thaw,
            Arc::clone(&refresh),
            Arc::clone(&cancel),
        ));
        WatchdogHandle {
            refresh,
            cancel,
            task,
        }
    }
}

async fn run(
    cfg: WatchdogConfig,
    armed: Instant,
    state: Arc<FreezeStateMachine>,
    thaw: ThawFn,
    refresh: Arc<Notify>,
    cancel: Arc<Notify>,
) {
    let hard_deadline = armed + cfg.max;
    let mut idle_deadline = armed + cfg.idle;
    loop {
        // `biased` polls the branches in order: a cancel first, then the
        // two deadlines, and a heartbeat last. A heartbeat extends the
        // idle deadline, never the hard cap, and a refresh that is ready
        // at every poll cannot keep an expired deadline from being taken
        // (with the refresh branch ahead of the deadlines only Tokio's
        // cooperative budget bounded that starvation).
        tokio::select! {
            biased;
            () = cancel.notified() => {
                tracing::debug!(event = "watchdog_cancelled", "freeze watchdog cancelled");
                return;
            }
            () = sleep_until(hard_deadline) => {
                expire(&state, &thaw, "hard_cap").await;
                return;
            }
            () = sleep_until(idle_deadline) => {
                expire(&state, &thaw, "idle_timeout").await;
                return;
            }
            () = refresh.notified() => {
                idle_deadline = Instant::now() + cfg.idle;
            }
        }
    }
}

/// The watchdog expired: claim the thaw and run the drain, unless another
/// thaw already claimed it.
async fn expire(state: &FreezeStateMachine, thaw: &ThawFn, cause: &'static str) {
    match state.claim_thaw_from_frozen() {
        Ok(token) => {
            tracing::warn!(
                event = "watchdog_thaw",
                cause,
                "freeze watchdog expired; thawing"
            );
            thaw(token).await;
        }
        Err(err) => {
            tracing::debug!(event = "watchdog_lost_race", cause, error = %err, "another thaw is in progress");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::FreezeState;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::advance;

    const CFG: WatchdogConfig = WatchdogConfig {
        idle: Duration::from_secs(30),
        max: Duration::from_secs(300),
    };

    /// A thaw callback that completes the transition and counts calls.
    fn counting_thaw(state: Arc<FreezeStateMachine>) -> (ThawFn, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let thaw: ThawFn = Arc::new(move |token: ThawToken| {
            let state = Arc::clone(&state);
            let calls = Arc::clone(&calls2);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                state.thaw_succeeded(token);
            })
        });
        (thaw, calls)
    }

    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_thaws_when_no_heartbeat() {
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        advance(Duration::from_secs(29)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.current(), FreezeState::Frozen);
        advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.current(), FreezeState::Thawed);
        assert!(handle.is_finished());
        // Nothing more ever happens.
        advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_refresh_extends_deadline() {
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        for _ in 0..6 {
            advance(Duration::from_secs(15)).await;
            settle().await;
            handle.refresh();
            settle().await;
        }
        // t = 90 s, last refresh at 90 s.
        advance(Duration::from_secs(10)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            state.current(),
            FreezeState::Frozen,
            "still frozen at 100 s"
        );
        assert!(!handle.is_finished());
        // Heartbeats stop: 30 s after the last one it thaws.
        advance(Duration::from_secs(20)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.current(), FreezeState::Thawed);
    }

    #[tokio::test(start_paused = true)]
    async fn hard_cap_thaws_despite_heartbeats() {
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        let mut elapsed = 0;
        while elapsed < 300 {
            advance(Duration::from_secs(15)).await;
            settle().await;
            elapsed += 15;
            if elapsed < 300 {
                assert_eq!(state.current(), FreezeState::Frozen, "at {elapsed} s");
                handle.refresh();
                settle().await;
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.current(),
            FreezeState::Thawed,
            "thawed at 300 s (AC11)"
        );
        assert!(handle.is_finished());
        // A refresh after the fact is harmless.
        handle.refresh();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_heartbeat_storm_cannot_defer_the_hard_cap() {
        // Real time, short cap: a thread refreshes the watchdog in a busy
        // loop, so a refresh is ready at every poll of the timer loop.
        // The hard deadline must still be taken as soon as it expires: a
        // refresh may extend the idle deadline, never the hard cap, and a
        // continuously ready refresh branch must not starve the deadline
        // branch (Tokio's `biased` select polls in order).
        use std::sync::atomic::AtomicBool;
        let cfg = WatchdogConfig {
            idle: Duration::from_millis(50),
            max: Duration::from_millis(200),
        };
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let started = std::time::Instant::now();
        let handle = Watchdog::arm(cfg, Arc::clone(&state), thaw);
        let stop = Arc::new(AtomicBool::new(false));
        let storm = {
            let refresh = Arc::clone(&handle.refresh);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    refresh.notify_one();
                    // A permit is re-armed at every scheduling opportunity
                    // without starving the runtime on a loaded machine.
                    std::thread::yield_now();
                }
            })
        };
        let mut thawed_after = None;
        while started.elapsed() < Duration::from_secs(10) {
            if calls.load(Ordering::SeqCst) == 1 {
                thawed_after = Some(started.elapsed());
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        stop.store(true, Ordering::Relaxed);
        storm.join().unwrap();
        let after = thawed_after.expect("the hard cap never fired under the heartbeat storm");
        // Generous in real time (the suite runs in parallel on loaded CI
        // runners): what matters is that the cap fires at all, and not
        // before its time.
        assert!(
            after < Duration::from_secs(5),
            "hard cap deferred to {after:?} by the storm"
        );
        assert!(
            after >= Duration::from_millis(200),
            "not before the cap: {after:?}"
        );
        assert_eq!(state.current(), FreezeState::Thawed);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(handle.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_prevents_thaw() {
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        advance(Duration::from_secs(10)).await;
        settle().await;
        handle.cancel();
        settle().await;
        assert!(handle.is_finished());
        advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.current(), FreezeState::Frozen);
        // Cancelling twice, or before the task ever polled, is fine.
        handle.cancel();
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        handle.cancel();
        advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(handle.is_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn manual_thaw_and_deadline_race_produce_exactly_one_drain() {
        // Case 1: the manual thaw claims first, at the very instant the
        // deadline expires; the watchdog loses and runs nothing.
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        advance(Duration::from_secs(30)).await;
        let token = state.claim_thaw().expect("manual claim wins");
        settle().await;
        assert!(handle.is_finished(), "the watchdog exits quietly");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.current(), FreezeState::Thawing);
        state.thaw_succeeded(token);

        // Case 2: the deadline wins; the manual claim fails while the
        // drain runs.
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let gate = Arc::new(Notify::new());
        let gate2 = Arc::clone(&gate);
        let drains = Arc::new(AtomicUsize::new(0));
        let drains2 = Arc::clone(&drains);
        let state2 = Arc::clone(&state);
        let thaw: ThawFn = Arc::new(move |token| {
            let gate = Arc::clone(&gate2);
            let drains = Arc::clone(&drains2);
            let state = Arc::clone(&state2);
            Box::pin(async move {
                drains.fetch_add(1, Ordering::SeqCst);
                gate.notified().await;
                state.thaw_succeeded(token);
            })
        });
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        advance(Duration::from_secs(30)).await;
        settle().await;
        assert_eq!(drains.load(Ordering::SeqCst), 1);
        assert_eq!(state.current(), FreezeState::Thawing);
        assert!(state.claim_thaw().is_err(), "manual thaw loses");
        assert!(!handle.is_finished(), "drain still running");
        gate.notify_one();
        settle().await;
        assert!(handle.is_finished());
        assert_eq!(state.current(), FreezeState::Thawed);
        assert_eq!(drains.load(Ordering::SeqCst), 1);

        // Case 3: the deadline fires after a manual thaw already completed
        // (cancel not yet delivered): no recovery drain is started.
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        let token = state.claim_thaw().unwrap();
        state.thaw_succeeded(token);
        advance(Duration::from_secs(30)).await;
        settle().await;
        assert!(handle.is_finished());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(state.current(), FreezeState::Thawed);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_handle_is_dropped_safely_after_thaw() {
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        advance(Duration::from_secs(30)).await;
        settle().await;
        assert!(handle.is_finished());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(handle);
        settle().await;
        // Dropping a live handle does not abort the task either: the loop
        // keeps running until its deadline.
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let (thaw, calls) = counting_thaw(Arc::clone(&state));
        let handle = Watchdog::arm(CFG, Arc::clone(&state), thaw);
        drop(handle);
        advance(Duration::from_secs(30)).await;
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(state.current(), FreezeState::Thawed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_blocking_handles_are_not_treated_as_cancellable() {
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let started = Arc::new(Notify::new());
        let started2 = Arc::clone(&started);
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        let state2 = Arc::clone(&state);
        let thaw: ThawFn = Arc::new(move |token| {
            let started = Arc::clone(&started2);
            let log = Arc::clone(&log2);
            let state = Arc::clone(&state2);
            Box::pin(async move {
                started.notify_one();
                // The drain: blocking work that must run to completion.
                let done = tokio::task::spawn_blocking(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    "drained"
                })
                .await
                .unwrap();
                log.lock().unwrap().push(done);
                state.thaw_succeeded(token);
            })
        });
        let cfg = WatchdogConfig {
            idle: Duration::from_millis(20),
            max: Duration::from_secs(10),
        };
        let handle = Watchdog::arm(cfg, Arc::clone(&state), thaw);
        started.notified().await;
        // Cancel while the drain is in flight: it must not be interrupted.
        handle.cancel();
        handle.refresh();
        assert!(!handle.is_finished());
        tokio::time::timeout(Duration::from_secs(5), async {
            while !handle.is_finished() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("drain completes");
        assert_eq!(*log.lock().unwrap(), ["drained"]);
        assert_eq!(state.current(), FreezeState::Thawed);
    }

    #[test]
    fn config_maps_seconds_to_durations() {
        let agent = AgentConfig::default();
        let cfg = WatchdogConfig::from(&agent);
        assert_eq!(cfg.idle, Duration::from_secs(30));
        assert_eq!(cfg.max, Duration::from_secs(300));
    }
}
