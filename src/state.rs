//! Freeze state machine (design §4.2 diagram, §4.4 atomic claim of
//! `Thawing`; C-6, C-7).
//!
//! ```text
//! [*] --> Thawed   : no recovery marker
//! [*] --> Frozen   : recovery marker present
//! Thawed   --> Freezing : begin_freeze
//! Freezing --> Frozen   : freeze_succeeded
//! Freezing --> Thawed   : freeze_failed (rollback complete)
//! Frozen   --> Thawing  : claim_thaw (thaw request or watchdog deadline)
//! Thawed   --> Thawing  : claim_thaw (recovery drain)
//! Thawing  --> Thawed   : thaw_succeeded (drain complete, marker removed)
//! Thawing  --> Frozen   : thaw_failed (unrecoverable; marker retained)
//! ```
//!
//! Transitions out of `Freezing`/`Thawing` require a token that only the
//! successful `begin_freeze`/`claim_thaw` call hands out, so two
//! concurrent claimants (the thaw handler and the watchdog) can never both
//! believe they own the drain. There is no global singleton: `main` creates
//! one [`FreezeStateMachine`] behind an `Arc` and shares it (C-6).
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Mutex;

/// The lifecycle state of the filesystem freeze (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeState {
    /// No freeze in progress.
    Thawed,
    /// `FIFREEZE` calls are being issued.
    Freezing,
    /// Filesystems are (believed to be) frozen.
    Frozen,
    /// `FITHAW` drains are being issued.
    Thawing,
}

impl FreezeState {
    /// Lowercase spelling used in audit records and `guest-fsfreeze-status`.
    pub const fn as_str(self) -> &'static str {
        match self {
            FreezeState::Thawed => "thawed",
            FreezeState::Freezing => "freezing",
            FreezeState::Frozen => "frozen",
            FreezeState::Thawing => "thawing",
        }
    }

    /// `true` for every state except [`FreezeState::Thawed`]: the frozen
    /// gate rejects non-safe commands whenever a freeze may be in effect
    /// (C-7).
    pub const fn is_frozen_for_gate(self) -> bool {
        !matches!(self, FreezeState::Thawed)
    }
}

impl fmt::Display for FreezeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A transition that is not allowed from the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("cannot {attempted} while {current}")]
pub struct TransitionError {
    /// What was attempted (`"begin freeze"`, `"claim thaw"`).
    pub attempted: &'static str,
    /// The state at the time of the attempt.
    pub current: FreezeState,
}

/// Proof that the holder moved the machine into `Freezing`. Consumed by
/// [`FreezeStateMachine::freeze_succeeded`] or
/// [`FreezeStateMachine::freeze_failed`]. Not `Clone`, not constructible
/// outside this module.
#[derive(Debug)]
#[must_use = "a freeze that is never completed leaves the machine in Freezing"]
pub struct FreezeToken {
    _private: (),
}

/// Proof that the holder won the `Thawing` transition. Consumed by
/// [`FreezeStateMachine::thaw_succeeded`] or
/// [`FreezeStateMachine::thaw_failed`]. Not `Clone`, not constructible
/// outside this module.
#[derive(Debug)]
#[must_use = "a thaw that is never completed leaves the machine in Thawing"]
pub struct ThawToken {
    origin: FreezeState,
}

impl ThawToken {
    /// The state the thaw was claimed from: `Frozen` for a normal thaw,
    /// `Thawed` for a recovery drain.
    pub const fn origin(&self) -> FreezeState {
        self.origin
    }

    /// `true` when this thaw is a recovery drain from `Thawed`.
    pub const fn is_recovery_drain(&self) -> bool {
        matches!(self.origin, FreezeState::Thawed)
    }
}

/// Mutex-guarded freeze state with token-checked transitions.
#[derive(Debug)]
pub struct FreezeStateMachine {
    state: Mutex<FreezeState>,
}

impl Default for FreezeStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl FreezeStateMachine {
    /// Starts in `Thawed` (no recovery marker).
    pub fn new() -> Self {
        Self::starting_in(FreezeState::Thawed)
    }

    /// Starts in `Frozen` (recovery marker present, §4.4).
    pub fn starting_frozen() -> Self {
        Self::starting_in(FreezeState::Frozen)
    }

    /// Starts in an explicit state.
    pub fn starting_in(state: FreezeState) -> Self {
        FreezeStateMachine {
            state: Mutex::new(state),
        }
    }

    /// The current state.
    pub fn current(&self) -> FreezeState {
        *self.lock()
    }

    /// `true` whenever the state is not `Thawed` (C-7).
    pub fn is_frozen_for_gate(&self) -> bool {
        self.current().is_frozen_for_gate()
    }

    /// `Thawed → Freezing`.
    pub fn begin_freeze(&self) -> Result<FreezeToken, TransitionError> {
        let mut state = self.lock();
        match *state {
            FreezeState::Thawed => {
                *state = FreezeState::Freezing;
                Ok(FreezeToken { _private: () })
            }
            current => Err(TransitionError {
                attempted: "begin freeze",
                current,
            }),
        }
    }

    /// `Freezing → Frozen`.
    pub fn freeze_succeeded(&self, token: FreezeToken) {
        drop(token);
        *self.lock() = FreezeState::Frozen;
    }

    /// `Freezing → Thawed` (rollback finished).
    pub fn freeze_failed(&self, token: FreezeToken) {
        drop(token);
        *self.lock() = FreezeState::Thawed;
    }

    /// `Frozen → Thawing`, or `Thawed → Thawing` for a recovery drain.
    /// Exactly one of any number of concurrent callers succeeds.
    pub fn claim_thaw(&self) -> Result<ThawToken, TransitionError> {
        let mut state = self.lock();
        match *state {
            origin @ (FreezeState::Frozen | FreezeState::Thawed) => {
                *state = FreezeState::Thawing;
                Ok(ThawToken { origin })
            }
            current => Err(TransitionError {
                attempted: "claim thaw",
                current,
            }),
        }
    }

    /// `Frozen → Thawing` only; unlike [`claim_thaw`](Self::claim_thaw) a
    /// `Thawed` machine is *not* moved into a recovery drain. Used by the
    /// watchdog so that a deadline firing after a completed manual thaw
    /// does not start an unnecessary drain (§4.4).
    pub fn claim_thaw_from_frozen(&self) -> Result<ThawToken, TransitionError> {
        let mut state = self.lock();
        match *state {
            FreezeState::Frozen => {
                *state = FreezeState::Thawing;
                Ok(ThawToken {
                    origin: FreezeState::Frozen,
                })
            }
            current => Err(TransitionError {
                attempted: "claim thaw from frozen",
                current,
            }),
        }
    }

    /// `Thawing → Thawed` (drain complete, marker removed).
    pub fn thaw_succeeded(&self, token: ThawToken) {
        drop(token);
        *self.lock() = FreezeState::Thawed;
    }

    /// `Thawing → Frozen` (unrecoverable thaw failure, marker retained).
    pub fn thaw_failed(&self, token: ThawToken) {
        drop(token);
        *self.lock() = FreezeState::Frozen;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FreezeState> {
        // The guarded value is a plain enum, so a poisoned lock (a panic
        // elsewhere while holding it) leaves a consistent state.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn starts_thawed_by_default() {
        assert_eq!(FreezeStateMachine::new().current(), FreezeState::Thawed);
        assert_eq!(FreezeStateMachine::default().current(), FreezeState::Thawed);
        assert!(!FreezeStateMachine::new().is_frozen_for_gate());
    }

    #[test]
    fn can_start_frozen_for_recovery() {
        let sm = FreezeStateMachine::starting_frozen();
        assert_eq!(sm.current(), FreezeState::Frozen);
        assert!(sm.is_frozen_for_gate());
    }

    #[test]
    fn begin_freeze_moves_thawed_to_freezing() {
        let sm = FreezeStateMachine::new();
        let token = sm.begin_freeze().unwrap();
        assert_eq!(sm.current(), FreezeState::Freezing);
        sm.freeze_succeeded(token);
    }

    #[test]
    fn begin_freeze_fails_unless_thawed() {
        for start in [
            FreezeState::Freezing,
            FreezeState::Frozen,
            FreezeState::Thawing,
        ] {
            let sm = FreezeStateMachine::starting_in(start);
            let err = sm.begin_freeze().unwrap_err();
            assert_eq!(
                err,
                TransitionError {
                    attempted: "begin freeze",
                    current: start
                }
            );
            assert_eq!(sm.current(), start, "state must be unchanged");
            assert_eq!(
                err.to_string(),
                format!("cannot begin freeze while {start}")
            );
        }
    }

    #[test]
    fn freeze_succeeded_moves_freezing_to_frozen() {
        let sm = FreezeStateMachine::new();
        let token = sm.begin_freeze().unwrap();
        sm.freeze_succeeded(token);
        assert_eq!(sm.current(), FreezeState::Frozen);
    }

    #[test]
    fn freeze_failed_moves_freezing_to_thawed() {
        let sm = FreezeStateMachine::new();
        let token = sm.begin_freeze().unwrap();
        sm.freeze_failed(token);
        assert_eq!(sm.current(), FreezeState::Thawed);
    }

    #[test]
    fn claim_thaw_moves_frozen_to_thawing() {
        let sm = FreezeStateMachine::starting_frozen();
        let token = sm.claim_thaw().unwrap();
        assert_eq!(sm.current(), FreezeState::Thawing);
        assert_eq!(token.origin(), FreezeState::Frozen);
        assert!(!token.is_recovery_drain());
        sm.thaw_succeeded(token);
    }

    #[test]
    fn claim_thaw_from_thawed_is_recovery_drain() {
        let sm = FreezeStateMachine::new();
        let token = sm.claim_thaw().unwrap();
        assert_eq!(sm.current(), FreezeState::Thawing);
        assert_eq!(token.origin(), FreezeState::Thawed);
        assert!(token.is_recovery_drain());
        sm.thaw_succeeded(token);
        assert_eq!(sm.current(), FreezeState::Thawed);
    }

    #[test]
    fn claim_thaw_fails_while_freezing_or_thawing() {
        for start in [FreezeState::Freezing, FreezeState::Thawing] {
            let sm = FreezeStateMachine::starting_in(start);
            let err = sm.claim_thaw().unwrap_err();
            assert_eq!(
                err,
                TransitionError {
                    attempted: "claim thaw",
                    current: start
                }
            );
            assert_eq!(sm.current(), start);
        }
    }

    #[test]
    fn claim_thaw_from_frozen_refuses_every_other_state() {
        let sm = FreezeStateMachine::starting_frozen();
        let token = sm.claim_thaw_from_frozen().unwrap();
        assert!(!token.is_recovery_drain());
        sm.thaw_succeeded(token);
        for start in [
            FreezeState::Thawed,
            FreezeState::Freezing,
            FreezeState::Thawing,
        ] {
            let sm = FreezeStateMachine::starting_in(start);
            assert!(sm.claim_thaw_from_frozen().is_err(), "{start}");
            assert_eq!(sm.current(), start);
        }
    }

    #[test]
    fn thaw_succeeded_moves_thawing_to_thawed() {
        let sm = FreezeStateMachine::starting_frozen();
        let token = sm.claim_thaw().unwrap();
        sm.thaw_succeeded(token);
        assert_eq!(sm.current(), FreezeState::Thawed);
        // The machine is reusable for the next cycle.
        let token = sm.begin_freeze().unwrap();
        sm.freeze_succeeded(token);
        assert_eq!(sm.current(), FreezeState::Frozen);
    }

    #[test]
    fn thaw_failed_moves_thawing_back_to_frozen() {
        let sm = FreezeStateMachine::starting_frozen();
        let token = sm.claim_thaw().unwrap();
        sm.thaw_failed(token);
        assert_eq!(sm.current(), FreezeState::Frozen);
        // A retry is possible.
        assert!(sm.claim_thaw().is_ok());
    }

    #[test]
    fn only_one_of_two_concurrent_claims_wins() {
        for _ in 0..20 {
            let sm = Arc::new(FreezeStateMachine::starting_frozen());
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let sm = Arc::clone(&sm);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        sm.claim_thaw().is_ok()
                    })
                })
                .collect();
            let wins = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|won| *won)
                .count();
            assert_eq!(wins, 1);
            assert_eq!(sm.current(), FreezeState::Thawing);
        }
    }

    #[test]
    fn tokens_cannot_be_forged() {
        // API shape: both token types have private fields, no public
        // constructor and no `Clone`/`Copy` derive, so the only way to hold
        // one is to win `begin_freeze`/`claim_thaw`. Using a token consumes
        // it: the next transition needs a fresh claim.
        let sm = FreezeStateMachine::starting_frozen();
        let token = sm.claim_thaw().unwrap();
        sm.thaw_succeeded(token);
        assert!(sm.claim_thaw().is_ok(), "recovery drain from Thawed");
        assert_eq!(sm.current(), FreezeState::Thawing);
        assert!(
            sm.begin_freeze().is_err(),
            "no token can be minted while Thawing"
        );
    }

    #[test]
    fn is_frozen_for_gate() {
        assert!(!FreezeState::Thawed.is_frozen_for_gate());
        assert!(FreezeState::Freezing.is_frozen_for_gate());
        assert!(FreezeState::Frozen.is_frozen_for_gate());
        assert!(FreezeState::Thawing.is_frozen_for_gate());
        for state in [
            FreezeState::Freezing,
            FreezeState::Frozen,
            FreezeState::Thawing,
        ] {
            assert!(FreezeStateMachine::starting_in(state).is_frozen_for_gate());
        }
    }

    #[test]
    fn display_is_lowercase() {
        assert_eq!(FreezeState::Thawed.to_string(), "thawed");
        assert_eq!(FreezeState::Freezing.to_string(), "freezing");
        assert_eq!(FreezeState::Frozen.to_string(), "frozen");
        assert_eq!(FreezeState::Thawing.to_string(), "thawing");
    }
}
