//! qeminga — a minimum secure subset of the QEMU guest agent.
//!
//! The library crate holds every testable component (protocol, framing,
//! dispatch, state machine, handlers, kernel shim). The binary in
//! `src/main.rs` is a thin wrapper that wires them together.
//!
//! Security posture (design §5.6): `unsafe` is denied crate-wide here and
//! *forbidden* in every module except `kernel`, which is the single reviewed
//! location allowed to opt back in. `scripts/check-unsafe.sh` enforces this
//! in CI.
#![deny(unsafe_code)]

pub mod audit;
pub mod config;
pub mod dispatch;
pub mod framing;
pub mod handlers;
pub mod proto;
pub mod state;

/// Agent version reported by `guest-info`.
///
/// This is build metadata taken from the Cargo manifest; it cannot be
/// overridden by the runtime configuration file (design §8.2).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_like() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "expected MAJOR.MINOR.PATCH, got {VERSION}");
        for part in parts {
            part.parse::<u64>()
                .unwrap_or_else(|_| panic!("non-numeric version component {part:?}"));
        }
    }
}
