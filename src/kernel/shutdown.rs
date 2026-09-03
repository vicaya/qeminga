//! `sync(2)` and `reboot(2)` via `nix` (design §4.1, C-11, OQ-1).
//!
//! No `unsafe` is needed here: `nix` exposes both as safe wrappers. The
//! mapping from [`RebootCommand`] to the kernel command is kept in one
//! function so that OQ-1 (a graceful systemd shutdown instead of an
//! immediate `reboot(2)`) is a local change.
#![forbid(unsafe_code)]

use nix::sys::reboot::RebootMode;

use super::{KernelError, RebootCommand};

/// `sync(2)`: flush filesystem caches before `reboot(2)` (C-11).
pub fn sync() {
    nix::unistd::sync();
}

/// The `reboot(2)` command for a shutdown mode (OQ-1 lives here).
pub const fn reboot_mode(cmd: RebootCommand) -> RebootMode {
    match cmd {
        RebootCommand::PowerOff => RebootMode::RB_POWER_OFF,
        RebootCommand::Restart => RebootMode::RB_AUTOBOOT,
        RebootCommand::Halt => RebootMode::RB_HALT_SYSTEM,
    }
}

/// `reboot(2)`. Does not return on success.
pub fn reboot(cmd: RebootCommand) -> Result<(), KernelError> {
    match nix::sys::reboot::reboot(reboot_mode(cmd)) {
        Ok(never) => match never {},
        Err(errno) => Err(KernelError::Errno(errno)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_map_to_kernel_commands() {
        assert_eq!(
            reboot_mode(RebootCommand::PowerOff),
            RebootMode::RB_POWER_OFF
        );
        assert_eq!(reboot_mode(RebootCommand::Restart), RebootMode::RB_AUTOBOOT);
        assert_eq!(reboot_mode(RebootCommand::Halt), RebootMode::RB_HALT_SYSTEM);
    }
}
