//! The kernel shim: the **only** module allowed to contain `unsafe`
//! (design §5.6, §4.1 Kernel Interface, §6, G8).
//!
//! Everything the daemon needs from the kernel goes through the
//! [`KernelOps`] trait so that handlers are tested against
//! [`fake::FakeKernel`] and production uses [`LinuxKernel`]. Every
//! `unsafe` block lives in [`ioctl`] and carries a `// SAFETY:` comment;
//! `scripts/check-unsafe.sh` and clippy's `undocumented_unsafe_blocks`
//! enforce this.
#![allow(unsafe_code)]

pub mod fake;
pub mod ioctl;
pub mod shutdown;

use std::path::Path;

use nix::errno::Errno;

/// What `guest-shutdown` asks `reboot(2)` to do (§3 `mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootCommand {
    /// `mode = "powerdown"` (default): `LINUX_REBOOT_CMD_POWER_OFF`.
    PowerOff,
    /// `mode = "reboot"`: `LINUX_REBOOT_CMD_RESTART`.
    Restart,
    /// `mode = "halt"`: `LINUX_REBOOT_CMD_HALT`.
    Halt,
}

/// A failed kernel operation, carrying the errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    /// The syscall or ioctl failed with this errno.
    #[error("{0}")]
    Errno(Errno),
}

impl KernelError {
    /// The underlying errno.
    pub const fn errno(&self) -> Errno {
        match self {
            KernelError::Errno(errno) => *errno,
        }
    }

    /// The filesystem does not implement the operation (`EOPNOTSUPP`, or
    /// `ENOTTY`/`ENOSYS` from a filesystem without the ioctl at all).
    /// Counted as skipped by freeze (§4.2).
    pub fn is_not_supported(&self) -> bool {
        matches!(
            self.errno(),
            Errno::EOPNOTSUPP | Errno::ENOTTY | Errno::ENOSYS
        )
    }

    /// The superblock is already frozen (`EBUSY`, §4.2).
    pub fn is_busy(&self) -> bool {
        self.errno() == Errno::EBUSY
    }

    /// Permission denied (`EPERM`/`EACCES`): missing capability or an
    /// unreadable mountpoint (§5.4).
    pub fn is_permission(&self) -> bool {
        matches!(self.errno(), Errno::EPERM | Errno::EACCES)
    }

    /// `EINVAL`: for `FITHAW`, the filesystem is not frozen, which is the
    /// normal end of a thaw drain (§4.2, OQ-3).
    pub fn is_invalid(&self) -> bool {
        self.errno() == Errno::EINVAL
    }
}

impl From<Errno> for KernelError {
    fn from(errno: Errno) -> Self {
        KernelError::Errno(errno)
    }
}

/// The kernel operations qeminga performs. Production: [`LinuxKernel`];
/// tests: [`fake::FakeKernel`].
pub trait KernelOps: Send + Sync {
    /// `FIFREEZE` on the filesystem mounted at `mountpoint`.
    fn fifreeze(&self, mountpoint: &Path) -> Result<(), KernelError>;
    /// `FITHAW` on the filesystem mounted at `mountpoint`.
    fn fithaw(&self, mountpoint: &Path) -> Result<(), KernelError>;
    /// `FITRIM` over the whole filesystem with the given minimum extent;
    /// returns the number of bytes trimmed.
    fn fitrim(&self, mountpoint: &Path, minimum: u64) -> Result<u64, KernelError>;
    /// `sync(2)`; never fails.
    fn sync(&self);
    /// `reboot(2)`. On success the call does not return; `Ok(())` is only
    /// reachable through fakes.
    fn reboot(&self, cmd: RebootCommand) -> Result<(), KernelError>;
}

/// The production implementation over `nix`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxKernel;

impl KernelOps for LinuxKernel {
    fn fifreeze(&self, mountpoint: &Path) -> Result<(), KernelError> {
        ioctl::fifreeze(mountpoint)
    }

    fn fithaw(&self, mountpoint: &Path) -> Result<(), KernelError> {
        ioctl::fithaw(mountpoint)
    }

    fn fitrim(&self, mountpoint: &Path, minimum: u64) -> Result<u64, KernelError> {
        ioctl::fitrim(mountpoint, minimum)
    }

    fn sync(&self) {
        shutdown::sync();
    }

    fn reboot(&self, cmd: RebootCommand) -> Result<(), KernelError> {
        shutdown::reboot(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_error_classifies_errno() {
        let e = |errno| KernelError::Errno(errno);
        assert!(e(Errno::EOPNOTSUPP).is_not_supported());
        assert!(e(Errno::ENOTTY).is_not_supported());
        assert!(!e(Errno::EBUSY).is_not_supported());
        assert!(e(Errno::EBUSY).is_busy());
        assert!(!e(Errno::EIO).is_busy());
        assert!(e(Errno::EPERM).is_permission());
        assert!(e(Errno::EACCES).is_permission());
        assert!(!e(Errno::EIO).is_permission());
        assert!(e(Errno::EINVAL).is_invalid());
        assert!(!e(Errno::EINVAL).is_busy());
        assert_eq!(e(Errno::EIO).errno(), Errno::EIO);
        assert_eq!(KernelError::from(Errno::EIO), e(Errno::EIO));
        assert_eq!(e(Errno::EIO).to_string(), Errno::EIO.to_string());
    }

    #[test]
    fn linux_kernel_reports_errno_for_a_missing_mountpoint() {
        let missing = Path::new("/nonexistent/qeminga-test-mountpoint");
        assert_eq!(
            LinuxKernel.fifreeze(missing),
            Err(KernelError::Errno(Errno::ENOENT))
        );
        assert_eq!(
            LinuxKernel.fithaw(missing),
            Err(KernelError::Errno(Errno::ENOENT))
        );
        assert_eq!(
            LinuxKernel.fitrim(missing, 0),
            Err(KernelError::Errno(Errno::ENOENT))
        );
        // A file (not a directory) is rejected by O_DIRECTORY.
        assert_eq!(
            LinuxKernel.fifreeze(Path::new("/proc/self/status")),
            Err(KernelError::Errno(Errno::ENOTDIR))
        );
    }

    #[test]
    fn linux_kernel_fifreeze_on_proc_is_not_supported_or_denied() {
        // procfs never implements freeze: EOPNOTSUPP with CAP_SYS_ADMIN,
        // EPERM without it. Either way the classification is what the
        // freeze algorithm needs and no state changes.
        let err = LinuxKernel.fifreeze(Path::new("/proc")).unwrap_err();
        assert!(err.is_not_supported() || err.is_permission(), "{err}");
    }

    #[test]
    fn linux_kernel_sync_does_not_fail() {
        LinuxKernel.sync();
    }
}
