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

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

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

/// A failed kernel operation. An ioctl needs the mountpoint opened and
/// verified first; a failure there is reported apart, because it means no
/// ioctl was issued at all (the caller must not read it as the
/// filesystem's answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KernelError {
    /// The syscall or ioctl failed with this errno.
    #[error("{0}")]
    Errno(Errno),
    /// The mountpoint could not be opened for the ioctl (`EMFILE`,
    /// `ENOENT`, `EACCES`, ...): the ioctl never ran.
    #[error("cannot open mountpoint: {0}")]
    Open(Errno),
    /// The opened mountpoint is not on the planned filesystem: another
    /// mount now hides the planned one under that pathname (or the mount
    /// table changed). No ioctl was issued.
    #[error(
        "mountpoint is on {}:{}, not on the planned {}:{}",
        found.0,
        found.1,
        expected.0,
        expected.1
    )]
    WrongFilesystem {
        /// The planned `(major, minor)`.
        expected: (u32, u32),
        /// What the opened directory is on.
        found: (u32, u32),
    },
}

impl KernelError {
    /// The underlying errno, if the failure came from a syscall.
    pub const fn errno(&self) -> Option<Errno> {
        match self {
            KernelError::Errno(errno) | KernelError::Open(errno) => Some(*errno),
            KernelError::WrongFilesystem { .. } => None,
        }
    }

    /// `true` when the mountpoint could not be opened, so the ioctl was
    /// never issued and nothing can be inferred about the filesystem.
    pub const fn is_open_failure(&self) -> bool {
        matches!(self, KernelError::Open(_))
    }

    /// `true` when the pathname led to a filesystem other than the planned
    /// one; no ioctl was issued.
    pub const fn is_wrong_filesystem(&self) -> bool {
        matches!(self, KernelError::WrongFilesystem { .. })
    }

    /// `true` when this is the filesystem's own answer to the ioctl (the
    /// ioctl was issued and failed), as opposed to a failure before it.
    pub const fn is_ioctl_answer(&self) -> bool {
        matches!(self, KernelError::Errno(_))
    }

    /// The filesystem does not implement the operation (`EOPNOTSUPP`, or
    /// `ENOTTY`/`ENOSYS` from a filesystem without the ioctl at all).
    /// Counted as skipped by freeze (§4.2). Only an ioctl's own answer
    /// qualifies: the same errno from `open(2)` says nothing about the
    /// filesystem.
    pub fn is_not_supported(&self) -> bool {
        matches!(
            self,
            KernelError::Errno(Errno::EOPNOTSUPP | Errno::ENOTTY | Errno::ENOSYS)
        )
    }

    /// The superblock is already frozen (`EBUSY` from the ioctl, §4.2).
    pub fn is_busy(&self) -> bool {
        matches!(self, KernelError::Errno(Errno::EBUSY))
    }

    /// Permission denied (`EPERM`/`EACCES`): missing capability or an
    /// unreadable mountpoint (§5.4). Either stage of the call can say so.
    pub fn is_permission(&self) -> bool {
        matches!(self.errno(), Some(Errno::EPERM | Errno::EACCES))
    }

    /// `EINVAL` from the ioctl: for `FITHAW`, the filesystem is not
    /// frozen, which is the normal end of a thaw drain (§4.2, OQ-3).
    pub fn is_invalid(&self) -> bool {
        matches!(self, KernelError::Errno(Errno::EINVAL))
    }
}

impl From<Errno> for KernelError {
    fn from(errno: Errno) -> Self {
        KernelError::Errno(errno)
    }
}

/// What a `FITRIM` reports back. The kernel rewrites the request range:
/// `len` becomes the number of bytes discarded and `minlen` the minimum
/// extent it actually used, rounded up to the filesystem's block size and
/// the device's discard granularity. The wire reply carries the effective
/// value, not the requested one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trimmed {
    /// Bytes discarded.
    pub bytes: u64,
    /// The minimum extent the kernel applied.
    pub minimum: u64,
}

/// An open mountpoint whose filesystem identity has been verified against
/// the plan: the directory descriptor was `fstat`ed and its `st_dev` is
/// the planned `(major, minor)`. Every freeze, thaw and trim ioctl goes
/// through such a handle, and the descriptor keeps referring to that
/// filesystem whatever happens to the pathname afterwards (a mount placed
/// over it, a rename), so a thaw issued on the handle a freeze opened
/// reaches the filesystem that was frozen.
#[derive(Debug)]
pub struct Mount {
    mountpoint: PathBuf,
    dev: (u32, u32),
    fd: Option<OwnedFd>,
}

impl Mount {
    /// The pathname the handle was opened from (for messages and audit).
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// The verified `(major, minor)` of the filesystem.
    pub const fn dev(&self) -> (u32, u32) {
        self.dev
    }

    /// A handle that holds no descriptor, for test doubles. The production
    /// kernel refuses it (`EBADF`): it never issues an ioctl on a handle it
    /// did not open and verify itself.
    pub fn unopened(mountpoint: impl Into<PathBuf>, dev: (u32, u32)) -> Mount {
        Mount {
            mountpoint: mountpoint.into(),
            dev,
            fd: None,
        }
    }

    /// A verified handle over an open descriptor.
    pub(crate) fn opened(mountpoint: PathBuf, dev: (u32, u32), fd: OwnedFd) -> Mount {
        Mount {
            mountpoint,
            dev,
            fd: Some(fd),
        }
    }

    /// `true` when the handle carries a descriptor.
    pub const fn is_open(&self) -> bool {
        self.fd.is_some()
    }

    /// The descriptor, or `EBADF` for an unopened handle.
    pub(crate) fn fd(&self) -> Result<BorrowedFd<'_>, KernelError> {
        self.fd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or(KernelError::Errno(Errno::EBADF))
    }
}

/// The kernel operations qeminga performs. Production: [`LinuxKernel`];
/// tests: [`fake::FakeKernel`].
pub trait KernelOps: Send + Sync {
    /// Opens `mountpoint` (`O_RDONLY | O_DIRECTORY | O_CLOEXEC`) and
    /// verifies that the opened directory is on `dev`; the handle is what
    /// the ioctls take. [`KernelError::Open`] when it cannot be opened,
    /// [`KernelError::WrongFilesystem`] when the pathname now leads
    /// elsewhere; no ioctl is issued in either case.
    fn open_mount(&self, mountpoint: &Path, dev: (u32, u32)) -> Result<Mount, KernelError>;
    /// `FIFREEZE` on the filesystem behind `mount`.
    fn fifreeze(&self, mount: &Mount) -> Result<(), KernelError>;
    /// `FITHAW` on the filesystem behind `mount`.
    fn fithaw(&self, mount: &Mount) -> Result<(), KernelError>;
    /// `FITRIM` over the whole filesystem behind `mount` with the given
    /// minimum extent; returns what the kernel wrote back: the bytes
    /// trimmed and the minimum extent it actually applied.
    fn fitrim(&self, mount: &Mount, minimum: u64) -> Result<Trimmed, KernelError>;
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
    fn open_mount(&self, mountpoint: &Path, dev: (u32, u32)) -> Result<Mount, KernelError> {
        ioctl::open_mount(mountpoint, dev)
    }

    fn fifreeze(&self, mount: &Mount) -> Result<(), KernelError> {
        ioctl::fifreeze(mount)
    }

    fn fithaw(&self, mount: &Mount) -> Result<(), KernelError> {
        ioctl::fithaw(mount)
    }

    fn fitrim(&self, mount: &Mount, minimum: u64) -> Result<Trimmed, KernelError> {
        ioctl::fitrim(mount, minimum)
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
        assert_eq!(e(Errno::EIO).errno(), Some(Errno::EIO));
        assert_eq!(KernelError::from(Errno::EIO), e(Errno::EIO));
        assert_eq!(e(Errno::EIO).to_string(), Errno::EIO.to_string());
        // An open failure keeps its errno but says the ioctl never ran.
        let open = KernelError::Open(Errno::EMFILE);
        assert!(open.is_open_failure());
        assert!(!e(Errno::EMFILE).is_open_failure());
        assert_eq!(open.errno(), Some(Errno::EMFILE));
        assert!(!open.is_ioctl_answer());
        assert!(e(Errno::EMFILE).is_ioctl_answer());
        assert!(open.to_string().starts_with("cannot open mountpoint: "));
        assert!(KernelError::Open(Errno::EACCES).is_permission());
        // The errno of an open failure is never the filesystem's answer to
        // an ioctl: it cannot mean "not frozen", "unsupported" or "busy".
        for errno in [
            Errno::EINVAL,
            Errno::EOPNOTSUPP,
            Errno::ENOTTY,
            Errno::ENOSYS,
            Errno::EBUSY,
        ] {
            let open = KernelError::Open(errno);
            assert!(!open.is_invalid(), "{open:?}");
            assert!(!open.is_not_supported(), "{open:?}");
            assert!(!open.is_busy(), "{open:?}");
            assert!(open.is_open_failure());
        }
    }

    /// `(major, minor)` of the filesystem holding `path`, as `stat` sees it.
    fn dev_of(path: &Path) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt;
        let dev = std::fs::metadata(path).unwrap().dev();
        (
            u32::try_from(nix::sys::stat::major(dev)).unwrap(),
            u32::try_from(nix::sys::stat::minor(dev)).unwrap(),
        )
    }

    #[test]
    fn linux_kernel_reports_errno_for_a_missing_mountpoint() {
        let missing = Path::new("/nonexistent/qeminga-test-mountpoint");
        assert_eq!(
            LinuxKernel.open_mount(missing, (0, 0)).unwrap_err(),
            KernelError::Open(Errno::ENOENT)
        );
        // A file (not a directory) is rejected by O_DIRECTORY at open time.
        assert_eq!(
            LinuxKernel
                .open_mount(Path::new("/proc/self/status"), (0, 0))
                .unwrap_err(),
            KernelError::Open(Errno::ENOTDIR)
        );
    }

    #[test]
    fn open_mount_verifies_the_device_of_the_opened_directory() {
        // The right device: an open handle that remembers both.
        let root = Path::new("/");
        let dev = dev_of(root);
        let mount = LinuxKernel.open_mount(root, dev).unwrap();
        assert!(mount.is_open());
        assert_eq!(mount.mountpoint(), root);
        assert_eq!(mount.dev(), dev);
        // Any other device: refused before any ioctl, naming both sides.
        let wrong = (dev.0.wrapping_add(1), dev.1.wrapping_add(7));
        let err = LinuxKernel.open_mount(root, wrong).unwrap_err();
        assert_eq!(
            err,
            KernelError::WrongFilesystem {
                expected: wrong,
                found: dev
            }
        );
        assert!(err.is_wrong_filesystem());
        assert!(!err.is_open_failure());
        assert!(!err.is_ioctl_answer());
        assert_eq!(err.errno(), None);
        assert!(!err.is_invalid() && !err.is_not_supported() && !err.is_busy());
        assert!(!err.is_permission());
        let text = err.to_string();
        assert!(text.contains(&format!("{}:{}", dev.0, dev.1)), "{text}");
        assert!(text.contains(&format!("{}:{}", wrong.0, wrong.1)), "{text}");
        // A pseudo filesystem verifies the same way (the handle carries
        // whatever `stat` reports, mountinfo's major:minor).
        let proc = Path::new("/proc");
        assert!(LinuxKernel.open_mount(proc, dev_of(proc)).is_ok());
    }

    #[test]
    fn the_production_kernel_refuses_a_handle_it_did_not_open() {
        let unopened = Mount::unopened("/", (0, 0));
        assert!(!unopened.is_open());
        assert_eq!(unopened.mountpoint(), Path::new("/"));
        assert_eq!(unopened.dev(), (0, 0));
        let badf = KernelError::Errno(Errno::EBADF);
        assert_eq!(LinuxKernel.fifreeze(&unopened), Err(badf));
        assert_eq!(LinuxKernel.fithaw(&unopened), Err(badf));
        assert_eq!(LinuxKernel.fitrim(&unopened, 0).unwrap_err(), badf);
        assert!(format!("{unopened:?}").contains("Mount"));
    }

    #[test]
    fn linux_kernel_fifreeze_on_proc_is_not_supported_or_denied() {
        // procfs never implements freeze: EOPNOTSUPP with CAP_SYS_ADMIN,
        // EPERM without it. Either way the classification is what the
        // freeze algorithm needs and no state changes.
        let proc = Path::new("/proc");
        let mount = LinuxKernel.open_mount(proc, dev_of(proc)).unwrap();
        let err = LinuxKernel.fifreeze(&mount).unwrap_err();
        assert!(err.is_ioctl_answer());
        assert!(err.is_not_supported() || err.is_permission(), "{err}");
    }

    #[test]
    fn linux_kernel_sync_does_not_fail() {
        LinuxKernel.sync();
    }
}
