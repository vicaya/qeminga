//! `FIFREEZE`, `FITHAW` and `FITRIM` via `nix` (design §4.1, §5.5).
//!
//! [`open_mount`] opens the mountpoint with `O_RDONLY | O_DIRECTORY |
//! O_CLOEXEC` (never following into a file) and checks with `fstat(2)`
//! that the descriptor is on the planned device; the ioctls take that
//! handle, so they can never reach a filesystem that was mounted over the
//! planned one after the plan was made. This file holds every `unsafe`
//! block in the crate.
#![allow(unsafe_code)]

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::{Mode, fstat, major, minor};

use super::{KernelError, Mount, Trimmed};

/// `_IOWR('X', 119, int)`: freeze the filesystem.
pub const FIFREEZE: u32 = 0xC004_5877;
/// `_IOWR('X', 120, int)`: thaw the filesystem.
pub const FITHAW: u32 = 0xC004_5878;
/// `_IOWR('X', 121, struct fstrim_range)`: discard unused blocks.
pub const FITRIM: u32 = 0xC018_5879;

/// `struct fstrim_range` from `<linux/fs.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FstrimRange {
    /// First byte to trim.
    pub start: u64,
    /// Number of bytes to consider; the kernel writes back the number
    /// of bytes actually trimmed.
    pub len: u64,
    /// Minimum extent length to trim.
    pub minlen: u64,
}

// The generated wrappers are `unsafe fn`s; the callers below document why
// each call is sound.
nix::ioctl_write_int_bad!(
    /// Raw `FIFREEZE`; the integer argument is ignored by the kernel.
    fifreeze_raw,
    FIFREEZE as nix::libc::c_ulong
);
nix::ioctl_write_int_bad!(
    /// Raw `FITHAW`; the integer argument is ignored by the kernel.
    fithaw_raw,
    FITHAW as nix::libc::c_ulong
);
nix::ioctl_readwrite!(
    /// Raw `FITRIM` over a `struct fstrim_range`.
    fitrim_raw,
    b'X',
    121,
    FstrimRange
);

/// Opens a mountpoint directory for an ioctl.
fn open_dir(mountpoint: &Path) -> Result<OwnedFd, KernelError> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    open(mountpoint, flags, Mode::empty()).map_err(KernelError::Open)
}

/// `(major, minor)` of a `st_dev`, as mountinfo spells it.
fn split_dev(dev: nix::libc::dev_t) -> (u32, u32) {
    (
        u32::try_from(major(dev)).unwrap_or(u32::MAX),
        u32::try_from(minor(dev)).unwrap_or(u32::MAX),
    )
}

/// Opens `mountpoint` and verifies, on the descriptor, that it is on
/// `dev`. A pathname only names whatever is mounted there *now*; the
/// descriptor names the filesystem it was opened on for as long as it is
/// held.
pub fn open_mount(mountpoint: &Path, dev: (u32, u32)) -> Result<Mount, KernelError> {
    let fd = open_dir(mountpoint)?;
    let found = split_dev(fstat(&fd).map_err(KernelError::Open)?.st_dev);
    if found != dev {
        return Err(KernelError::WrongFilesystem {
            expected: dev,
            found,
        });
    }
    Ok(Mount::opened(mountpoint.to_owned(), dev, fd))
}

/// `FIFREEZE` on the filesystem behind `mount`.
pub fn fifreeze(mount: &Mount) -> Result<(), KernelError> {
    let fd = mount.fd()?;
    // SAFETY: `fd` is an open directory descriptor borrowed from `mount`
    // for the duration of the call, and FIFREEZE takes an integer argument
    // the kernel ignores; no memory is shared with the kernel.
    unsafe { fifreeze_raw(fd.as_raw_fd(), 0) }?;
    Ok(())
}

/// `FITHAW` on the filesystem behind `mount`.
pub fn fithaw(mount: &Mount) -> Result<(), KernelError> {
    let fd = mount.fd()?;
    // SAFETY: as for `fifreeze`: an open directory descriptor borrowed for
    // the call and an ignored integer argument.
    unsafe { fithaw_raw(fd.as_raw_fd(), 0) }?;
    Ok(())
}

/// `FITRIM` over the whole filesystem behind `mount` with the given
/// minimum extent; returns the bytes trimmed and the minimum extent the
/// kernel applied (it rewrites both fields of the range).
pub fn fitrim(mount: &Mount, minimum: u64) -> Result<Trimmed, KernelError> {
    let fd = mount.fd()?;
    let mut range = FstrimRange {
        start: 0,
        len: u64::MAX,
        minlen: minimum,
    };
    // SAFETY: `fd` is an open directory descriptor borrowed for the call
    // and `range` is a live, correctly laid out (`repr(C)`) `struct
    // fstrim_range` that outlives the call; the kernel reads and writes
    // only that struct.
    unsafe { fitrim_raw(fd.as_raw_fd(), &raw mut range) }?;
    Ok(Trimmed {
        bytes: range.len,
        minimum: range.minlen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_numbers_match_linux_fs_h() {
        // _IOWR(type, nr, size) = (3 << 30) | (size << 16) | (type << 8) | nr
        let iowr = |nr: u32, size: u32| (3u32 << 30) | (size << 16) | (u32::from(b'X') << 8) | nr;
        assert_eq!(FIFREEZE, iowr(119, 4));
        assert_eq!(FITHAW, iowr(120, 4));
        assert_eq!(FITRIM, iowr(121, 24));
        assert_eq!(std::mem::size_of::<FstrimRange>(), 24);
    }

    /// Runs the real ioctls against a loop-mounted ext4 filesystem whose
    /// mountpoint is given by `QEMINGA_TEST_EXT4_MOUNT` (created by
    /// `scripts/ci/mk-loop-fs.sh`, T5.2). Needs `CAP_SYS_ADMIN`.
    #[test]
    #[ignore = "needs root and a loop-mounted ext4 (QEMINGA_TEST_EXT4_MOUNT)"]
    fn privileged_fifreeze_then_fithaw_on_loop_mounted_ext4() {
        use std::os::unix::fs::MetadataExt;
        let mount = std::env::var("QEMINGA_TEST_EXT4_MOUNT")
            .expect("QEMINGA_TEST_EXT4_MOUNT must point at a mounted ext4 filesystem");
        let path = Path::new(&mount);
        let dev = split_dev(std::fs::metadata(path).unwrap().dev());
        let mount = open_mount(path, dev).expect("open and verify the mountpoint");
        fifreeze(&mount).expect("FIFREEZE");
        // A second freeze reports the superblock is already frozen.
        assert!(fifreeze(&mount).unwrap_err().is_busy());
        // A handle opened while frozen verifies and thaws just the same.
        let again = open_mount(path, dev).expect("open while frozen");
        fithaw(&again).expect("FITHAW");
        // Fully thawed: FITHAW now returns EINVAL, the end of a drain.
        assert!(fithaw(&mount).unwrap_err().is_invalid());
        let trimmed = fitrim(&mount, 0).expect("FITRIM");
        let _ = trimmed.bytes;
        // The kernel rounds the requested minimum up to its block size and
        // the device's discard granularity and writes the value back: a
        // 1-byte request comes back larger, and the effective value is a
        // fixed point (asking for it again yields it again).
        let effective = fitrim(&mount, 1).expect("FITRIM").minimum;
        assert!(effective >= 1);
        assert_eq!(
            fitrim(&mount, effective).expect("FITRIM").minimum,
            effective
        );
    }
}
