//! `FIFREEZE`, `FITHAW` and `FITRIM` via `nix` (design §4.1, §5.5).
//!
//! Each call opens the mountpoint with `O_RDONLY | O_DIRECTORY |
//! O_CLOEXEC` (never following into a file), issues the ioctl on that
//! descriptor, and closes it. This file holds every `unsafe` block in the
//! crate.
#![allow(unsafe_code)]

use std::os::fd::AsRawFd;
use std::path::Path;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

use super::KernelError;

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
fn open_dir(mountpoint: &Path) -> Result<std::os::fd::OwnedFd, KernelError> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
    open(mountpoint, flags, Mode::empty()).map_err(KernelError::from)
}

/// `FIFREEZE` on the filesystem mounted at `mountpoint`.
pub fn fifreeze(mountpoint: &Path) -> Result<(), KernelError> {
    let fd = open_dir(mountpoint)?;
    // SAFETY: `fd` is an open directory descriptor owned by this frame,
    // and FIFREEZE takes an integer argument the kernel ignores; no memory
    // is shared with the kernel.
    unsafe { fifreeze_raw(fd.as_raw_fd(), 0) }?;
    Ok(())
}

/// `FITHAW` on the filesystem mounted at `mountpoint`.
pub fn fithaw(mountpoint: &Path) -> Result<(), KernelError> {
    let fd = open_dir(mountpoint)?;
    // SAFETY: as for `fifreeze`: an owned open directory descriptor and an
    // ignored integer argument.
    unsafe { fithaw_raw(fd.as_raw_fd(), 0) }?;
    Ok(())
}

/// `FITRIM` over the whole filesystem mounted at `mountpoint` with the
/// given minimum extent; returns the number of bytes trimmed.
pub fn fitrim(mountpoint: &Path, minimum: u64) -> Result<u64, KernelError> {
    let fd = open_dir(mountpoint)?;
    let mut range = FstrimRange {
        start: 0,
        len: u64::MAX,
        minlen: minimum,
    };
    // SAFETY: `fd` is an owned open directory descriptor and `range` is a
    // live, correctly laid out (`repr(C)`) `struct fstrim_range` that
    // outlives the call; the kernel reads and writes only that struct.
    unsafe { fitrim_raw(fd.as_raw_fd(), &raw mut range) }?;
    Ok(range.len)
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
        let mount = std::env::var("QEMINGA_TEST_EXT4_MOUNT")
            .expect("QEMINGA_TEST_EXT4_MOUNT must point at a mounted ext4 filesystem");
        let mount = Path::new(&mount);
        fifreeze(mount).expect("FIFREEZE");
        // A second freeze reports the superblock is already frozen.
        assert!(fifreeze(mount).unwrap_err().is_busy());
        fithaw(mount).expect("FITHAW");
        // Fully thawed: FITHAW now returns EINVAL, the end of a drain.
        assert!(fithaw(mount).unwrap_err().is_invalid());
        let trimmed = fitrim(mount, 0).expect("FITRIM");
        let _ = trimmed;
    }
}
