//! Descriptor mount-identity query via `statx(2)` (design §4.5, §5.6, AC27).
//!
//! `guest-get-fsinfo` opens each advertised mount point with `O_PATH |
//! O_NOFOLLOW | O_CLOEXEC` and checks both the superblock `(major, minor)`
//! and the mount ID (`STATX_MNT_ID`, column 1 of `/proc/self/mountinfo`) on
//! that descriptor before issuing `fstatfs(2)`. Verifying the mount ID in
//! addition to `st_dev` catches same-device mount replacements such as two
//! XFS bind mounts carrying different project quotas, whose `fstatfs(2)`
//! block counts differ despite sharing `st_dev`.

use std::os::fd::{AsRawFd, BorrowedFd};

use nix::errno::Errno;

/// Superblock device and mount ID of an open descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountIdentity {
    /// Superblock `(major, minor)` (`stx_dev_major`, `stx_dev_minor`).
    pub dev: (u32, u32),
    /// Mount ID matching column 1 of `/proc/self/mountinfo` (`stx_mnt_id`),
    /// `Some` only when the kernel sets `STATX_MNT_ID` in `stx_mask` and
    /// the value fits in `u32`.
    pub mount_id: Option<u32>,
}

/// Queries the superblock device and mount ID of `fd` via `statx(2)` with
/// `AT_EMPTY_PATH | AT_STATX_DONT_SYNC` and `STATX_MNT_ID`. Works on
/// metadata-only (`O_PATH`) descriptors for both directories and regular
/// files without touching backing storage or triggering automounts.
pub fn fd_mount_identity(fd: BorrowedFd<'_>) -> Result<MountIdentity, Errno> {
    // SAFETY: `nix::libc::statx` is a plain C struct of integer fields, so
    // zero-initialisation is valid; the kernel overwrites it on success.
    let mut stx: nix::libc::statx = unsafe { std::mem::zeroed() };
    let empty = c"";
    // SAFETY: `fd` is a valid borrowed descriptor, `empty` is a valid
    // NUL-terminated empty path for `AT_EMPTY_PATH`, and `&mut stx` points
    // to a valid, aligned `libc::statx` buffer for the syscall's duration.
    let rc = unsafe {
        nix::libc::statx(
            fd.as_raw_fd(),
            empty.as_ptr(),
            nix::libc::AT_EMPTY_PATH | nix::libc::AT_STATX_DONT_SYNC,
            nix::libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if rc != 0 {
        return Err(Errno::last());
    }
    let mount_id = ((stx.stx_mask & nix::libc::STATX_MNT_ID) != 0)
        .then(|| u32::try_from(stx.stx_mnt_id).ok())
        .flatten();
    Ok(MountIdentity {
        dev: (stx.stx_dev_major, stx.stx_dev_minor),
        mount_id,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::fd::AsFd;
    use std::path::Path;

    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    use super::*;
    use crate::mountinfo::{MountSource, ProcMounts};

    #[test]
    fn fd_mount_identity_matches_proc_mountinfo_for_root_and_works_on_regular_file() {
        let mounts = ProcMounts.mounts().unwrap();
        let visible = crate::freeze_plan::visible_mounts(&mounts).unwrap();
        let root = visible
            .into_iter()
            .find(|m| m.mount_point == Path::new("/"))
            .expect("visible `/` row in /proc/self/mountinfo");
        let fd = open(
            Path::new("/"),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let id = fd_mount_identity(fd.as_fd()).unwrap();
        assert_eq!(id.dev, root.dev());
        assert_eq!(id.mount_id, Some(root.mount_id));

        let file = tempfile::NamedTempFile::new().unwrap();
        let file_fd = open(
            file.path(),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let file_id = fd_mount_identity(file_fd.as_fd()).unwrap();
        assert!(
            file_id.mount_id.is_some(),
            "regular-file O_PATH descriptor should report STATX_MNT_ID: {file_id:?}"
        );
    }
}
