//! Descriptor mount-identity query via `statx(2)` (design §4.5, §5.6, AC27).
//!
//! `guest-get-fsinfo` opens each advertised mount point with `O_PATH |
//! O_NOFOLLOW | O_CLOEXEC` and checks both the superblock `(major, minor)`
//! and the mount ID (`STATX_MNT_ID`, column 1 of `/proc/self/mountinfo`,
//! falling back to a bounded read of `/proc/self/fdinfo/<fd>` on stock
//! Linux 5.4–5.7 where `STATX_MNT_ID` is absent) on that descriptor before
//! issuing `fstatfs(2)`. Verifying the mount ID in addition to `st_dev`
//! catches same-device mount replacements such as two XFS bind mounts
//! carrying different project quotas, whose `fstatfs(2)` block counts differ
//! despite sharing `st_dev`.

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
/// `AT_EMPTY_PATH | AT_STATX_DONT_SYNC` and `STATX_MNT_ID`, falling back to
/// a bounded read of `/proc/self/fdinfo/<fd>` when `statx(2)` succeeds with
/// `STATX_MNT_ID` clear (stock Linux 5.4–5.7, before `STATX_MNT_ID` arrived
/// in Linux 5.8). Works on metadata-only (`O_PATH`) descriptors for both
/// directories and regular files without touching backing storage or
/// triggering automounts.
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
    let mount_id = resolve_mount_id(fd, stx.stx_mask, stx.stx_mnt_id);
    Ok(MountIdentity {
        dev: (stx.stx_dev_major, stx.stx_dev_minor),
        mount_id,
    })
}

fn resolve_mount_id(fd: BorrowedFd<'_>, stx_mask: u32, stx_mnt_id: u64) -> Option<u32> {
    if (stx_mask & nix::libc::STATX_MNT_ID) != 0 {
        u32::try_from(stx_mnt_id).ok()
    } else {
        crate::mountinfo::read_fdinfo_mnt_id(fd)
    }
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
            "regular-file O_PATH descriptor should report mount_id: {file_id:?}"
        );
    }

    #[test]
    fn resolve_mount_id_falls_back_to_fdinfo_when_statx_mnt_id_is_clear() {
        // On stock Linux 5.4-5.7, statx(2) succeeds with STATX_MNT_ID clear
        // in stx_mask. Falling back to /proc/self/fdinfo/<fd> preserves sizes
        // while keeping mount-ID verification on the supported 5.4+ baseline.
        let mounts = ProcMounts.mounts().unwrap();
        let visible = crate::freeze_plan::visible_mounts(&mounts).unwrap();
        let root = visible
            .into_iter()
            .find(|m| m.mount_point == Path::new("/"))
            .expect("visible `/` row in /proc/self/mountinfo");
        let root_fd = open(
            Path::new("/"),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert_eq!(
            resolve_mount_id(root_fd.as_fd(), 0, 0),
            Some(root.mount_id),
            "clear STATX_MNT_ID must fall back to /proc/self/fdinfo/<fd> for directories"
        );

        let file = tempfile::NamedTempFile::new().unwrap();
        let file_fd = open(
            file.path(),
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let direct = fd_mount_identity(file_fd.as_fd()).unwrap();
        assert_eq!(
            resolve_mount_id(file_fd.as_fd(), 0, 0),
            direct.mount_id,
            "clear STATX_MNT_ID must fall back to /proc/self/fdinfo/<fd> for regular files"
        );
        // When STATX_MNT_ID IS set, trust statx directly and fail closed if out of range.
        assert_eq!(
            resolve_mount_id(file_fd.as_fd(), nix::libc::STATX_MNT_ID, 77),
            Some(77)
        );
        assert_eq!(
            resolve_mount_id(
                file_fd.as_fd(),
                nix::libc::STATX_MNT_ID,
                u64::from(u32::MAX) + 1
            ),
            None
        );
    }
}
