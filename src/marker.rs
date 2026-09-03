//! The pre-freeze recovery marker (design §4.4, §5.5, §5.7; D5; AC10;
//! C-20).
//!
//! A file on an unfreezable runtime filesystem (default
//! `/run/qeminga/frozen`) that is created atomically with
//! `open(O_CREAT | O_EXCL)` and `fsync`ed **before** the first `FIFREEZE`,
//! and removed with `unlinkat` only after a complete thaw drain. Its
//! presence at startup forces the conservative `Frozen` recovery mode.
//!
//! The parent directory is provisioned by the service manager
//! (`RuntimeDirectory=`, C-20); this module never creates directories, so
//! `mkdirat` can stay out of the seccomp profile.
//!
//! `create` returns only after `fsync(2)` succeeded on the new file; the
//! privileged strace check in T5.2 verifies the `openat`/`fsync`/`unlinkat`
//! sequence on the real binary.
#![forbid(unsafe_code)]

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, fsync, unlinkat};

/// A marker operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarkerError {
    /// `create` found the marker already present (`EEXIST`); nothing was
    /// overwritten.
    #[error("recovery marker {path} already exists")]
    AlreadyPresent {
        /// The marker path.
        path: PathBuf,
    },
    /// `remove` found no marker (`ENOENT`).
    #[error("recovery marker {path} is absent")]
    Absent {
        /// The marker path.
        path: PathBuf,
    },
    /// Any other errno, including `ENOENT` from a missing parent directory
    /// on `create`.
    #[error("recovery marker {path}: {op} failed: {errno}")]
    Io {
        /// The marker path.
        path: PathBuf,
        /// The failed operation (`open`, `fsync`, `unlink`).
        op: &'static str,
        /// The errno.
        errno: Errno,
    },
}

/// Handle to the marker file at a fixed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    path: PathBuf,
}

impl Marker {
    /// A marker at `path` (nothing is touched until `create`).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Marker { path: path.into() }
    }

    /// The marker path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates the marker atomically (`O_CREAT | O_EXCL`, mode `0600`) and
    /// `fsync`s it before returning. Never creates the parent directory.
    pub fn create(&self) -> Result<(), MarkerError> {
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
        let fd = match open(&self.path, flags, Mode::S_IRUSR | Mode::S_IWUSR) {
            Ok(fd) => fd,
            Err(Errno::EEXIST) => {
                return Err(MarkerError::AlreadyPresent {
                    path: self.path.clone(),
                });
            }
            Err(errno) => return Err(self.io("open", errno)),
        };
        fsync(fd.as_fd()).map_err(|errno| self.io("fsync", errno))?;
        Ok(())
    }

    /// Removes the marker with `unlinkat`; an absent marker is an error
    /// because it means the drain-then-remove sequence was violated.
    pub fn remove(&self) -> Result<(), MarkerError> {
        match unlinkat(nix::fcntl::AT_FDCWD, &self.path, UnlinkatFlags::NoRemoveDir) {
            Ok(()) => Ok(()),
            Err(Errno::ENOENT) => Err(MarkerError::Absent {
                path: self.path.clone(),
            }),
            Err(errno) => Err(self.io("unlink", errno)),
        }
    }

    /// `true` when the marker file exists.
    pub fn exists(&self) -> bool {
        self.path.symlink_metadata().is_ok()
    }

    fn io(&self, op: &'static str, errno: Errno) -> MarkerError {
        MarkerError::Io {
            path: self.path.clone(),
            op,
            errno,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn marker_in(dir: &Path) -> Marker {
        Marker::new(dir.join("frozen"))
    }

    #[test]
    fn create_makes_file_with_o_excl_and_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        assert!(!marker.exists());
        marker.create().unwrap();
        assert!(marker.exists());
        let meta = std::fs::metadata(marker.path()).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.len(), 0);
    }

    #[test]
    fn create_fails_if_marker_exists() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        std::fs::write(marker.path(), b"stale contents").unwrap();
        let err = marker.create().unwrap_err();
        assert_eq!(
            err,
            MarkerError::AlreadyPresent {
                path: marker.path().to_owned()
            }
        );
        assert_eq!(
            std::fs::read(marker.path()).unwrap(),
            b"stale contents",
            "nothing is overwritten"
        );
        // A symlink at the path is never followed.
        let link = Marker::new(dir.path().join("link"));
        std::os::unix::fs::symlink(dir.path().join("target"), link.path()).unwrap();
        let err = link.create().unwrap_err();
        assert!(matches!(err, MarkerError::AlreadyPresent { .. }), "{err:?}");
        assert!(!dir.path().join("target").exists());
    }

    #[test]
    fn create_fails_if_parent_missing() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("missing");
        let marker = Marker::new(parent.join("frozen"));
        let err = marker.create().unwrap_err();
        assert_eq!(
            err,
            MarkerError::Io {
                path: marker.path().to_owned(),
                op: "open",
                errno: Errno::ENOENT
            }
        );
        assert!(!parent.exists(), "no mkdir is ever attempted");
        assert!(!marker.exists());
        assert!(err.to_string().contains("open failed"));
    }

    #[test]
    fn create_fsyncs_before_returning() {
        // `fsync` is observable only through the syscall trace (T5.2); here
        // the contract is that a successful `create` leaves a durable,
        // closed file that a second `create` refuses.
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        marker.create().unwrap();
        assert!(matches!(
            marker.create(),
            Err(MarkerError::AlreadyPresent { .. })
        ));
        // Read-only parent: open fails with EACCES, not a panic. Root
        // bypasses directory permissions, so only assert when unprivileged.
        if !nix::unistd::geteuid().is_root() {
            let ro = tempfile::tempdir().unwrap();
            std::fs::set_permissions(ro.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
            let err = Marker::new(ro.path().join("frozen")).create().unwrap_err();
            assert!(matches!(
                err,
                MarkerError::Io {
                    op: "open",
                    errno: Errno::EACCES,
                    ..
                }
            ));
        }
    }

    #[test]
    fn remove_unlinks_and_is_error_if_absent() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        marker.create().unwrap();
        marker.remove().unwrap();
        assert!(!marker.exists());
        let err = marker.remove().unwrap_err();
        assert_eq!(
            err,
            MarkerError::Absent {
                path: marker.path().to_owned()
            }
        );
        // After removal a fresh create works again (next freeze cycle).
        marker.create().unwrap();
        assert!(marker.exists());
        // `remove` refuses to remove a directory at the path.
        let d = Marker::new(dir.path().join("dir"));
        std::fs::create_dir(d.path()).unwrap();
        let err = d.remove().unwrap_err();
        assert!(
            matches!(err, MarkerError::Io { op: "unlink", .. }),
            "{err:?}"
        );
        assert!(d.path().is_dir());
    }

    #[test]
    fn exists_reports_presence() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        assert!(!marker.exists());
        marker.create().unwrap();
        assert!(marker.exists());
        marker.remove().unwrap();
        assert!(!marker.exists());
        // A dangling symlink still counts as "something is there" so that
        // a startup sees it as a marker rather than overwriting it.
        std::os::unix::fs::symlink("/nonexistent", marker.path()).unwrap();
        assert!(marker.exists());
        assert_eq!(marker.path(), dir.path().join("frozen"));
    }
}
