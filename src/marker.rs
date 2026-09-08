//! The pre-freeze recovery marker (design §4.4, §5.5, §5.7; D5; AC10;
//! C-20).
//!
//! A file on an unfreezable runtime filesystem (default
//! `/run/qeminga/frozen`) that is created atomically with
//! `openat(O_CREAT | O_EXCL)` and `fsync`ed **before** the first
//! `FIFREEZE`, and removed with `unlinkat` only after a complete thaw
//! drain. Its presence at startup forces the conservative `Frozen`
//! recovery mode.
//!
//! [`Marker::open`] opens the marker's directory once, at startup, and
//! every later operation is relative to that descriptor: the directory
//! the kernel resolved the configured path to, with its `..` components
//! and symlinks followed *then*, is the one the marker lives in for the
//! life of the process, whatever the pathname leads to later. The
//! directory's device ([`Marker::dev`]) is what startup checks against the
//! freeze plan (§8.2), since a pathname's prefix cannot tell which
//! filesystem `/run/../var/lib/x` or a symlinked parent resolves to.
//!
//! The parent directory is provisioned by the service manager (C-20);
//! this module never creates directories, so `mkdirat` can stay out of
//! the seccomp profile.
//!
//! `create` returns only after `fsync(2)` succeeded on the new file; the
//! privileged strace check in T5.2 verifies the `openat`/`fsync`/`unlinkat`
//! sequence on the real binary.
#![forbid(unsafe_code)]

use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{Mode, fstat, fstatat, major, minor};
use nix::unistd::{UnlinkatFlags, fsync, unlinkat};

/// A marker operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MarkerError {
    /// The configured path has no directory part or no file name.
    #[error("recovery marker path {path} needs a directory and a file name")]
    InvalidPath {
        /// The configured path.
        path: PathBuf,
    },
    /// The marker's directory could not be opened (missing, not a
    /// directory, unreadable): no handle, nothing created.
    #[error("cannot open the directory of recovery marker {path}: {errno}")]
    Directory {
        /// The marker path.
        path: PathBuf,
        /// The errno from `open(2)` or `fstat(2)` on the directory.
        errno: Errno,
    },
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
    /// Any other errno, including `ENOENT` from a pinned directory that was
    /// removed meanwhile.
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

/// Handle to the marker file: its pinned directory and its name in it.
#[derive(Debug, Clone)]
pub struct Marker {
    dir: Arc<OwnedFd>,
    name: PathBuf,
    path: PathBuf,
    dev: (u32, u32),
}

impl Marker {
    /// Opens the directory of `path` (`O_RDONLY | O_DIRECTORY |
    /// O_CLOEXEC`, resolving it as the kernel does) and records its
    /// device. Nothing is created; a directory that cannot be opened is
    /// [`MarkerError::Directory`].
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, MarkerError> {
        let path = path.into();
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(MarkerError::InvalidPath { path });
        };
        if parent.as_os_str().is_empty() {
            return Err(MarkerError::InvalidPath { path });
        }
        let directory = |errno| MarkerError::Directory {
            path: path.clone(),
            errno,
        };
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
        let dir = open(parent, flags, Mode::empty()).map_err(directory)?;
        let st = fstat(&dir).map_err(directory)?;
        let dev = (
            u32::try_from(major(st.st_dev)).unwrap_or(u32::MAX),
            u32::try_from(minor(st.st_dev)).unwrap_or(u32::MAX),
        );
        Ok(Marker {
            dir: Arc::new(dir),
            name: PathBuf::from(name),
            path,
            dev,
        })
    }

    /// The configured marker path (for messages; operations do not go
    /// through it).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `(major, minor)` of the filesystem holding the pinned directory:
    /// what startup checks against the freeze plan (§8.2).
    pub const fn dev(&self) -> (u32, u32) {
        self.dev
    }

    /// Creates the marker atomically (`O_CREAT | O_EXCL`, mode `0600`) in
    /// the pinned directory and `fsync`s it before returning. Never
    /// creates a directory.
    pub fn create(&self) -> Result<(), MarkerError> {
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
        let fd = match openat(
            self.dir.as_fd(),
            &self.name,
            flags,
            Mode::S_IRUSR | Mode::S_IWUSR,
        ) {
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

    /// Removes the marker from the pinned directory with `unlinkat`; an
    /// absent marker is an error because it means the drain-then-remove
    /// sequence was violated.
    pub fn remove(&self) -> Result<(), MarkerError> {
        match unlinkat(self.dir.as_fd(), &self.name, UnlinkatFlags::NoRemoveDir) {
            Ok(()) => Ok(()),
            Err(Errno::ENOENT) => Err(MarkerError::Absent {
                path: self.path.clone(),
            }),
            Err(errno) => Err(self.io("unlink", errno)),
        }
    }

    /// `true` when something is at the marker's name in the pinned
    /// directory (a symlink counts, and is not followed).
    pub fn exists(&self) -> bool {
        fstatat(self.dir.as_fd(), &self.name, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok()
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
        Marker::open(dir.join("frozen")).unwrap()
    }

    fn dev_of(path: &Path) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt;
        let dev = std::fs::metadata(path).unwrap().dev();
        (
            u32::try_from(nix::sys::stat::major(dev)).unwrap(),
            u32::try_from(nix::sys::stat::minor(dev)).unwrap(),
        )
    }

    #[test]
    fn open_pins_the_parent_directory_and_reports_its_device() {
        let dir = tempfile::tempdir().unwrap();
        let marker = marker_in(dir.path());
        assert_eq!(marker.path(), dir.path().join("frozen"));
        assert_eq!(marker.dev(), dev_of(dir.path()));
        assert!(!marker.exists());
        // A path whose directory does not exist cannot be opened: no
        // marker handle, nothing created.
        let missing = dir.path().join("missing").join("frozen");
        let err = Marker::open(&missing).unwrap_err();
        assert_eq!(
            err,
            MarkerError::Directory {
                path: missing.clone(),
                errno: Errno::ENOENT
            }
        );
        assert!(err.to_string().contains("directory"), "{err}");
        assert!(!dir.path().join("missing").exists());
        // A directory of a file is not a directory.
        std::fs::write(dir.path().join("file"), b"").unwrap();
        let err = Marker::open(dir.path().join("file").join("frozen")).unwrap_err();
        assert!(
            matches!(
                err,
                MarkerError::Directory {
                    errno: Errno::ENOTDIR,
                    ..
                }
            ),
            "{err:?}"
        );
        // A path with no file name or no directory is rejected outright.
        for bad in ["/", "frozen", ""] {
            let err = Marker::open(bad).unwrap_err();
            assert!(
                matches!(err, MarkerError::InvalidPath { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn the_device_is_that_of_the_resolved_directory_not_of_the_pathname() {
        // `..` and a symlinked parent both resolve to another directory;
        // the device reported is the one the kernel resolved to, which is
        // what the startup check must judge.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let via_dotdot = a
            .path()
            .join("..")
            .join(b.path().file_name().unwrap())
            .join("frozen");
        let marker = Marker::open(&via_dotdot).unwrap();
        assert_eq!(marker.dev(), dev_of(b.path()));
        marker.create().unwrap();
        assert!(
            b.path().join("frozen").is_file(),
            "created where the kernel resolved to"
        );
        marker.remove().unwrap();
        let link = a.path().join("link");
        std::os::unix::fs::symlink(b.path(), &link).unwrap();
        let marker = Marker::open(link.join("frozen")).unwrap();
        assert_eq!(marker.dev(), dev_of(b.path()));
        // The same holds for /proc-style pseudo filesystems: the device of
        // the directory, whatever the pathname's prefix suggests.
        let proc_marker = Marker::open("/proc/self/../self/frozen").unwrap();
        assert_eq!(proc_marker.dev(), dev_of(Path::new("/proc/self")));
    }

    #[test]
    fn marker_operations_follow_the_pinned_directory_not_the_pathname() {
        // After the marker is opened, the directory is renamed away and a
        // symlink of the same name points elsewhere: create, exists and
        // remove keep acting on the pinned directory, never on what the
        // pathname now leads to.
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("state");
        let elsewhere = root.path().join("elsewhere");
        let moved = root.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        let marker = Marker::open(original.join("frozen")).unwrap();
        std::fs::rename(&original, &moved).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &original).unwrap();
        marker.create().unwrap();
        assert!(
            moved.join("frozen").is_file(),
            "created in the pinned directory"
        );
        assert!(
            !elsewhere.join("frozen").exists(),
            "never where the pathname leads now"
        );
        assert!(marker.exists());
        // A file appearing where the pathname leads is not the marker.
        std::fs::write(elsewhere.join("frozen"), b"decoy").unwrap();
        marker.remove().unwrap();
        assert!(!moved.join("frozen").exists());
        assert!(elsewhere.join("frozen").is_file(), "the decoy is untouched");
        assert!(!marker.exists(), "exists() looks in the pinned directory");
        // The handle still reports the configured path for messages.
        assert_eq!(marker.path(), original.join("frozen"));
        assert!(format!("{:?}", marker.clone()).contains("Marker"));
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
        let link = Marker::open(dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("target"), link.path()).unwrap();
        let err = link.create().unwrap_err();
        assert!(matches!(err, MarkerError::AlreadyPresent { .. }), "{err:?}");
        assert!(!dir.path().join("target").exists());
    }

    #[test]
    fn create_fails_if_parent_missing() {
        // The directory is pinned at `open`, so a missing one is refused
        // there (`Directory`), and one removed afterwards makes `create`
        // fail with ENOENT from `openat` on the dead directory: no mkdir
        // is ever attempted either way.
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("missing");
        assert!(matches!(
            Marker::open(parent.join("frozen")).unwrap_err(),
            MarkerError::Directory { .. }
        ));
        assert!(!parent.exists(), "no mkdir is ever attempted");
        std::fs::create_dir(&parent).unwrap();
        let marker = Marker::open(parent.join("frozen")).unwrap();
        std::fs::remove_dir(&parent).unwrap();
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
            let err = marker_in(ro.path()).create().unwrap_err();
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
        let d = Marker::open(dir.path().join("dir")).unwrap();
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
