//! Cooperative per-superblock freeze ownership records (design §4.2, OQ-11, #69).
//!
//! By default (`[agent] freeze_ownership_dir` unset), qeminga runs in v1
//! sole-freezer mode where no independent in-guest freezer is supported.
//! When an operator configures `[agent] freeze_ownership_dir` (a root-owned
//! sticky+setgid `03770` guest-local runtime `tmpfs` directory shared only
//! with cooperating guest freezers), every participating freezer follows this
//! protocol:
//!
//! 1. **Claim before `FIFREEZE`:** atomically create `<major>-<minor>` with
//!    `openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC)`,
//!    write `<owner-tag>\n` (`qeminga\n` for qeminga), `fsync` the file, and
//!    `fsync` the directory before issuing `FIFREEZE`.
//! 2. **Respect foreign claims:** if `<major>-<minor>` already exists with a
//!    valid foreign owner tag, do **not** issue `FIFREEZE` or `FITHAW` and do
//!    **not** retain the superblock for later thaw. If `FIFREEZE` returns
//!    `EBUSY` on a freshly acquired claim (an unannounced freezer holds the
//!    superblock), immediately release the claim and do not retain the target.
//! 3. **Verify before thaw and release only after complete drain:** check
//!    current ownership with a read-only non-blocking `inspect` before issuing
//!    `FITHAW`, and unlink `<major>-<minor>` only after verifying the entry is
//!    still owned by `qeminga` and `FITHAW` has reached `EINVAL` or
//!    `EOPNOTSUPP`, then `fsync` the directory.
//! 4. **Fail closed on ambiguity:** corrupt, empty, non-regular (including
//!    FIFOs, sockets, and directories), symlinked, unreadable, unparseable, or
//!    spoofed-UID entries are classified as ambiguous; recovery drains every
//!    reachable `qeminga`-owned superblock without touching foreign
//!    superblocks and retains the recovery marker and `Frozen` state until the
//!    guest operator resolves the ambiguity.
//!
//! All runtime filesystem operations go through a pinned directory descriptor
//! opened once at startup (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`;
//! startup validates `fstatfs` `TMPFS_MAGIC`, owner UID, group GID, and mode
//! before installing seccomp) and use only syscalls already permitted by the
//! CVM seccomp profile (`openat`, `read`, `write`, `fstat`, `fsync`,
//! `unlinkat`, `getdents64`, `geteuid`, `close`).
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fstat, major, minor};
use nix::sys::statfs::{TMPFS_MAGIC, fstatfs};
use nix::unistd::{UnlinkatFlags, fsync, geteuid, unlinkat};
use thiserror::Error;

/// The owner tag qeminga writes into its `<major>-<minor>` claim files.
pub const QEMINGA_OWNER: &str = "qeminga";

/// Maximum bytes read from any single claim file (strict parser bound).
pub const MAX_CLAIM_BYTES: usize = 128;

/// Maximum ASCII byte length of an owner tag (excluding trailing `\n`).
pub const MAX_OWNER_TAG_LEN: usize = 64;

/// Maximum directory entries inspected during one `inspect_all` scan.
pub const MAX_OWNERSHIP_ENTRIES: usize = 4096;

/// Formats a superblock `(major, minor)` pair into its canonical claim file
/// name (`"<major>-<minor>"`).
pub fn format_dev_filename(dev: (u32, u32)) -> String {
    format!("{}-{}", dev.0, dev.1)
}

/// Parses a canonical `<major>-<minor>` claim file name.
///
/// Rejects non-canonical forms such as leading zeros (`"08-1"`), signs
/// (`"+8-1"`), extra hyphens, whitespace, or overflow beyond `u32::MAX`.
pub fn parse_dev_filename(name: &str) -> Option<(u32, u32)> {
    let (maj_s, min_s) = name.split_once('-')?;
    if !is_canonical_u32_decimal(maj_s) || !is_canonical_u32_decimal(min_s) {
        return None;
    }
    let maj = maj_s.parse::<u32>().ok()?;
    let min = min_s.parse::<u32>().ok()?;
    Some((maj, min))
}

fn is_canonical_u32_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s.len() == 1 || !s.starts_with('0'))
}

/// Parses a bounded claim file payload into a validated ASCII owner tag.
///
/// Requires a single trailing `\n`, non-empty tag up to [`MAX_OWNER_TAG_LEN`]
/// bytes, and characters strictly in `[A-Za-z0-9._-]`. Any empty, truncated,
/// oversized, or malformed content returns `None` (classified as ambiguous).
pub fn parse_owner_tag(bytes: &[u8]) -> Option<&str> {
    if bytes.is_empty() || bytes.len() > MAX_CLAIM_BYTES {
        return None;
    }
    let body = bytes.strip_suffix(b"\n")?;
    if body.is_empty() || body.len() > MAX_OWNER_TAG_LEN {
        return None;
    }
    if !body
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return None;
    }
    std::str::from_utf8(body).ok()
}

/// Outcome of attempting to claim a superblock before `FIFREEZE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// qeminga freshly created and synced the claim file (`O_CREAT | O_EXCL`).
    Acquired,
    /// A valid claim file owned by qeminga already existed (for example from
    /// an earlier crash before recovery).
    AlreadyOwnedBySelf,
    /// A valid claim file owned by another cooperating guest component exists;
    /// qeminga must leave the superblock untouched.
    OwnedByOther {
        /// The foreign owner's tag (for guest-local diagnostics only).
        owner: String,
    },
    /// An entry exists at `<major>-<minor>` whose ownership cannot be proven
    /// safely (corrupt, empty, symlink, non-regular, unreadable, or UID
    /// mismatch on `"qeminga"`).
    Ambiguous {
        /// Guest-local diagnostic reason (never sent on the wire).
        reason: String,
    },
}

/// An entry in the cooperative ownership directory whose ownership could not
/// be verified safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousEntry {
    /// Superblock `(major, minor)` parsed from a canonical `<major>-<minor>`
    /// filename, or `None` for directory-level entries whose names do not
    /// identify a superblock (non-UTF-8 or unrecognised filenames).
    pub dev: Option<(u32, u32)>,
    /// Guest-local diagnostic detail (never sent on the wire).
    pub reason: String,
}

/// Point-in-time inventory of the cooperative ownership directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipSnapshot {
    /// Superblocks verified as owned by `qeminga` (sorted, deduplicated).
    pub owned_by_self: Vec<(u32, u32)>,
    /// Superblocks verified as owned by another cooperating freezer (guest-local
    /// diagnostics only; never thawed by qeminga).
    pub owned_by_other: Vec<(u32, u32)>,
    /// Guest-local diagnostics (with parsed device identity when available) for
    /// entries whose ownership is ambiguous. When non-empty, recovery must fail
    /// closed and retain the marker.
    pub ambiguous: Vec<AmbiguousEntry>,
}

/// Errors interacting with the cooperative ownership store.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OwnershipError {
    /// Could not open and pin the configured ownership directory at startup.
    #[error("cannot open freeze ownership directory {}: {errno}", path.display())]
    OpenDir {
        /// Configured directory path.
        path: PathBuf,
        /// Kernel error.
        errno: Errno,
    },
    /// A filesystem operation inside the pinned ownership directory failed.
    #[error("freeze ownership {op} failed{}: {errno}", format_opt_dev(*.dev))]
    Io {
        /// Device pair when specific to one target.
        dev: Option<(u32, u32)>,
        /// Operation name (`create`, `write`, `fsync`, `dir_fsync`, `unlink`, `readdir`).
        op: &'static str,
        /// Kernel error.
        errno: Errno,
    },
    /// Directory exceeded [`MAX_OWNERSHIP_ENTRIES`].
    #[error("freeze ownership directory exceeds entry bound ({limit})")]
    TooManyEntries {
        /// Entry cap.
        limit: usize,
    },
    /// Refused to unlink a claim file that is not verified as owned by qeminga.
    #[error("refusing to release freeze ownership for {}:{}: not owned by qeminga", dev.0, dev.1)]
    NotOwnedBySelf {
        /// Target device pair.
        dev: (u32, u32),
    },
}

fn format_opt_dev(dev: Option<(u32, u32)>) -> String {
    match dev {
        Some((maj, min)) => format!(" for {maj}:{min}"),
        None => String::new(),
    }
}

impl OwnershipError {
    /// Fixed host-facing reason without guest paths or device numbers (§5.9).
    pub const fn host_reason(&self) -> &'static str {
        match self {
            OwnershipError::OpenDir { .. } | OwnershipError::Io { .. } => {
                "cannot update freeze ownership state"
            }
            OwnershipError::TooManyEntries { .. } | OwnershipError::NotOwnedBySelf { .. } => {
                "freeze ownership is ambiguous; cannot confirm complete recovery"
            }
        }
    }
}

/// Result of a read-only ownership check for a single superblock before
/// issuing `FITHAW` on a retained handle (OQ-11, #69).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetOwnership {
    /// Verified regular claim file owned by `qeminga` (matching `geteuid()`).
    OwnedBySelf,
    /// No claim file currently exists for this superblock.
    Unclaimed,
    /// Verified claim file owned by another cooperating freezer.
    OwnedByOther {
        /// Foreign owner tag (guest-local diagnostics only).
        owner: String,
    },
    /// Entry exists or could not be read safely (corrupt, non-regular,
    /// symlink, unreadable, or UID mismatch on `"qeminga"`).
    Ambiguous {
        /// Guest-local diagnostic reason (never sent on the wire).
        reason: String,
    },
}

/// Abstraction over cooperative per-superblock freeze ownership records.
/// Production: [`LinuxOwnershipStore`]; tests: [`InMemoryOwnershipStore`].
pub trait OwnershipStore: Send + Sync + std::fmt::Debug {
    /// Attempts to claim `dev` for qeminga before issuing `FIFREEZE`.
    fn try_claim(&self, dev: (u32, u32)) -> Result<ClaimOutcome, OwnershipError>;
    /// Read-only check of the current ownership record for `dev`, called
    /// before issuing `FITHAW` on a retained handle.
    fn inspect(&self, dev: (u32, u32)) -> Result<TargetOwnership, OwnershipError>;
    /// Releases qeminga's claim on `dev` after a complete `FITHAW` drain.
    /// Never unlinks a claim owned by another component or an ambiguous entry.
    fn release(&self, dev: (u32, u32)) -> Result<(), OwnershipError>;
    /// Scans all current ownership entries for recovery.
    fn inspect_all(&self) -> Result<OwnershipSnapshot, OwnershipError>;
}

/// Production ownership store pinned to an open directory descriptor.
#[derive(Debug)]
pub struct LinuxOwnershipStore {
    dir: OwnedFd,
    path: PathBuf,
    dev: (u32, u32),
    uid: u32,
    gid: u32,
    mode: u32,
    is_tmpfs: bool,
}

impl LinuxOwnershipStore {
    /// Opens and pins `path` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`)
    /// and records its backing device, filesystem type (`fstatfs`), owner UID,
    /// owner GID, and mode bits for startup validation.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, OwnershipError> {
        let path = path.into();
        let open_err = |errno| OwnershipError::OpenDir {
            path: path.clone(),
            errno,
        };
        let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let dir = open(&path, flags, Mode::empty()).map_err(open_err)?;
        let st = fstat(&dir).map_err(open_err)?;
        let fs = fstatfs(&dir).map_err(open_err)?;
        let dev = (
            u32::try_from(major(st.st_dev)).unwrap_or(u32::MAX),
            u32::try_from(minor(st.st_dev)).unwrap_or(u32::MAX),
        );
        Ok(LinuxOwnershipStore {
            dir,
            path,
            dev,
            uid: st.st_uid,
            gid: st.st_gid,
            mode: st.st_mode & 0o7777,
            is_tmpfs: fs.filesystem_type() == TMPFS_MAGIC,
        })
    }

    /// The configured ownership directory path (for startup diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `(major, minor)` of the filesystem holding the pinned directory:
    /// startup rejects any freezable filesystem (§8.2).
    pub const fn dev(&self) -> (u32, u32) {
        self.dev
    }

    /// Owner UID of the pinned directory at startup.
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Owner GID of the pinned directory at startup.
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Permission and special mode bits (`0o7777`) of the pinned directory.
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Whether `fstatfs(2)` on the pinned directory descriptor reported
    /// guest-local `tmpfs` (`TMPFS_MAGIC`).
    pub const fn is_tmpfs(&self) -> bool {
        self.is_tmpfs
    }

    /// Helper for cooperating owners (and two-owner integration tests) to
    /// create a claim file in the same directory using a distinct owner tag.
    pub fn claim_as(&self, owner: &str, dev: (u32, u32)) -> Result<bool, OwnershipError> {
        let payload = format!("{owner}\n");
        if parse_owner_tag(payload.as_bytes()).is_none() {
            return Err(OwnershipError::Io {
                dev: Some(dev),
                op: "validate_owner",
                errno: Errno::EINVAL,
            });
        }
        let name = format_dev_filename(dev);
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let mode = Mode::from_bits_truncate(0o640);
        match openat(self.dir.as_fd(), name.as_str(), flags, mode) {
            Ok(fd) => {
                if let Err(err) =
                    write_and_sync_claim(&self.dir, &name, dev, fd, payload.as_bytes())
                {
                    let _ = unlinkat(self.dir.as_fd(), name.as_str(), UnlinkatFlags::NoRemoveDir);
                    return Err(err);
                }
                Ok(true)
            }
            Err(Errno::EEXIST) => Ok(false),
            Err(errno) => Err(OwnershipError::Io {
                dev: Some(dev),
                op: "create",
                errno,
            }),
        }
    }

    /// Helper for cooperating owners (and tests) to release a claim file owned
    /// by `owner`.
    pub fn release_as(&self, owner: &str, dev: (u32, u32)) -> Result<(), OwnershipError> {
        let name = format_dev_filename(dev);
        match inspect_entry_fd(&self.dir, &name, None) {
            EntryClass::Absent => return Ok(()),
            EntryClass::Tag { tag, .. } if tag == owner => {}
            EntryClass::Tag { .. } | EntryClass::Ambiguous(_) => {
                return Err(OwnershipError::NotOwnedBySelf { dev });
            }
        }
        match unlinkat(self.dir.as_fd(), name.as_str(), UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => {}
            Err(errno) => {
                return Err(OwnershipError::Io {
                    dev: Some(dev),
                    op: "unlink",
                    errno,
                });
            }
        }
        fsync(self.dir.as_fd()).map_err(|errno| OwnershipError::Io {
            dev: Some(dev),
            op: "dir_fsync",
            errno,
        })
    }
}

fn write_and_sync_claim(
    dir: &OwnedFd,
    _name: &str,
    dev: (u32, u32),
    fd: OwnedFd,
    payload: &[u8],
) -> Result<(), OwnershipError> {
    let mut file = File::from(fd);
    file.write_all(payload).map_err(|err| OwnershipError::Io {
        dev: Some(dev),
        op: "write",
        errno: err
            .raw_os_error()
            .map(Errno::from_raw)
            .unwrap_or(Errno::EIO),
    })?;
    fsync(file.as_fd()).map_err(|errno| OwnershipError::Io {
        dev: Some(dev),
        op: "fsync",
        errno,
    })?;
    drop(file);
    fsync(dir.as_fd()).map_err(|errno| OwnershipError::Io {
        dev: Some(dev),
        op: "dir_fsync",
        errno,
    })
}

enum EntryClass {
    Absent,
    Tag { tag: String, uid: u32 },
    Ambiguous(String),
}

fn inspect_entry_fd(dir: &OwnedFd, name: &str, expect_uid_for_self: Option<u32>) -> EntryClass {
    // O_NONBLOCK ensures a FIFO claim entry with no writer never blocks openat
    // before the fstat regular-file check classifies it as Ambiguous.
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
    let fd = match openat(dir.as_fd(), name, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return EntryClass::Absent,
        Err(Errno::ELOOP) => return EntryClass::Ambiguous("symlink at claim entry".to_owned()),
        Err(errno) => return EntryClass::Ambiguous(format!("cannot open claim entry: {errno}")),
    };
    let st = match fstat(&fd) {
        Ok(st) => st,
        Err(errno) => return EntryClass::Ambiguous(format!("cannot stat claim entry: {errno}")),
    };
    if (st.st_mode & SFlag::S_IFMT.bits()) != SFlag::S_IFREG.bits() {
        return EntryClass::Ambiguous("non-regular file at claim entry".to_owned());
    }
    let file = File::from(fd);
    let mut buf = Vec::new();
    if let Err(err) = file
        .take((MAX_CLAIM_BYTES + 1) as u64)
        .read_to_end(&mut buf)
    {
        return EntryClass::Ambiguous(format!("cannot read claim entry: {err}"));
    }
    if buf.len() > MAX_CLAIM_BYTES {
        return EntryClass::Ambiguous("claim entry exceeds byte limit".to_owned());
    }
    let Some(tag) = parse_owner_tag(&buf) else {
        return EntryClass::Ambiguous("malformed or empty owner tag".to_owned());
    };
    if tag == QEMINGA_OWNER
        && let Some(own_uid) = expect_uid_for_self
        && st.st_uid != own_uid
    {
        return EntryClass::Ambiguous(format!(
            "qeminga owner tag owned by uid {}, expected {own_uid}",
            st.st_uid
        ));
    }
    EntryClass::Tag {
        tag: tag.to_owned(),
        uid: st.st_uid,
    }
}

impl OwnershipStore for LinuxOwnershipStore {
    fn try_claim(&self, dev: (u32, u32)) -> Result<ClaimOutcome, OwnershipError> {
        let name = format_dev_filename(dev);
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        let mode = Mode::from_bits_truncate(0o640);
        let payload = format!("{QEMINGA_OWNER}\n");
        let own_uid = geteuid().as_raw();

        // Retry once if a concurrent owner released the entry between EEXIST
        // and our inspection open.
        for _ in 0..2 {
            match openat(self.dir.as_fd(), name.as_str(), flags, mode) {
                Ok(fd) => {
                    if let Err(err) =
                        write_and_sync_claim(&self.dir, &name, dev, fd, payload.as_bytes())
                    {
                        let _ =
                            unlinkat(self.dir.as_fd(), name.as_str(), UnlinkatFlags::NoRemoveDir);
                        return Err(err);
                    }
                    return Ok(ClaimOutcome::Acquired);
                }
                Err(Errno::EEXIST) => match inspect_entry_fd(&self.dir, &name, Some(own_uid)) {
                    EntryClass::Absent => continue,
                    EntryClass::Tag { tag, .. } if tag == QEMINGA_OWNER => {
                        return Ok(ClaimOutcome::AlreadyOwnedBySelf);
                    }
                    EntryClass::Tag { tag, .. } => {
                        return Ok(ClaimOutcome::OwnedByOther { owner: tag });
                    }
                    EntryClass::Ambiguous(reason) => {
                        return Ok(ClaimOutcome::Ambiguous { reason });
                    }
                },
                Err(errno) => {
                    return Err(OwnershipError::Io {
                        dev: Some(dev),
                        op: "create",
                        errno,
                    });
                }
            }
        }
        Ok(ClaimOutcome::Ambiguous {
            reason: "concurrent claim churn prevented ownership verification".to_owned(),
        })
    }

    fn inspect(&self, dev: (u32, u32)) -> Result<TargetOwnership, OwnershipError> {
        let name = format_dev_filename(dev);
        let own_uid = geteuid().as_raw();
        Ok(match inspect_entry_fd(&self.dir, &name, Some(own_uid)) {
            EntryClass::Absent => TargetOwnership::Unclaimed,
            EntryClass::Tag { tag, .. } if tag == QEMINGA_OWNER => TargetOwnership::OwnedBySelf,
            EntryClass::Tag { tag, .. } => TargetOwnership::OwnedByOther { owner: tag },
            EntryClass::Ambiguous(reason) => TargetOwnership::Ambiguous { reason },
        })
    }

    fn release(&self, dev: (u32, u32)) -> Result<(), OwnershipError> {
        let name = format_dev_filename(dev);
        let own_uid = geteuid().as_raw();
        match inspect_entry_fd(&self.dir, &name, Some(own_uid)) {
            EntryClass::Absent => return Ok(()),
            EntryClass::Tag { tag, uid } if tag == QEMINGA_OWNER && uid == own_uid => {}
            EntryClass::Tag { .. } | EntryClass::Ambiguous(_) => {
                return Err(OwnershipError::NotOwnedBySelf { dev });
            }
        }
        match unlinkat(self.dir.as_fd(), name.as_str(), UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => {}
            Err(errno) => {
                return Err(OwnershipError::Io {
                    dev: Some(dev),
                    op: "unlink",
                    errno,
                });
            }
        }
        fsync(self.dir.as_fd()).map_err(|errno| OwnershipError::Io {
            dev: Some(dev),
            op: "dir_fsync",
            errno,
        })
    }

    fn inspect_all(&self) -> Result<OwnershipSnapshot, OwnershipError> {
        let mut dir = Dir::openat(
            self.dir.as_fd(),
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| OwnershipError::Io {
            dev: None,
            op: "readdir",
            errno,
        })?;

        let own_uid = geteuid().as_raw();
        let mut self_devs = BTreeSet::new();
        let mut other_devs = BTreeSet::new();
        let mut ambiguous = Vec::new();
        let mut count = 0usize;

        for entry in dir.iter() {
            let entry = entry.map_err(|errno| OwnershipError::Io {
                dev: None,
                op: "readdir",
                errno,
            })?;
            let raw_name = entry.file_name().to_bytes();
            if raw_name == b"." || raw_name == b".." {
                continue;
            }
            count += 1;
            if count > MAX_OWNERSHIP_ENTRIES {
                return Err(OwnershipError::TooManyEntries {
                    limit: MAX_OWNERSHIP_ENTRIES,
                });
            }
            let Ok(name) = std::str::from_utf8(raw_name) else {
                ambiguous.push(AmbiguousEntry {
                    dev: None,
                    reason: "non-UTF-8 entry in freeze ownership directory".to_owned(),
                });
                continue;
            };
            let Some(dev) = parse_dev_filename(name) else {
                ambiguous.push(AmbiguousEntry {
                    dev: None,
                    reason: format!("unrecognised ownership entry name {name:?}"),
                });
                continue;
            };
            match inspect_entry_fd(&self.dir, name, Some(own_uid)) {
                EntryClass::Absent => {}
                EntryClass::Tag { tag, .. } if tag == QEMINGA_OWNER => {
                    self_devs.insert(dev);
                }
                EntryClass::Tag { .. } => {
                    other_devs.insert(dev);
                }
                EntryClass::Ambiguous(reason) => {
                    ambiguous.push(AmbiguousEntry {
                        dev: Some(dev),
                        reason: format!("{name}: {reason}"),
                    });
                }
            }
        }

        Ok(OwnershipSnapshot {
            owned_by_self: self_devs.into_iter().collect(),
            owned_by_other: other_devs.into_iter().collect(),
            ambiguous,
        })
    }
}

/// Entry stored inside [`InMemoryOwnershipStore`] for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeEntry {
    Owner(String),
    Ambiguous(String),
}

#[derive(Debug, Default)]
struct FakeState {
    entries: BTreeMap<(u32, u32), FakeEntry>,
    extra_ambiguous: Vec<String>,
    claim_error: Option<Errno>,
    release_error: Option<Errno>,
    inspect_error: Option<Errno>,
    inspect_target_error: Option<Errno>,
}

/// In-memory [`OwnershipStore`] test double supporting two cooperating owners
/// and fault injection.
#[derive(Debug, Default)]
pub struct InMemoryOwnershipStore {
    state: Mutex<FakeState>,
}

impl InMemoryOwnershipStore {
    /// Creates an empty in-memory ownership store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Simulates an independent guest freezer claiming `dev`. Returns `true`
    /// if the claim was newly acquired, `false` if already claimed.
    pub fn claim_foreign(&self, dev: (u32, u32), owner: impl Into<String>) -> bool {
        let mut s = self.lock();
        if s.entries.contains_key(&dev) {
            return false;
        }
        s.entries.insert(dev, FakeEntry::Owner(owner.into()));
        true
    }

    /// Simulates an independent guest freezer releasing its claim on `dev`.
    pub fn release_foreign(&self, dev: (u32, u32), owner: &str) -> bool {
        let mut s = self.lock();
        if matches!(s.entries.get(&dev), Some(FakeEntry::Owner(o)) if o == owner) {
            s.entries.remove(&dev);
            true
        } else {
            false
        }
    }

    /// Pre-seeds a `qeminga` claim (e.g. simulating restart after a crash).
    pub fn seed_self_claim(&self, dev: (u32, u32)) {
        self.lock()
            .entries
            .insert(dev, FakeEntry::Owner(QEMINGA_OWNER.to_owned()));
    }

    /// Marks `dev` as having an ambiguous claim entry.
    pub fn inject_ambiguous_entry(&self, dev: (u32, u32), reason: impl Into<String>) {
        self.lock()
            .entries
            .insert(dev, FakeEntry::Ambiguous(reason.into()));
    }

    /// Adds a stray unparseable/corrupt directory entry reported by `inspect_all`.
    pub fn inject_stray_ambiguous(&self, reason: impl Into<String>) {
        self.lock().extra_ambiguous.push(reason.into());
    }

    /// Injects an error returned by `try_claim`.
    pub fn script_claim_error(&self, errno: Option<Errno>) {
        self.lock().claim_error = errno;
    }

    /// Injects an error returned by `release`.
    pub fn script_release_error(&self, errno: Option<Errno>) {
        self.lock().release_error = errno;
    }

    /// Injects an error returned by `inspect_all` (directory scan).
    pub fn script_inspect_error(&self, errno: Option<Errno>) {
        self.lock().inspect_error = errno;
    }

    /// Injects an error returned by per-target `inspect`.
    pub fn script_inspect_target_error(&self, errno: Option<Errno>) {
        self.lock().inspect_target_error = errno;
    }

    /// Returns current owner tag for `dev`, if unambiguously owned.
    pub fn owner_of(&self, dev: (u32, u32)) -> Option<String> {
        match self.lock().entries.get(&dev) {
            Some(FakeEntry::Owner(owner)) => Some(owner.clone()),
            _ => None,
        }
    }

    /// Lists superblocks currently owned by `qeminga`.
    pub fn owned_by_self(&self) -> Vec<(u32, u32)> {
        self.lock()
            .entries
            .iter()
            .filter_map(|(&dev, entry)| match entry {
                FakeEntry::Owner(o) if o == QEMINGA_OWNER => Some(dev),
                _ => None,
            })
            .collect()
    }
}

impl OwnershipStore for InMemoryOwnershipStore {
    fn try_claim(&self, dev: (u32, u32)) -> Result<ClaimOutcome, OwnershipError> {
        let mut s = self.lock();
        if let Some(errno) = s.claim_error {
            return Err(OwnershipError::Io {
                dev: Some(dev),
                op: "create",
                errno,
            });
        }
        match s.entries.get(&dev) {
            None => {
                s.entries
                    .insert(dev, FakeEntry::Owner(QEMINGA_OWNER.to_owned()));
                Ok(ClaimOutcome::Acquired)
            }
            Some(FakeEntry::Owner(o)) if o == QEMINGA_OWNER => Ok(ClaimOutcome::AlreadyOwnedBySelf),
            Some(FakeEntry::Owner(o)) => Ok(ClaimOutcome::OwnedByOther { owner: o.clone() }),
            Some(FakeEntry::Ambiguous(reason)) => Ok(ClaimOutcome::Ambiguous {
                reason: reason.clone(),
            }),
        }
    }

    fn inspect(&self, dev: (u32, u32)) -> Result<TargetOwnership, OwnershipError> {
        let s = self.lock();
        if let Some(errno) = s.inspect_target_error {
            return Err(OwnershipError::Io {
                dev: Some(dev),
                op: "inspect",
                errno,
            });
        }
        Ok(match s.entries.get(&dev) {
            None => TargetOwnership::Unclaimed,
            Some(FakeEntry::Owner(o)) if o == QEMINGA_OWNER => TargetOwnership::OwnedBySelf,
            Some(FakeEntry::Owner(o)) => TargetOwnership::OwnedByOther { owner: o.clone() },
            Some(FakeEntry::Ambiguous(reason)) => TargetOwnership::Ambiguous {
                reason: reason.clone(),
            },
        })
    }

    fn release(&self, dev: (u32, u32)) -> Result<(), OwnershipError> {
        let mut s = self.lock();
        if let Some(errno) = s.release_error {
            return Err(OwnershipError::Io {
                dev: Some(dev),
                op: "unlink",
                errno,
            });
        }
        match s.entries.get(&dev) {
            None => Ok(()),
            Some(FakeEntry::Owner(o)) if o == QEMINGA_OWNER => {
                s.entries.remove(&dev);
                Ok(())
            }
            Some(FakeEntry::Owner(_) | FakeEntry::Ambiguous(_)) => {
                Err(OwnershipError::NotOwnedBySelf { dev })
            }
        }
    }

    fn inspect_all(&self) -> Result<OwnershipSnapshot, OwnershipError> {
        let s = self.lock();
        if let Some(errno) = s.inspect_error {
            return Err(OwnershipError::Io {
                dev: None,
                op: "readdir",
                errno,
            });
        }
        let mut owned_by_self = Vec::new();
        let mut owned_by_other = Vec::new();
        let mut ambiguous: Vec<AmbiguousEntry> = s
            .extra_ambiguous
            .iter()
            .cloned()
            .map(|reason| AmbiguousEntry { dev: None, reason })
            .collect();
        for (&dev, entry) in &s.entries {
            match entry {
                FakeEntry::Owner(o) if o == QEMINGA_OWNER => owned_by_self.push(dev),
                FakeEntry::Owner(_) => owned_by_other.push(dev),
                FakeEntry::Ambiguous(reason) => {
                    ambiguous.push(AmbiguousEntry {
                        dev: Some(dev),
                        reason: format!("{}: {reason}", format_dev_filename(dev)),
                    });
                }
            }
        }
        Ok(OwnershipSnapshot {
            owned_by_self,
            owned_by_other,
            ambiguous,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dev_filename_round_trips_and_rejects_non_canonical_forms() {
        assert_eq!(format_dev_filename((0, 0)), "0-0");
        assert_eq!(format_dev_filename((8, 17)), "8-17");
        assert_eq!(parse_dev_filename("0-0"), Some((0, 0)));
        assert_eq!(parse_dev_filename("8-17"), Some((8, 17)));
        assert_eq!(
            parse_dev_filename("4294967295-4294967295"),
            Some((u32::MAX, u32::MAX))
        );
        for bad in [
            "",
            "8",
            "8-",
            "-1",
            "08-1",
            "8-01",
            "+8-1",
            "8-1-2",
            "8:1",
            "8-1\n",
            "4294967296-1",
            "frozen",
        ] {
            assert_eq!(parse_dev_filename(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn owner_tag_parser_enforces_charset_and_bounds() {
        assert_eq!(parse_owner_tag(b"qeminga\n"), Some("qeminga"));
        assert_eq!(
            parse_owner_tag(b"guest-integrity_v1.2\n"),
            Some("guest-integrity_v1.2")
        );
        for bad in [
            b"".as_slice(),
            b"\n",
            b"qeminga",
            b"qeminga\r\n",
            b"qeminga\nextra\n",
            b"bad tag\n",
            b"bad/tag\n",
            b"bad\0tag\n",
        ] {
            assert_eq!(parse_owner_tag(bad), None, "{bad:?}");
        }
        let max_valid = format!("{}\n", "a".repeat(MAX_OWNER_TAG_LEN));
        assert_eq!(
            parse_owner_tag(max_valid.as_bytes()),
            Some("a".repeat(MAX_OWNER_TAG_LEN).as_str())
        );
        let too_long = format!("{}\n", "a".repeat(MAX_OWNER_TAG_LEN + 1));
        assert_eq!(parse_owner_tag(too_long.as_bytes()), None);
    }

    proptest! {
        #[test]
        fn dev_filename_round_trip_property(maj in any::<u32>(), min in any::<u32>()) {
            let formatted = format_dev_filename((maj, min));
            prop_assert_eq!(parse_dev_filename(&formatted), Some((maj, min)));
        }

        #[test]
        fn parsers_never_panic_on_arbitrary_input(s in ".*", bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_dev_filename(&s);
            let _ = parse_owner_tag(&bytes);
        }
    }

    #[test]
    fn linux_store_claims_releases_respects_foreign_and_detects_ambiguity() {
        let dir = tempfile::tempdir().unwrap();
        let store = LinuxOwnershipStore::open(dir.path()).unwrap();

        // 1. Unclaimed -> inspect returns Unclaimed; fresh claim -> Acquired, repeat -> AlreadyOwnedBySelf.
        assert_eq!(store.inspect((8, 1)).unwrap(), TargetOwnership::Unclaimed);
        assert_eq!(store.try_claim((8, 1)).unwrap(), ClaimOutcome::Acquired);
        assert_eq!(store.inspect((8, 1)).unwrap(), TargetOwnership::OwnedBySelf);
        assert_eq!(
            store.try_claim((8, 1)).unwrap(),
            ClaimOutcome::AlreadyOwnedBySelf
        );

        // 2. Cooperating second owner claims (8, 2) -> qeminga sees OwnedByOther
        //    on both inspect and try_claim and refuses to release it.
        assert!(store.claim_as("guest-integrity", (8, 2)).unwrap());
        assert!(!store.claim_as("other", (8, 2)).unwrap());
        assert_eq!(
            store.inspect((8, 2)).unwrap(),
            TargetOwnership::OwnedByOther {
                owner: "guest-integrity".to_owned()
            }
        );
        assert_eq!(
            store.try_claim((8, 2)).unwrap(),
            ClaimOutcome::OwnedByOther {
                owner: "guest-integrity".to_owned()
            }
        );
        assert!(matches!(
            store.release((8, 2)),
            Err(OwnershipError::NotOwnedBySelf { dev: (8, 2) })
        ));
        assert!(dir.path().join("8-2").exists());

        // 3. inspect_all classifies self vs other cleanly with zero ambiguity.
        let snap = store.inspect_all().unwrap();
        assert_eq!(snap.owned_by_self, vec![(8, 1)]);
        assert_eq!(snap.owned_by_other, vec![(8, 2)]);
        assert!(snap.ambiguous.is_empty());

        // 4. Empty file, symlink, and stray filename all classify as Ambiguous.
        std::fs::write(dir.path().join("8-3"), b"").unwrap();
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join("8-4")).unwrap();
        std::fs::write(dir.path().join("stray-file"), b"junk\n").unwrap();
        assert!(matches!(
            store.inspect((8, 3)).unwrap(),
            TargetOwnership::Ambiguous { .. }
        ));
        assert!(matches!(
            store.inspect((8, 4)).unwrap(),
            TargetOwnership::Ambiguous { .. }
        ));
        assert!(matches!(
            store.try_claim((8, 3)).unwrap(),
            ClaimOutcome::Ambiguous { .. }
        ));
        assert!(matches!(
            store.try_claim((8, 4)).unwrap(),
            ClaimOutcome::Ambiguous { .. }
        ));
        let snap = store.inspect_all().unwrap();
        assert_eq!(snap.owned_by_self, vec![(8, 1)]);
        assert_eq!(snap.owned_by_other, vec![(8, 2)]);
        assert_eq!(snap.ambiguous.len(), 3, "{:?}", snap.ambiguous);
        let amb_devs: BTreeSet<Option<(u32, u32)>> = snap.ambiguous.iter().map(|e| e.dev).collect();
        assert_eq!(
            amb_devs,
            BTreeSet::from([None, Some((8, 3)), Some((8, 4))]),
            "{:?}",
            snap.ambiguous
        );

        // 5. Release removes only qeminga's claim and is idempotent.
        store.release((8, 1)).unwrap();
        assert!(!dir.path().join("8-1").exists());
        assert_eq!(store.inspect((8, 1)).unwrap(), TargetOwnership::Unclaimed);
        store.release((8, 1)).unwrap();
        assert!(dir.path().join("8-2").exists());

        // 6. Cooperating owner releases its own claim cleanly.
        store.release_as("guest-integrity", (8, 2)).unwrap();
        assert!(!dir.path().join("8-2").exists());
    }

    #[test]
    fn linux_store_refuses_symlink_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = LinuxOwnershipStore::open(&link).unwrap_err();
        assert!(
            matches!(
                err,
                OwnershipError::OpenDir {
                    errno: Errno::ELOOP | Errno::ENOTDIR,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn linux_store_rejects_fifo_socket_and_dir_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo_path = dir.path().join("8-5");
        let sock_path = dir.path().join("8-6");
        let subdir_path = dir.path().join("8-7");

        nix::unistd::mkfifo(&fifo_path, Mode::from_bits_truncate(0o600)).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        std::fs::create_dir(&subdir_path).unwrap();

        let store = std::sync::Arc::new(LinuxOwnershipStore::open(dir.path()).unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let s = std::sync::Arc::clone(&store);
        let worker = std::thread::spawn(move || {
            let i_fifo = s.inspect((8, 5)).unwrap();
            let i_sock = s.inspect((8, 6)).unwrap();
            let i_dir = s.inspect((8, 7)).unwrap();
            let c_fifo = s.try_claim((8, 5)).unwrap();
            let c_sock = s.try_claim((8, 6)).unwrap();
            let c_dir = s.try_claim((8, 7)).unwrap();
            let snap = s.inspect_all().unwrap();
            let _ = tx.send((i_fifo, i_sock, i_dir, c_fifo, c_sock, c_dir, snap));
        });

        let (i_fifo, i_sock, i_dir, c_fifo, c_sock, c_dir, snap) = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("opening FIFO claim entry blocked instead of using O_NONBLOCK");
        worker.join().unwrap();
        assert!(
            matches!(i_fifo, TargetOwnership::Ambiguous { .. }),
            "{i_fifo:?}"
        );
        assert!(
            matches!(i_sock, TargetOwnership::Ambiguous { .. }),
            "{i_sock:?}"
        );
        assert!(
            matches!(i_dir, TargetOwnership::Ambiguous { .. }),
            "{i_dir:?}"
        );
        assert!(
            matches!(c_fifo, ClaimOutcome::Ambiguous { .. }),
            "{c_fifo:?}"
        );
        assert!(
            matches!(c_sock, ClaimOutcome::Ambiguous { .. }),
            "{c_sock:?}"
        );
        assert!(matches!(c_dir, ClaimOutcome::Ambiguous { .. }), "{c_dir:?}");
        assert!(snap.owned_by_self.is_empty(), "{snap:?}");
        assert!(snap.owned_by_other.is_empty(), "{snap:?}");
        assert_eq!(snap.ambiguous.len(), 3, "{snap:?}");
        let amb_devs: BTreeSet<Option<(u32, u32)>> = snap.ambiguous.iter().map(|e| e.dev).collect();
        assert_eq!(
            amb_devs,
            BTreeSet::from([Some((8, 5)), Some((8, 6)), Some((8, 7))]),
            "{snap:?}"
        );
    }

    #[test]
    fn linux_store_reports_gid_and_tmpfs_magic() {
        use std::os::unix::fs::MetadataExt;
        // `/dev/shm` is tmpfs on Linux; the repository root is on a non-tmpfs filesystem.
        if Path::new("/dev/shm").is_dir() {
            let shm_dir = tempfile::tempdir_in("/dev/shm").unwrap();
            let meta = std::fs::metadata(shm_dir.path()).unwrap();
            let store = LinuxOwnershipStore::open(shm_dir.path()).unwrap();
            assert_eq!(store.gid(), meta.gid());
            assert_eq!(store.uid(), meta.uid());
            let fs = nix::sys::statfs::statfs(shm_dir.path()).unwrap();
            assert_eq!(store.is_tmpfs(), fs.filesystem_type() == TMPFS_MAGIC);
            assert!(store.is_tmpfs(), "/dev/shm should report TMPFS_MAGIC");
        }
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let store = LinuxOwnershipStore::open(manifest_dir).unwrap();
        let meta = std::fs::metadata(manifest_dir).unwrap();
        assert_eq!(store.gid(), meta.gid());
        let fs = nix::sys::statfs::statfs(manifest_dir).unwrap();
        assert_eq!(store.is_tmpfs(), fs.filesystem_type() == TMPFS_MAGIC);
        assert!(
            !store.is_tmpfs(),
            "repository checkout should not be on tmpfs"
        );
    }

    #[test]
    fn ownership_error_host_reasons_never_disclose_paths_or_devices() {
        let cases = [
            OwnershipError::OpenDir {
                path: PathBuf::from("/run/secret-tenant-owners"),
                errno: Errno::EACCES,
            },
            OwnershipError::Io {
                dev: Some((8, 42)),
                op: "create",
                errno: Errno::EIO,
            },
            OwnershipError::TooManyEntries { limit: 4096 },
            OwnershipError::NotOwnedBySelf { dev: (8, 42) },
        ];
        for err in cases {
            let reason = err.host_reason();
            assert!(!reason.contains("secret-tenant"), "{reason}");
            assert!(!reason.contains("8:42"), "{reason}");
            assert!(!reason.contains("8-42"), "{reason}");
        }
    }
}
