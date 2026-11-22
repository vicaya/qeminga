//! `/proc/self/mountinfo` parser (design §3 `guest-get-fsinfo`, §4.2 mount
//! plan; C-19). Shared by `guest-get-fsinfo` (T2.5) and the freeze plan
//! (T3.2).
//!
//! Format (`proc_pid_mountinfo(5)`):
//!
//! ```text
//! 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//! (1)(2)(3)  (4)   (5)   (6)       (7)     (8)(9)  (10)      (11)
//! ```
//!
//! Fields 4, 5, 10 and 11 escape space, tab, newline and backslash as
//! `\040`, `\011`, `\012` and `\134`; [`unescape`] decodes them. The
//! kernel escapes nothing else: a path name is otherwise emitted byte for
//! byte, so the table is not text and need not be UTF-8. The parser works
//! on bytes; path fields stay byte-exact (`PathBuf`), the numeric and
//! structural fields are ASCII, and the informational fields are
//! converted lossily. Malformed lines are skipped rather than failing the
//! whole parse, and line order (mount order) is preserved.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use crate::proto::Error;

/// One line of `mountinfo`, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Unique mount id.
    pub mount_id: u32,
    /// Id of the parent mount.
    pub parent_id: u32,
    /// Device major number (`st_dev`).
    pub major: u32,
    /// Device minor number.
    pub minor: u32,
    /// Root of the mount within the filesystem (`/` unless a bind mount or
    /// a subvolume). Unescaped, byte-exact (paths need not be UTF-8).
    pub root: PathBuf,
    /// Mount point, unescaped and byte-exact: this is what the kernel is
    /// asked to open, so a non-UTF-8 name must survive as is (the wire
    /// reply converts lossily).
    pub mount_point: PathBuf,
    /// Per-mount options (`rw,relatime,...`).
    pub mount_options: String,
    /// Optional fields such as `shared:1`, possibly empty.
    pub optional_fields: Vec<String>,
    /// Filesystem type (`ext4`, `tmpfs`, `fuse.sshfs`, ...).
    pub fs_type: String,
    /// Mount source, unescaped (`/dev/sda1`, `tmpfs`, `filer:/export`);
    /// informational only, so a non-UTF-8 name is converted lossily.
    pub source: String,
    /// Per-superblock options, unescaped (lossily, informational).
    pub super_options: String,
}

impl MountEntry {
    /// `(major, minor)`: the identity of the backing superblock, which is
    /// what freeze de-duplication is keyed on (§4.2).
    pub const fn dev(&self) -> (u32, u32) {
        (self.major, self.minor)
    }
}

/// Decodes the octal escapes used in `mountinfo` paths (`\040` → space,
/// `\011` → tab, `\012` → newline, `\134` → backslash; any three-digit
/// octal escape is decoded the same way). Any other backslash sequence is
/// kept verbatim, and so is every other byte: the result is the path the
/// kernel had, which need not be UTF-8; see [`unescape_path`] and
/// [`unescape_lossy`].
pub fn unescape(field: impl AsRef<[u8]>) -> Vec<u8> {
    let bytes = field.as_ref();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 4 <= bytes.len() {
            let digits = &bytes[i + 1..i + 4];
            if digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                let value = digits
                    .iter()
                    .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// [`unescape`] as a byte-exact path.
pub fn unescape_path(field: impl AsRef<[u8]>) -> PathBuf {
    PathBuf::from(OsString::from_vec(unescape(field)))
}

/// [`unescape`] for informational fields: non-UTF-8 bytes become U+FFFD.
pub fn unescape_lossy(field: impl AsRef<[u8]>) -> String {
    String::from_utf8_lossy(&unescape(field)).into_owned()
}

/// Parses a `mountinfo` table (bytes; it need not be UTF-8). Malformed
/// lines are skipped; never panics.
pub fn parse_mountinfo(table: impl AsRef<[u8]>) -> Vec<MountEntry> {
    table
        .as_ref()
        .split(|&b| b == b'\n')
        .filter_map(parse_line)
        .collect()
}

/// An ASCII field as text, for the numeric and structural fields.
fn ascii(field: &[u8]) -> Option<&str> {
    std::str::from_utf8(field).ok().filter(|s| s.is_ascii())
}

fn number(field: &[u8]) -> Option<u32> {
    ascii(field)?.parse().ok()
}

/// An informational field as text; non-UTF-8 bytes become U+FFFD.
fn lossy(field: &[u8]) -> String {
    String::from_utf8_lossy(field).into_owned()
}

fn parse_line(line: &[u8]) -> Option<MountEntry> {
    let mut fields = line.split(|&b| b == b' ').filter(|f| !f.is_empty());
    let mount_id = number(fields.next()?)?;
    let parent_id = number(fields.next()?)?;
    let (major, minor) = ascii(fields.next()?)?.split_once(':')?;
    let major = major.parse().ok()?;
    let minor = minor.parse().ok()?;
    let root = unescape_path(fields.next()?);
    let mount_point = unescape_path(fields.next()?);
    let mount_options = lossy(fields.next()?);
    let mut optional_fields = Vec::new();
    loop {
        let field = fields.next()?;
        if field == b"-" {
            break;
        }
        optional_fields.push(lossy(field));
    }
    let fs_type = lossy(fields.next()?);
    let source = unescape_lossy(fields.next()?);
    let super_options = fields.next().map(unescape_lossy).unwrap_or_default();
    Some(MountEntry {
        mount_id,
        parent_id,
        major,
        minor,
        root,
        mount_point,
        mount_options,
        optional_fields,
        fs_type,
        source,
        super_options,
    })
}

/// Observes whether the mount namespace has changed since a
/// [`MountSnapshot`] was opened.
///
/// Implementations latch once a change is observed: Linux's
/// `/proc/self/mountinfo` `POLLPRI` notification resets its per-descriptor
/// event watermark on the first poll that reports a change
/// (`fs/proc_namespace.c`), so callers checking before and after each target
/// rely on the monitor staying tripped for the remainder of the walk.
pub trait MountNamespaceMonitor: Send {
    /// Returns `true` if any mount-namespace event occurred since the
    /// snapshot descriptor was opened (or if change detection failed).
    fn has_changed(&mut self) -> bool;
}

/// Static monitor that never reports a mount-namespace change (fixtures and
/// tests).
#[derive(Debug, Default, Clone, Copy)]
pub struct NeverChanged;

impl MountNamespaceMonitor for NeverChanged {
    fn has_changed(&mut self) -> bool {
        false
    }
}

/// Keeps the `/proc/self/mountinfo` descriptor open across a sample and polls
/// it with non-blocking `ppoll(POLLPRI)` to detect any mount, unmount, move,
/// or `pivot_root` event (including unmount-and-rebind mount-ID recycling).
struct ProcMountMonitor {
    file: File,
    changed: bool,
}

impl MountNamespaceMonitor for ProcMountMonitor {
    fn has_changed(&mut self) -> bool {
        if self.changed {
            return true;
        }
        if poll_mountinfo_changed(self.file.as_fd()) {
            self.changed = true;
        }
        self.changed
    }
}

fn revents_indicate_mount_change(revents: nix::poll::PollFlags) -> bool {
    use nix::poll::PollFlags;
    revents.intersects(
        PollFlags::POLLPRI | PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL,
    )
}

fn poll_mountinfo_changed(fd: BorrowedFd<'_>) -> bool {
    use nix::errno::Errno;
    use nix::poll::{PollFd, PollFlags, ppoll};
    use nix::sys::time::TimeSpec;

    let timeout = TimeSpec::new(0, 0);
    loop {
        let mut fds = [PollFd::new(fd, PollFlags::POLLPRI)];
        match ppoll(&mut fds, Some(timeout), None) {
            Ok(0) => return false,
            Ok(_) => {
                // Unknown bits or any error flag fail closed.
                let revents = fds[0].revents().unwrap_or(PollFlags::POLLERR);
                return revents_indicate_mount_change(revents);
            }
            Err(Errno::EINTR) => continue,
            Err(_) => return true,
        }
    }
}

/// A parsed mount-table snapshot paired with a mount-namespace change
/// monitor anchored to the `/proc/self/mountinfo` descriptor that produced
/// it.
pub struct MountSnapshot {
    /// Parsed entries in mount order.
    pub entries: Vec<MountEntry>,
    monitor: Box<dyn MountNamespaceMonitor>,
}

impl MountSnapshot {
    /// Wraps parsed entries with [`NeverChanged`] (fixtures and tests).
    pub fn static_entries(entries: Vec<MountEntry>) -> Self {
        Self {
            entries,
            monitor: Box::new(NeverChanged),
        }
    }

    /// Wraps parsed entries with a custom mount-namespace monitor (tests).
    pub fn with_monitor(entries: Vec<MountEntry>, monitor: Box<dyn MountNamespaceMonitor>) -> Self {
        Self { entries, monitor }
    }

    /// Returns `true` if the mount namespace changed since this snapshot was
    /// opened (latched once observed).
    pub fn has_changed(&mut self) -> bool {
        self.monitor.has_changed()
    }

    /// Borrows the parsed entries and change monitor disjointly so callers
    /// can walk the snapshot while polling for namespace changes.
    pub fn split_mut(&mut self) -> (&[MountEntry], &mut dyn MountNamespaceMonitor) {
        (&self.entries, self.monitor.as_mut())
    }
}

/// Where the mount table comes from; production reads
/// `/proc/self/mountinfo`, tests use fixtures.
pub trait MountSource: Send + Sync {
    /// The raw `mountinfo` table, byte for byte.
    fn read_mountinfo(&self) -> Result<Vec<u8>, Error>;

    /// Parsed entries in mount order.
    fn mounts(&self) -> Result<Vec<MountEntry>, Error> {
        Ok(parse_mountinfo(self.read_mountinfo()?))
    }

    /// Parsed entries paired with a mount-namespace change monitor anchored
    /// to the underlying `mountinfo` descriptor when available.
    fn mount_snapshot(&self) -> Result<MountSnapshot, Error> {
        Ok(MountSnapshot::static_entries(self.mounts()?))
    }
}

/// Production source.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcMounts;

/// The file [`ProcMounts`] reads.
pub const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

/// Explicit bound on the mount table (32 MiB, room for the kernel's
/// `fs.mount-max` default of 100 000 mounts at a few hundred bytes each);
/// a larger table is an error rather than a partial parse.
pub const MOUNTINFO_MAX_BYTES: usize = 32 * 1024 * 1024;

impl MountSource for ProcMounts {
    fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
        read_mountinfo_bounded(Path::new(MOUNTINFO_PATH))
    }

    fn mount_snapshot(&self) -> Result<MountSnapshot, Error> {
        read_mountinfo_snapshot(Path::new(MOUNTINFO_PATH))
    }
}

fn read_bounded_from_file(file: &File, path: &Path) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    file.take(MOUNTINFO_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::Internal(format!("cannot read {}: {err}", path.display())))?;
    if bytes.len() > MOUNTINFO_MAX_BYTES {
        return Err(Error::Internal(format!(
            "{} exceeds {MOUNTINFO_MAX_BYTES} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Reads a mount table under [`MOUNTINFO_MAX_BYTES`], byte for byte.
pub fn read_mountinfo_bounded(path: &Path) -> Result<Vec<u8>, Error> {
    let file = File::open(path)
        .map_err(|err| Error::Internal(format!("cannot read {}: {err}", path.display())))?;
    read_bounded_from_file(&file, path)
}

/// Opens `path`, reads it under [`MOUNTINFO_MAX_BYTES`], parses the mount
/// table, and keeps the open descriptor so `ppoll(POLLPRI)` can detect any
/// mount-namespace change from `open(2)` onward.
pub fn read_mountinfo_snapshot(path: &Path) -> Result<MountSnapshot, Error> {
    let file = File::open(path)
        .map_err(|err| Error::Internal(format!("cannot read {}: {err}", path.display())))?;
    let bytes = read_bounded_from_file(&file, path)?;
    Ok(MountSnapshot {
        entries: parse_mountinfo(&bytes),
        monitor: Box::new(ProcMountMonitor {
            file,
            changed: false,
        }),
    })
}

/// Explicit bound on `/proc/self/fdinfo/<fd>` reads used for the Linux
/// 5.4–5.7 `mnt_id` fallback. The kernel emits `pos`, `flags` and `mnt_id`
/// in the first ~100 bytes ahead of any per-fd lock lines; reading a fixed
/// prefix keeps memory bounded even on files carrying many locks.
pub const FDINFO_MAX_BYTES: usize = 4096;

/// Extracts the `mnt_id` field from `/proc/self/fdinfo/<fd>` bytes.
///
/// Looks for a line starting with `mnt_id:` followed by ASCII whitespace and
/// a base-10 `u32`. Never panics on arbitrary bytes.
pub fn parse_fdinfo_mnt_id(bytes: &[u8]) -> Option<u32> {
    for raw_line in bytes.split(|&b| b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(rest) = line.strip_prefix(b"mnt_id:") else {
            continue;
        };
        let trimmed = rest.trim_ascii();
        if trimmed.is_empty() || !trimmed.iter().all(u8::is_ascii_digit) {
            return None;
        }
        return std::str::from_utf8(trimmed).ok()?.parse().ok();
    }
    None
}

/// Reads `mnt_id` for an open descriptor from `/proc/self/fdinfo/<fd>`
/// under [`FDINFO_MAX_BYTES`].
///
/// Used as the Linux 5.4–5.7 fallback when `statx(2)` succeeds without
/// setting `STATX_MNT_ID` (which arrived in Linux 5.8). Returns `None` on
/// any I/O or parse failure so callers fail closed.
pub fn read_fdinfo_mnt_id(fd: BorrowedFd<'_>) -> Option<u32> {
    let path = format!("/proc/self/fdinfo/{}", fd.as_raw_fd());
    read_fdinfo_mnt_id_from_path(Path::new(&path))
}

fn read_fdinfo_mnt_id_from_path(path: &Path) -> Option<u32> {
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    // Read one extra byte so we know whether the prefix truncated a line.
    file.take(FDINFO_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let slice = if bytes.len() > FDINFO_MAX_BYTES {
        let end = bytes[..FDINFO_MAX_BYTES]
            .iter()
            .rposition(|&b| b == b'\n')?;
        &bytes[..end]
    } else {
        &bytes[..]
    };
    parse_fdinfo_mnt_id(slice)
}

/// A fixed mount table (tests and fixtures).
#[derive(Debug, Clone)]
pub struct StaticMounts(pub String);

impl MountSource for StaticMounts {
    fn read_mountinfo(&self) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    pub(crate) fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mountinfo")
                .join(name),
        )
        .unwrap()
    }

    /// A fixture that is not UTF-8.
    fn fixture_bytes(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mountinfo")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn raw_non_utf8_bytes_survive_the_parse_and_the_read() {
        // The kernel escapes only space, tab, newline and backslash: a
        // Latin-1 "é" (0xE9) in a mount point is written raw, so the table
        // is not UTF-8. Every other line must still parse, and the raw
        // path must reach the kernel byte-exact.
        use std::os::unix::ffi::OsStrExt;
        let table = fixture_bytes("raw_bytes.txt");
        assert!(std::str::from_utf8(&table).is_err(), "fixture is not UTF-8");
        let entries = parse_mountinfo(&table);
        let points: Vec<&[u8]> = entries
            .iter()
            .map(|e| e.mount_point.as_os_str().as_bytes())
            .collect();
        assert_eq!(
            points,
            [&b"/"[..], b"/mnt/caf\xe9", b"/mnt/\xff\xfe bytes", b"/home"]
        );
        assert_eq!(entries[1].mount_point.to_string_lossy(), "/mnt/caf\u{fffd}");
        assert_eq!(entries[1].fs_type, "ext4");
        assert_eq!(entries[1].root, Path::new("/"));
        // A raw byte in an informational field is reported lossily.
        assert_eq!(entries[2].source, "/dev/disk/by-label/caf\u{fffd}");
        // The bounded reader hands the bytes over untouched.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("mountinfo");
        std::fs::write(&file, &table).unwrap();
        assert_eq!(read_mountinfo_bounded(&file).unwrap(), table);
        assert_eq!(
            parse_mountinfo(read_mountinfo_bounded(&file).unwrap()).len(),
            4
        );
    }

    #[test]
    fn parses_all_fields_of_a_line() {
        let entries = parse_mountinfo(
            "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 shared:5 - ext3 /dev/root rw,errors=continue",
        );
        assert_eq!(
            entries,
            vec![MountEntry {
                mount_id: 36,
                parent_id: 35,
                major: 98,
                minor: 0,
                root: "/mnt1".into(),
                mount_point: "/mnt2".into(),
                mount_options: "rw,noatime".into(),
                optional_fields: vec!["master:1".into(), "shared:5".into()],
                fs_type: "ext3".into(),
                source: "/dev/root".into(),
                super_options: "rw,errors=continue".into(),
            }]
        );
        assert_eq!(entries[0].dev(), (98, 0));
        // No optional fields at all.
        let entries = parse_mountinfo(fixture("tmpfs_and_nfs.txt"));
        let overlay = entries.iter().find(|e| e.fs_type == "overlay").unwrap();
        assert!(overlay.optional_fields.is_empty());
        assert_eq!(
            overlay.mount_point,
            Path::new("/var/lib/docker/overlay2/abc/merged")
        );
        let simple = parse_mountinfo(fixture("simple.txt"));
        assert_eq!(simple.len(), 5);
        assert_eq!(simple[3].fs_type, "ext4");
        assert_eq!(simple[3].source, "/dev/sda1");
        assert_eq!(simple[4].mount_point, Path::new("/home"));
    }

    #[test]
    fn non_utf8_mount_points_are_kept_byte_exact() {
        // The kernel escapes every byte outside printable ASCII; `\351` is
        // a Latin-1 "é", not UTF-8, and must reach the kernel unchanged.
        use std::os::unix::ffi::OsStrExt;
        let entries = parse_mountinfo(fixture("escaped_paths.txt"));
        let latin1 = entries.last().unwrap();
        assert_eq!(latin1.mount_point.as_os_str().as_bytes(), b"/mnt/caf\xe9");
        assert_eq!(latin1.mount_point.to_string_lossy(), "/mnt/caf\u{fffd}");
        assert_eq!(unescape_path("/a\\351").as_os_str().as_bytes(), b"/a\xe9");
        assert_eq!(unescape_lossy("/a\\351"), "/a\u{fffd}");
    }

    #[test]
    fn the_mount_table_read_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small");
        std::fs::write(&small, fixture("simple.txt")).unwrap();
        assert_eq!(
            parse_mountinfo(read_mountinfo_bounded(&small).unwrap()).len(),
            5
        );
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'#'; MOUNTINFO_MAX_BYTES + 1]).unwrap();
        let err = read_mountinfo_bounded(&big).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
        assert!(read_mountinfo_bounded(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn decodes_octal_escapes_in_paths() {
        assert_eq!(unescape("a\\040b"), b"a b");
        assert_eq!(unescape("a\\011b"), b"a\tb");
        assert_eq!(unescape("a\\012b"), b"a\nb");
        assert_eq!(unescape("a\\134b"), b"a\\b");
        assert_eq!(unescape("\\040\\040"), b"  ");
        // Not an escape: too short, non-octal, or out of range.
        assert_eq!(unescape("a\\04"), b"a\\04");
        assert_eq!(unescape("a\\0x9b"), b"a\\0x9b");
        assert_eq!(unescape("trailing\\"), b"trailing\\");
        assert_eq!(unescape("\\777"), b"\\777");
        let entries = parse_mountinfo(fixture("escaped_paths.txt"));
        let points: Vec<&Path> = entries.iter().map(|e| e.mount_point.as_path()).collect();
        assert_eq!(
            &points[..5],
            [
                Path::new("/"),
                Path::new("/mnt/with space"),
                Path::new("/mnt/tab\there"),
                Path::new("/mnt/back\\slash"),
                Path::new("/mnt/nl\ninside"),
            ]
        );
        assert_eq!(entries[3].root, Path::new("/sub dir"));
        assert_eq!(entries[3].source, "/dev/disk/by-label/my label");
    }

    #[test]
    fn preserves_line_order_as_mount_order() {
        let entries = parse_mountinfo(fixture("nested.txt"));
        let points: Vec<&Path> = entries.iter().map(|e| e.mount_point.as_path()).collect();
        assert_eq!(
            points,
            ["/", "/home", "/home/data", "/home/data/deep"].map(Path::new)
        );
        let ids: Vec<u32> = entries.iter().map(|e| e.mount_id).collect();
        assert_eq!(ids, [27, 30, 31, 32]);
        // Bind mounts share (major, minor) with their origin.
        let entries = parse_mountinfo(fixture("bind_mounts.txt"));
        assert_eq!(entries[0].dev(), entries[1].dev());
        assert_eq!(entries[1].root, Path::new("/srv/www"));
        let entries = parse_mountinfo(fixture("btrfs_subvols.txt"));
        assert!(entries[..3].iter().all(|e| e.dev() == (0, 38)));
        assert_eq!(entries[1].root, Path::new("/@home"));
    }

    #[test]
    fn skips_malformed_lines_without_panicking() {
        let text = "\n\
                    27 1 8:1 / / rw shared:1 - ext4 /dev/sda1 rw\n\
                    not a mount line\n\
                    x 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
                    28 1 8 / / rw - ext4 /dev/sda1 rw\n\
                    29 1 8:1 / / rw shared:1 ext4 /dev/sda1 rw\n\
                    30 1 8:1 / /ok rw -\n\
                    31 1 8:1 / /ok rw - ext4\n\
                    32 1 8:2 / /also-ok rw - xfs /dev/sda2\n\
                    33 1 8:3 / /fine rw - ext4 /dev/sda3 rw\n";
        let entries = parse_mountinfo(text);
        let points: Vec<&Path> = entries.iter().map(|e| e.mount_point.as_path()).collect();
        assert_eq!(points, ["/", "/also-ok", "/fine"].map(Path::new));
        assert_eq!(entries[1].super_options, "");
        assert!(parse_mountinfo("").is_empty());
    }

    #[test]
    fn proc_source_parses_the_running_system() {
        let entries = ProcMounts.mounts().unwrap();
        assert!(entries.iter().any(|e| e.mount_point == Path::new("/")));
        assert!(entries.iter().any(|e| e.fs_type == "proc"));
    }

    #[test]
    fn parse_fdinfo_mnt_id_extracts_id_and_rejects_malformed_lines() {
        assert_eq!(
            parse_fdinfo_mnt_id(b"pos:\t0\nflags:\t010000000\nmnt_id:\t308\nino:\t1\n"),
            Some(308)
        );
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:   0\r\n"), Some(0));
        assert_eq!(parse_fdinfo_mnt_id(b"pos:\t0\nflags:\t0\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:\t-1\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:\t+42\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:\t42 extra\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:\t4294967296\n"), None);
        assert_eq!(parse_fdinfo_mnt_id(b"mnt_id:\t\n"), None);
    }

    #[test]
    fn read_fdinfo_mnt_id_is_bounded_and_reads_real_o_path_descriptors() {
        use std::os::fd::AsFd;

        // Real O_PATH descriptors on `/` and on a regular file.
        let mounts = ProcMounts.mounts().unwrap();
        let visible = crate::freeze_plan::visible_mounts(&mounts).unwrap();
        let root = visible
            .into_iter()
            .find(|m| m.mount_point == Path::new("/"))
            .expect("visible `/` row");
        let root_fd = nix::fcntl::open(
            Path::new("/"),
            nix::fcntl::OFlag::O_PATH
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .unwrap();
        assert_eq!(read_fdinfo_mnt_id(root_fd.as_fd()), Some(root.mount_id));

        let file = tempfile::NamedTempFile::new().unwrap();
        let file_fd = nix::fcntl::open(
            file.path(),
            nix::fcntl::OFlag::O_PATH
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .unwrap();
        assert!(read_fdinfo_mnt_id(file_fd.as_fd()).is_some());

        // Bounded prefix still parses `mnt_id:` ahead of many lock lines.
        let dir = tempfile::tempdir().unwrap();
        let with_locks = dir.path().join("with_locks");
        let mut content = b"pos:\t0\nflags:\t010000000\nmnt_id:\t42\n".to_vec();
        content.extend(std::iter::repeat_n(b'x', FDINFO_MAX_BYTES * 2));
        std::fs::write(&with_locks, &content).unwrap();
        assert_eq!(read_fdinfo_mnt_id_from_path(&with_locks), Some(42));

        // A `mnt_id:` line straddling the FDINFO_MAX_BYTES boundary is dropped
        // rather than parsed as a truncated integer.
        let truncated = dir.path().join("truncated");
        let mut trunc_bytes = vec![b'a'; FDINFO_MAX_BYTES - 12];
        trunc_bytes.push(b'\n');
        trunc_bytes.extend_from_slice(b"mnt_id:\t123456\n");
        std::fs::write(&truncated, &trunc_bytes).unwrap();
        assert_eq!(read_fdinfo_mnt_id_from_path(&truncated), None);

        assert_eq!(
            read_fdinfo_mnt_id_from_path(&dir.path().join("missing")),
            None
        );
    }

    #[test]
    fn mount_snapshot_tracks_unchanged_proc_mountinfo_and_enforces_size_bound() {
        let mut snapshot = ProcMounts.mount_snapshot().unwrap();
        assert!(
            snapshot
                .entries
                .iter()
                .any(|e| e.mount_point == Path::new("/"))
        );
        assert!(
            !snapshot.has_changed(),
            "unchanged /proc/self/mountinfo must not report a namespace change"
        );
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'#'; MOUNTINFO_MAX_BYTES + 1]).unwrap();
        assert!(read_mountinfo_snapshot(&big).is_err());
        assert!(read_mountinfo_snapshot(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn poll_mountinfo_revents_detects_change_on_pollpri_or_error() {
        use nix::poll::PollFlags;
        assert!(!revents_indicate_mount_change(PollFlags::empty()));
        assert!(!revents_indicate_mount_change(PollFlags::POLLIN));
        assert!(revents_indicate_mount_change(PollFlags::POLLPRI));
        assert!(revents_indicate_mount_change(
            PollFlags::POLLPRI | PollFlags::POLLERR
        ));
        assert!(revents_indicate_mount_change(PollFlags::POLLERR));
        assert!(revents_indicate_mount_change(PollFlags::POLLHUP));
        assert!(revents_indicate_mount_change(PollFlags::POLLNVAL));
    }

    proptest! {
        #[test]
        fn parser_never_panics(text in "\\PC*") {
            let _ = parse_mountinfo(&text);
            let _ = unescape(&text);
        }

        #[test]
        fn parser_never_panics_on_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let entries = parse_mountinfo(&bytes);
            prop_assert!(entries.len() <= bytes.iter().filter(|&&b| b == b'\n').count() + 1);
            let _ = unescape(&bytes);
            let _ = parse_fdinfo_mnt_id(&bytes);
        }

        #[test]
        fn fdinfo_mnt_id_round_trips(id in any::<u32>()) {
            let sample = format!("pos:\t0\nflags:\t010000000\nmnt_id:\t{id}\nino:\t1\n");
            prop_assert_eq!(parse_fdinfo_mnt_id(sample.as_bytes()), Some(id));
        }

        #[test]
        fn structured_lines_never_panic(
            lines in prop::collection::vec(
                "[0-9]{1,3} [0-9]{1,3} [0-9]{1,3}:[0-9]{1,3} /[a-z\\\\0-9]{0,8} /[a-z\\\\0-9 ]{0,12} [a-z,]{1,8}( [a-z]+:[0-9]+){0,2} - [a-z0-9.]{1,8} [a-z/:]{1,10}( [a-z,=0-9]{0,10})?",
                0..10,
            )
        ) {
            let text = lines.join("\n");
            let entries = parse_mountinfo(&text);
            prop_assert!(entries.len() <= lines.len());
            for entry in entries {
                prop_assert!(!entry.fs_type.is_empty());
            }
        }

        #[test]
        fn unescape_round_trips_plain_text(text in "[^\\\\]*") {
            prop_assert_eq!(unescape(&text), text.as_bytes());
        }
    }
}
