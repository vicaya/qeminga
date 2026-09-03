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
//! `\040`, `\011`, `\012` and `\134`; [`unescape`] decodes them. Malformed
//! lines are skipped rather than failing the whole parse, and line order
//! (mount order) is preserved.
#![forbid(unsafe_code)]

use std::path::Path;

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
    /// a subvolume).
    pub root: String,
    /// Mount point, unescaped.
    pub mount_point: String,
    /// Per-mount options (`rw,relatime,...`).
    pub mount_options: String,
    /// Optional fields such as `shared:1`, possibly empty.
    pub optional_fields: Vec<String>,
    /// Filesystem type (`ext4`, `tmpfs`, `fuse.sshfs`, ...).
    pub fs_type: String,
    /// Mount source, unescaped (`/dev/sda1`, `tmpfs`, `filer:/export`).
    pub source: String,
    /// Per-superblock options, unescaped.
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
/// `\011` → tab, `\012` → newline, `\134` → backslash). Any other
/// backslash sequence is kept verbatim.
pub fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
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
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `mountinfo` text. Malformed lines are skipped; never panics.
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MountEntry> {
    let mut fields = line.split(' ').filter(|f| !f.is_empty());
    let mount_id = fields.next()?.parse().ok()?;
    let parent_id = fields.next()?.parse().ok()?;
    let (major, minor) = fields.next()?.split_once(':')?;
    let major = major.parse().ok()?;
    let minor = minor.parse().ok()?;
    let root = unescape(fields.next()?);
    let mount_point = unescape(fields.next()?);
    let mount_options = fields.next()?.to_owned();
    let mut optional_fields = Vec::new();
    loop {
        let field = fields.next()?;
        if field == "-" {
            break;
        }
        optional_fields.push(field.to_owned());
    }
    let fs_type = fields.next()?.to_owned();
    let source = unescape(fields.next()?);
    let super_options = fields.next().map(unescape).unwrap_or_default();
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

/// Where the mount table comes from; production reads
/// `/proc/self/mountinfo`, tests use fixtures.
pub trait MountSource: Send + Sync {
    /// The raw `mountinfo` text.
    fn read_mountinfo(&self) -> Result<String, Error>;

    /// Parsed entries in mount order.
    fn mounts(&self) -> Result<Vec<MountEntry>, Error> {
        Ok(parse_mountinfo(&self.read_mountinfo()?))
    }
}

/// Production source.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcMounts;

/// The file [`ProcMounts`] reads.
pub const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

impl MountSource for ProcMounts {
    fn read_mountinfo(&self) -> Result<String, Error> {
        std::fs::read_to_string(Path::new(MOUNTINFO_PATH))
            .map_err(|err| Error::Internal(format!("cannot read {MOUNTINFO_PATH}: {err}")))
    }
}

/// A fixed mount table (tests and fixtures).
#[derive(Debug, Clone)]
pub struct StaticMounts(pub String);

impl MountSource for StaticMounts {
    fn read_mountinfo(&self) -> Result<String, Error> {
        Ok(self.0.clone())
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
        let entries = parse_mountinfo(&fixture("tmpfs_and_nfs.txt"));
        let overlay = entries.iter().find(|e| e.fs_type == "overlay").unwrap();
        assert!(overlay.optional_fields.is_empty());
        assert_eq!(overlay.mount_point, "/var/lib/docker/overlay2/abc/merged");
        let simple = parse_mountinfo(&fixture("simple.txt"));
        assert_eq!(simple.len(), 5);
        assert_eq!(simple[3].fs_type, "ext4");
        assert_eq!(simple[3].source, "/dev/sda1");
        assert_eq!(simple[4].mount_point, "/home");
    }

    #[test]
    fn decodes_octal_escapes_in_paths() {
        assert_eq!(unescape("a\\040b"), "a b");
        assert_eq!(unescape("a\\011b"), "a\tb");
        assert_eq!(unescape("a\\012b"), "a\nb");
        assert_eq!(unescape("a\\134b"), "a\\b");
        assert_eq!(unescape("\\040\\040"), "  ");
        // Not an escape: too short, non-octal, or out of range.
        assert_eq!(unescape("a\\04"), "a\\04");
        assert_eq!(unescape("a\\0x9b"), "a\\0x9b");
        assert_eq!(unescape("trailing\\"), "trailing\\");
        assert_eq!(unescape("\\777"), "\\777");
        let entries = parse_mountinfo(&fixture("escaped_paths.txt"));
        let points: Vec<&str> = entries.iter().map(|e| e.mount_point.as_str()).collect();
        assert_eq!(
            points,
            [
                "/",
                "/mnt/with space",
                "/mnt/tab\there",
                "/mnt/back\\slash",
                "/mnt/nl\ninside"
            ]
        );
        assert_eq!(entries[3].root, "/sub dir");
        assert_eq!(entries[3].source, "/dev/disk/by-label/my label");
    }

    #[test]
    fn preserves_line_order_as_mount_order() {
        let entries = parse_mountinfo(&fixture("nested.txt"));
        let points: Vec<&str> = entries.iter().map(|e| e.mount_point.as_str()).collect();
        assert_eq!(points, ["/", "/home", "/home/data", "/home/data/deep"]);
        let ids: Vec<u32> = entries.iter().map(|e| e.mount_id).collect();
        assert_eq!(ids, [27, 30, 31, 32]);
        // Bind mounts share (major, minor) with their origin.
        let entries = parse_mountinfo(&fixture("bind_mounts.txt"));
        assert_eq!(entries[0].dev(), entries[1].dev());
        assert_eq!(entries[1].root, "/srv/www");
        let entries = parse_mountinfo(&fixture("btrfs_subvols.txt"));
        assert!(entries[..3].iter().all(|e| e.dev() == (0, 38)));
        assert_eq!(entries[1].root, "/@home");
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
        let points: Vec<&str> = entries.iter().map(|e| e.mount_point.as_str()).collect();
        assert_eq!(points, ["/", "/also-ok", "/fine"]);
        assert_eq!(entries[1].super_options, "");
        assert!(parse_mountinfo("").is_empty());
    }

    #[test]
    fn proc_source_parses_the_running_system() {
        let entries = ProcMounts.mounts().unwrap();
        assert!(entries.iter().any(|e| e.mount_point == "/"));
        assert!(entries.iter().any(|e| e.fs_type == "proc"));
    }

    proptest! {
        #[test]
        fn parser_never_panics(text in "\\PC*") {
            let _ = parse_mountinfo(&text);
            let _ = unescape(&text);
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
            prop_assert_eq!(unescape(&text), text);
        }
    }
}
