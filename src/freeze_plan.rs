//! The freeze plan: which mounted filesystems `guest-fsfreeze-*` and
//! `guest-fstrim` operate on, and in what order (design §4.2, §8.2
//! `state_path` validation, §8.5; AC17; OQ-4; C-12).
//!
//! From `/proc/self/mountinfo` the plan keeps only local, device-backed
//! filesystems of a type whose `FIFREEZE` behaviour is tested
//! ([`FREEZABLE_FS_TYPES`]); pseudo and network filesystems, FUSE, overlay
//! and anything not backed by a `/dev/` node are excluded. Bind mounts
//! and subvolumes of the same superblock are de-duplicated by `(major,
//! minor)`, keeping the first mount in mount order. Freeze traverses the
//! plan in reverse mount order (deepest first), thaw forward.
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::mountinfo::MountEntry;

/// Filesystem types eligible for the plan (OQ-4): only those whose freeze
/// behaviour is covered by a privileged test. Extending this list requires
/// a test in T5.2 for that filesystem.
pub const FREEZABLE_FS_TYPES: &[&str] = &["ext4", "xfs"];

/// A filesystem in the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The (first, in mount order) mount point of the superblock.
    pub mountpoint: PathBuf,
    /// `(major, minor)` of the superblock.
    pub dev: (u32, u32),
    /// Filesystem type.
    pub fs_type: String,
}

/// The ordered set of filesystems to freeze, thaw or trim.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FreezePlan {
    /// Targets in mount order.
    targets: Vec<Target>,
    /// Every mount point with its device, for [`covers`](Self::covers).
    mounts: Vec<(PathBuf, (u32, u32))>,
}

/// `true` when the entry is a local, device-backed filesystem of an
/// eligible type.
pub fn is_eligible(entry: &MountEntry) -> bool {
    FREEZABLE_FS_TYPES.contains(&entry.fs_type.as_str()) && entry.source.starts_with("/dev/")
}

impl FreezePlan {
    /// Builds the plan from a mount table in mount order.
    pub fn build(mounts: &[MountEntry]) -> FreezePlan {
        let mut seen = HashSet::new();
        let mut targets = Vec::new();
        for entry in mounts {
            if !is_eligible(entry) || !seen.insert(entry.dev()) {
                continue;
            }
            targets.push(Target {
                mountpoint: entry.mount_point.clone(),
                dev: entry.dev(),
                fs_type: entry.fs_type.clone(),
            });
        }
        FreezePlan {
            targets,
            mounts: mounts
                .iter()
                .map(|e| (e.mount_point.clone(), e.dev()))
                .collect(),
        }
    }

    /// Targets in mount order.
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// `true` when nothing is eligible; freezing zero filesystems is valid.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Number of targets.
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Reverse mount order: nested mounts first.
    pub fn freeze_order(&self) -> impl DoubleEndedIterator<Item = &Target> {
        self.targets.iter().rev()
    }

    /// Forward mount order.
    pub fn thaw_order(&self) -> impl DoubleEndedIterator<Item = &Target> {
        self.targets.iter()
    }

    /// The intersection with the requested mount points, matched exactly
    /// on the unescaped mount point (as a path, no normalisation; a mount
    /// point that is not valid UTF-8 can never be named on the wire);
    /// unknown paths are ignored, not errors (C-12). Order and the mount
    /// table are preserved.
    pub fn restrict_to(&self, mountpoints: &[String]) -> FreezePlan {
        FreezePlan {
            targets: self
                .targets
                .iter()
                .filter(|t| {
                    // Byte-exact (`Path` equality would tolerate `/home/`).
                    mountpoints
                        .iter()
                        .any(|m| m.as_str() == t.mountpoint.as_os_str())
                })
                .cloned()
                .collect(),
            mounts: self.mounts.clone(),
        }
    }

    /// The mount point that holds `path` (longest matching prefix, by path
    /// components), with its device.
    pub fn mount_of(&self, path: &Path) -> Option<(&Path, (u32, u32))> {
        self.mounts
            .iter()
            .filter(|(mp, _)| path.starts_with(mp))
            .max_by_key(|(mp, _)| mp.components().count())
            .map(|(mp, dev)| (mp.as_path(), *dev))
    }

    /// `true` when the filesystem holding `path` is in the plan, i.e. a
    /// freeze would freeze `path` (§8.2: the recovery marker must not be
    /// on such a filesystem).
    pub fn covers(&self, path: &Path) -> bool {
        self.mount_of(path)
            .is_some_and(|(_, dev)| self.targets.iter().any(|t| t.dev == dev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::parse_mountinfo;

    fn plan_from(fixture: &str) -> FreezePlan {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mountinfo")
                .join(fixture),
        )
        .unwrap();
        FreezePlan::build(&parse_mountinfo(&text))
    }

    fn mountpoints(plan: &FreezePlan) -> Vec<&str> {
        plan.targets()
            .iter()
            .map(|t| t.mountpoint.to_str().unwrap())
            .collect()
    }

    #[test]
    fn includes_only_freezable_local_device_backed_types() {
        let plan = plan_from("tmpfs_and_nfs.txt");
        assert_eq!(mountpoints(&plan), ["/"]);
        let plan = plan_from("simple.txt");
        assert_eq!(mountpoints(&plan), ["/", "/home"]);
        assert_eq!(plan.targets()[1].fs_type, "xfs");
        assert_eq!(plan.targets()[1].dev, (8, 2));
        // ext4 not backed by /dev (e.g. a network block device exposed
        // oddly, or a fixture) is excluded; xfs on /dev is included.
        let text = "1 0 8:1 / / rw - ext4 rootfs rw\n\
                    2 1 8:2 / /a rw - xfs /dev/sda2 rw\n\
                    3 1 0:40 / /b rw - btrfs /dev/sda3 rw\n\
                    4 1 8:4 / /c rw - vfat /dev/sda4 rw\n\
                    5 1 8:5 / /d rw - ext4 /dev/mapper/vg-lv rw\n\
                    6 1 7:0 / /e rw - ext4 /dev/loop0 rw\n";
        let plan = FreezePlan::build(&parse_mountinfo(text));
        assert_eq!(mountpoints(&plan), ["/a", "/d", "/e"]);
        assert_eq!(FREEZABLE_FS_TYPES, ["ext4", "xfs"]);
    }

    #[test]
    fn dedupes_bind_mounts_by_device_identity() {
        let plan = plan_from("bind_mounts.txt");
        // /var/www and /mnt/rootbind share 8:1 with /; /srv/exports shares
        // 8:2 with /data. First in mount order wins regardless of `root`.
        assert_eq!(mountpoints(&plan), ["/", "/data"]);
        // The bind mount appearing *first* is what gets kept.
        let text = "1 0 8:1 /srv/www /var/www rw - ext4 /dev/sda1 rw\n\
                    2 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let plan = FreezePlan::build(&parse_mountinfo(text));
        assert_eq!(mountpoints(&plan), ["/var/www"]);
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn freeze_order_is_reverse_mount_order_and_thaw_order_is_forward() {
        let plan = plan_from("nested.txt");
        let freeze: Vec<&str> = plan
            .freeze_order()
            .map(|t| t.mountpoint.to_str().unwrap())
            .collect();
        assert_eq!(freeze, ["/home/data/deep", "/home/data", "/home", "/"]);
        let thaw: Vec<&str> = plan
            .thaw_order()
            .map(|t| t.mountpoint.to_str().unwrap())
            .collect();
        assert_eq!(thaw, ["/", "/home", "/home/data", "/home/data/deep"]);
    }

    #[test]
    fn freeze_list_intersection_ignores_unknown_paths() {
        let plan = plan_from("nested.txt");
        let restricted = plan.restrict_to(&[
            "/home".to_owned(),
            "/nonexistent".to_owned(),
            "/proc".to_owned(),
            "/home/data/deep".to_owned(),
        ]);
        assert_eq!(mountpoints(&restricted), ["/home", "/home/data/deep"]);
        let freeze: Vec<&str> = restricted
            .freeze_order()
            .map(|t| t.mountpoint.to_str().unwrap())
            .collect();
        assert_eq!(freeze, ["/home/data/deep", "/home"]);
        // Exact string match on the unescaped mount point: no prefix
        // matching, no trailing slash tolerance.
        let none = plan.restrict_to(&["/home/".to_owned(), "/hom".to_owned()]);
        assert!(none.is_empty());
        assert!(plan.restrict_to(&[]).is_empty());
        let plan = plan_from("escaped_paths.txt");
        let restricted = plan.restrict_to(&["/mnt/with space".to_owned()]);
        assert_eq!(mountpoints(&restricted), ["/mnt/with space"]);
        // `covers` still sees the full mount table after restriction.
        assert!(restricted.covers(Path::new("/mnt/with space/file")));
    }

    #[test]
    fn state_path_on_tmpfs_is_not_covered() {
        let plan = plan_from("tmpfs_and_nfs.txt");
        assert!(!plan.covers(Path::new("/run/qeminga/frozen")));
        assert!(!plan.covers(Path::new("/dev/shm/x")));
        assert!(!plan.covers(Path::new("/mnt/nfs/marker")));
        assert!(
            !plan.covers(Path::new("/mnt/usb/marker")),
            "vfat is not in the plan"
        );
        assert_eq!(
            plan.mount_of(Path::new("/run/qeminga/frozen")),
            Some((Path::new("/run"), (0, 30)))
        );
    }

    #[test]
    fn state_path_on_root_ext4_is_covered() {
        let plan = plan_from("tmpfs_and_nfs.txt");
        assert!(plan.covers(Path::new("/var/lib/qeminga/frozen")));
        assert!(plan.covers(Path::new("/frozen")));
        // Longest prefix wins: /home/data is xfs (in plan), /home/data/deep
        // is ext4 (in plan) and /run (tmpfs) beats / for /run/...
        let plan = plan_from("nested.txt");
        assert_eq!(
            plan.mount_of(Path::new("/home/data/deep/x")),
            Some((Path::new("/home/data/deep"), (8, 4)))
        );
        assert_eq!(
            plan.mount_of(Path::new("/home/datafile")),
            Some((Path::new("/home"), (8, 2)))
        );
        assert!(plan.covers(Path::new("/home/datafile")));
        // A relative path matches no mount.
        assert_eq!(plan.mount_of(Path::new("relative")), None);
        assert!(!plan.covers(Path::new("relative")));
        // A bind mount of a planned device is covered too.
        let plan = plan_from("bind_mounts.txt");
        assert!(plan.covers(Path::new("/srv/exports/marker")));
    }

    #[test]
    fn empty_plan_is_valid() {
        let text = "1 0 0:1 / / rw - tmpfs tmpfs rw\n2 1 0:2 / /proc rw - proc proc rw\n";
        let plan = FreezePlan::build(&parse_mountinfo(text));
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert_eq!(plan.freeze_order().count(), 0);
        assert_eq!(plan.thaw_order().count(), 0);
        assert!(!plan.covers(Path::new("/run/qeminga/frozen")));
        assert_eq!(FreezePlan::build(&[]), FreezePlan::default());
        assert!(FreezePlan::default().is_empty());
    }

    #[test]
    fn btrfs_subvolumes_are_excluded_until_tested() {
        // OQ-4: btrfs is not in FREEZABLE_FS_TYPES yet, so only /boot
        // (ext4) is planned even though the subvolumes are device-backed.
        let plan = plan_from("btrfs_subvols.txt");
        assert_eq!(mountpoints(&plan), ["/boot"]);
    }
}
