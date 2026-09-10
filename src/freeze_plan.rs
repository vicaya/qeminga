//! The freeze plan: which mounted filesystems `guest-fsfreeze-*` and
//! `guest-fstrim` operate on, and in what order (design §4.2, §8.2
//! `state_path` validation, §8.5; AC17; OQ-4; C-12).
//!
//! From `/proc/self/mountinfo` the plan keeps only local, device-backed
//! filesystems of a type whose `FIFREEZE` behaviour is tested
//! ([`FREEZABLE_FS_TYPES`]); pseudo and network filesystems, FUSE, overlay
//! and anything not backed by a `/dev/` node are excluded. Bind mounts
//! and subvolumes of the same superblock are de-duplicated by `(major,
//! minor)`: the first mount in mount order names the target and the
//! others are kept as its aliases, since a later mount placed over the
//! first pathname leaves the superblock reachable only through them.
//! Freeze traverses the plan in reverse mount order (deepest first), thaw
//! forward.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::mountinfo::MountEntry;

/// Filesystem types eligible for the plan (OQ-4): only those whose freeze
/// behaviour is covered by a privileged test. Extending this list requires
/// a test in T5.2 for that filesystem.
pub const FREEZABLE_FS_TYPES: &[&str] = &["ext4", "xfs"];

/// A filesystem in the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The (first, in mount order) mount point of the superblock: the
    /// name the target goes by in replies and audit records.
    pub mountpoint: PathBuf,
    /// Its other mount points (bind mounts, subvolumes), in mount order.
    /// A pathname only names whatever is mounted there now, so the
    /// kernel shim verifies each opened directory against `dev` and the
    /// handlers fall back to the aliases when `mountpoint` no longer leads
    /// to this superblock (a mount placed over it).
    pub aliases: Vec<PathBuf>,
    /// `(major, minor)` of the superblock.
    pub dev: (u32, u32),
    /// Filesystem type.
    pub fs_type: String,
}

impl Target {
    /// Every pathname of the superblock, `mountpoint` first.
    pub fn mountpoints(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.mountpoint.as_path()).chain(self.aliases.iter().map(PathBuf::as_path))
    }
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
        let mut seen: HashMap<(u32, u32), usize> = HashMap::new();
        let mut targets: Vec<Target> = Vec::new();
        for entry in mounts {
            if !is_eligible(entry) {
                continue;
            }
            match seen.get(&entry.dev()) {
                Some(&index) => targets[index].aliases.push(entry.mount_point.clone()),
                None => {
                    seen.insert(entry.dev(), targets.len());
                    targets.push(Target {
                        mountpoint: entry.mount_point.clone(),
                        aliases: Vec::new(),
                        dev: entry.dev(),
                        fs_type: entry.fs_type.clone(),
                    });
                }
            }
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

    /// The intersection with the requested mount points. A requested name
    /// selects the superblock mounted at exactly that path *now*: the last
    /// mount-table entry with that mount point (byte-exact, no
    /// normalisation; a mount point that is not valid UTF-8 can never be
    /// named on the wire), whatever the plan calls the superblock. So one
    /// name never selects two superblocks, a name that only a hidden
    /// (overmounted) mount point of a target carries selects nothing, and
    /// the count of §4.2 "Coverage" is one per requested superblock (#43
    /// §1). The selected target keeps all its mount points: they are how
    /// it is reached and recovered, not what it was selected by. Unknown
    /// paths are ignored, not errors (C-12). Order and the mount table are
    /// preserved.
    pub fn restrict_to(&self, mountpoints: &[String]) -> FreezePlan {
        let selected: Vec<(u32, u32)> = mountpoints
            .iter()
            .filter_map(|name| self.mounted_at(name))
            .collect();
        FreezePlan {
            targets: self
                .targets
                .iter()
                .filter(|t| selected.contains(&t.dev))
                .cloned()
                .collect(),
            mounts: self.mounts.clone(),
        }
    }

    /// The superblock mounted at exactly `path` now: the last entry of the
    /// mount table with that mount point (a later mount over the same path
    /// hides the earlier one), or `None` when nothing is mounted there.
    fn mounted_at(&self, path: &str) -> Option<(u32, u32)> {
        self.mounts
            .iter()
            .rev()
            .find(|(mountpoint, _)| mountpoint.as_os_str() == path)
            .map(|(_, dev)| *dev)
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

    /// `true` when the filesystem holding `path` is in the plan, going by
    /// the mount table's pathnames (longest prefix). Startup validates the
    /// recovery marker with [`covers_device`](Self::covers_device) on the
    /// device of its opened directory instead: a pathname's prefix says
    /// nothing about `..` components or symlinks in it.
    pub fn covers(&self, path: &Path) -> bool {
        self.mount_of(path)
            .is_some_and(|(_, dev)| self.covers_device(dev))
    }

    /// `true` when the superblock `dev` is in the plan, i.e. a freeze would
    /// freeze whatever is on it (§8.2: the recovery marker must not be on
    /// such a filesystem).
    pub fn covers_device(&self, dev: (u32, u32)) -> bool {
        self.targets.iter().any(|t| t.dev == dev)
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
        // The other mount points of the superblock are kept as aliases,
        // in mount order: the ioctls fall back to them when the first
        // pathname no longer leads to the superblock.
        assert_eq!(
            plan.targets()[0].aliases,
            [PathBuf::from("/var/www"), PathBuf::from("/mnt/rootbind")]
        );
        assert_eq!(plan.targets()[1].aliases, [PathBuf::from("/srv/exports")]);
        // The bind mount appearing *first* is what gets kept as the name.
        let text = "1 0 8:1 /srv/www /var/www rw - ext4 /dev/sda1 rw\n\
                    2 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let plan = FreezePlan::build(&parse_mountinfo(text));
        assert_eq!(mountpoints(&plan), ["/var/www"]);
        assert_eq!(plan.targets()[0].aliases, [PathBuf::from("/")]);
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn a_hidden_first_mount_keeps_its_accessible_alias() {
        // /data (8:2) has a bind alias /data-alias; a later mount (8:3)
        // was placed over /data, so the pathname /data now leads to 8:3.
        // The plan must keep /data-alias for 8:2 rather than discard it as
        // a duplicate: the alias is how 8:2 is still reached.
        let plan = plan_from("hidden_mount.txt");
        assert_eq!(mountpoints(&plan), ["/", "/data", "/data"]);
        let data = plan.targets().iter().find(|t| t.dev == (8, 2)).unwrap();
        let names: Vec<&Path> = data.mountpoints().collect();
        assert_eq!(names, [Path::new("/data"), Path::new("/data-alias")]);
        assert_eq!(data.aliases, [PathBuf::from("/data-alias")]);
        let over = plan.targets().iter().find(|t| t.dev == (8, 3)).unwrap();
        assert!(over.aliases.is_empty());
        assert_eq!(over.mountpoints().count(), 1);
        // Both superblocks stay in the plan (each may be frozen), and the
        // device check knows both.
        assert!(plan.covers_device((8, 2)));
        assert!(plan.covers_device((8, 3)));
        assert!(!plan.covers_device((8, 4)));
        // A freeze-list naming the alias selects the hidden superblock.
        let restricted = plan.restrict_to(&["/data-alias".to_owned()]);
        assert_eq!(restricted.len(), 1);
        assert_eq!(restricted.targets()[0].dev, (8, 2));
        // Naming /data selects what is mounted there now (8:3), not the
        // superblock whose hidden first name it also is.
        let restricted = plan.restrict_to(&["/data".to_owned()]);
        let devs: Vec<(u32, u32)> = restricted.targets().iter().map(|t| t.dev).collect();
        assert_eq!(devs, [(8, 3)]);
    }

    #[test]
    fn a_requested_name_selects_at_most_one_superblock_so_the_count_is_coverage() {
        // The coverage contract (§4.2, §4.5) rests on one requested name
        // selecting at most one superblock. Over the overmount, a request
        // for /data and a path nothing is mounted at must select exactly
        // one target, so a controller requesting two sees a count of one
        // and rejects; were the hidden name to select 8:2 as well, the
        // count would read 2 with /required never protected.
        let plan = plan_from("hidden_mount.txt");
        let restricted = plan.restrict_to(&["/data".to_owned(), "/required".to_owned()]);
        let devs: Vec<(u32, u32)> = restricted.targets().iter().map(|t| t.dev).collect();
        assert_eq!(devs, [(8, 3)]);
        // The selected target keeps every name it has: they are how it is
        // reached, not what selected it.
        let both = plan.restrict_to(&["/data".to_owned(), "/data-alias".to_owned()]);
        let devs: Vec<(u32, u32)> = both.targets().iter().map(|t| t.dev).collect();
        assert_eq!(devs, [(8, 2), (8, 3)]);
        let hidden = both.targets().iter().find(|t| t.dev == (8, 2)).unwrap();
        assert_eq!(hidden.aliases, [PathBuf::from("/data-alias")]);
        // A name nothing is mounted at, or a mount outside the plan,
        // selects nothing.
        assert!(plan.restrict_to(&["/required".to_owned()]).is_empty());
        assert!(plan.restrict_to(&["/data/".to_owned()]).is_empty());
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
        // An alias names its superblock too.
        let plan = plan_from("bind_mounts.txt");
        let restricted = plan.restrict_to(&["/srv/exports".to_owned()]);
        assert_eq!(mountpoints(&restricted), ["/data"]);
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
        // The device check (what startup uses, on the opened directory).
        assert!(!plan.covers_device((0, 30)));
        assert!(!plan.covers_device((0, 0)));
    }

    #[test]
    fn state_path_on_root_ext4_is_covered() {
        let plan = plan_from("tmpfs_and_nfs.txt");
        assert!(plan.covers(Path::new("/var/lib/qeminga/frozen")));
        assert!(plan.covers(Path::new("/frozen")));
        assert!(plan.covers_device((8, 1)));
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
        assert!(!plan.covers_device((0, 1)));
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
