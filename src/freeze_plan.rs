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

use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
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
    /// The requested mount point that selected this target
    /// ([`FreezePlan::restrict_to`]), if any: the freeze opens the target
    /// on that name and on nothing else, so a wrong selection is a failed
    /// open rather than an alias silently standing in.
    pub requested: Option<PathBuf>,
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
    /// The whole mount table, as far as the plan needs it: for
    /// [`covers`](Self::covers) and for what a pathname leads to.
    mounts: Vec<MountRow>,
}

/// One row of the mount table: its identity and its parent (the mount
/// graph, which decides what a pathname leads to), its mount point and
/// its superblock.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountRow {
    id: u32,
    parent: u32,
    mount_point: PathBuf,
    dev: (u32, u32),
}

/// The mount table as the tree the kernel walks when it resolves a path:
/// every mount's children by the pathname they are attached at. Indexed
/// once per request, in one pass over the table.
struct MountTree<'a> {
    /// Children of a mount, by `(parent id, mount point)`. A consistent
    /// table has one child per attachment point: a mount stacked on that
    /// child is the child's own child, at the same mount point.
    children: HashMap<(u32, &'a [u8]), Vec<&'a MountRow>>,
    /// The root of the namespace: mounted at `/`, its parent not in the
    /// table or itself (proc_pid_mountinfo(5) permits the root to carry
    /// its own id as its parent id).
    root: Option<&'a MountRow>,
    rows: usize,
}

impl<'a> MountTree<'a> {
    fn index(mounts: &'a [MountRow]) -> Self {
        let ids: HashSet<u32> = mounts.iter().map(|row| row.id).collect();
        let mut children: HashMap<(u32, &[u8]), Vec<&MountRow>> = HashMap::new();
        for row in mounts {
            // A self-parented row (the namespace root) is not its own
            // child: indexed, it would be found stacked on itself at `/`
            // and walked into until the bound, resolving nothing.
            if row.parent == row.id {
                continue;
            }
            children
                .entry((row.parent, row.mount_point.as_os_str().as_bytes()))
                .or_default()
                .push(row);
        }
        let root = mounts.iter().find(|row| {
            row.mount_point.as_os_str() == "/"
                && (row.parent == row.id || !ids.contains(&row.parent))
        });
        MountTree {
            children,
            root,
            rows: mounts.len(),
        }
    }

    /// The superblock mounted at exactly `path` now. From the root mount,
    /// the walk crosses into the child attached at the shortest prefix of
    /// `path` at or below the current mount's own mount point (the first
    /// mount point the kernel meets on the way: a mount stacked on the
    /// current one, or one placed over a directory further down, hides
    /// everything the current mount holds beneath that point), and stops
    /// where there is none. `None` when the path then is not that mount's
    /// mount point (it leads into a filesystem, not to a mount), when the
    /// table is inconsistent at some step (two mounts attached at one
    /// point under one parent: refused rather than guessed), or when it
    /// cannot be walked at all. Proportional to the length of `path`.
    fn resolve(&self, path: &[u8]) -> Option<(u32, u32)> {
        if path.first() != Some(&b'/') {
            return None;
        }
        let mut current = self.root?;
        let mut settled = false;
        // Bounded by the table: a malformed table (a cycle) cannot loop this.
        for _ in 0..=self.rows {
            let at = current.mount_point.as_os_str().as_bytes().len();
            let next = prefixes(path)
                .filter(|prefix| prefix.len() >= at)
                .find_map(|prefix| self.children.get(&(current.id, prefix)));
            match next {
                Some(children) => {
                    if children.len() != 1 {
                        return None;
                    }
                    current = children[0];
                }
                None => {
                    settled = true;
                    break;
                }
            }
        }
        (settled && current.mount_point.as_os_str().as_bytes() == path).then_some(current.dev)
    }
}

/// The prefixes of an absolute `path` at which a mount point could be,
/// shortest first: `/`, then `path` cut at each later `/`, then `path`.
fn prefixes(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::once(&path[..1])
        .chain(
            (1..path.len())
                .filter(move |&i| path[i] == b'/')
                .map(move |i| &path[..i]),
        )
        .chain(std::iter::once(path))
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
                        requested: None,
                    });
                }
            }
        }
        FreezePlan {
            targets,
            mounts: mounts
                .iter()
                .map(|e| MountRow {
                    id: e.mount_id,
                    parent: e.parent_id,
                    mount_point: e.mount_point.clone(),
                    dev: e.dev(),
                })
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
    /// selects the superblock the pathname leads to *now*, resolved as the
    /// kernel resolves a path (`MountTree::resolve`, below: from the root mount
    /// along the pathname's components, crossing into whatever is mounted
    /// at each point, whether stacked on a mount, moved over a newer one
    /// or placed over a plain directory above another mount point;
    /// byte-exact, no normalisation; a mount point that is not valid UTF-8
    /// can never be named on the wire), whatever the plan calls the
    /// superblock. So one name never selects two superblocks, a name that
    /// only a hidden mount point of a target carries selects nothing, and
    /// the count of §4.2 "Coverage" is one per requested superblock (#43
    /// §1). The table is indexed once and each distinct name is resolved
    /// once, so the work is proportional to the request plus the table,
    /// never their product. The selected target records the name that
    /// selected it ([`Target::requested`]) and is opened on that name
    /// only; it keeps all its mount points for the thaw, which reaches and
    /// recovers it by any of them. Unknown paths are ignored, not errors
    /// (C-12). Order and the mount table are preserved.
    pub fn restrict_to(&self, mountpoints: &[String]) -> FreezePlan {
        let tree = MountTree::index(&self.mounts);
        // Each distinct name once; the first name that leads to a
        // superblock is the one it is opened on.
        let mut resolved: HashMap<&str, Option<(u32, u32)>> = HashMap::new();
        let mut selecting: HashMap<(u32, u32), &str> = HashMap::new();
        for name in mountpoints {
            let dev = *resolved
                .entry(name.as_str())
                .or_insert_with(|| tree.resolve(name.as_bytes()));
            if let Some(dev) = dev {
                selecting.entry(dev).or_insert(name.as_str());
            }
        }
        let targets = self
            .targets
            .iter()
            .filter_map(|target| {
                selecting.get(&target.dev).map(|name| Target {
                    requested: Some(PathBuf::from(name)),
                    ..target.clone()
                })
            })
            .collect();
        FreezePlan {
            targets,
            mounts: self.mounts.clone(),
        }
    }

    /// What `path` leads to now (tests; the handlers go through
    /// [`restrict_to`](Self::restrict_to)).
    #[cfg(test)]
    fn visible_at(&self, path: &str) -> Option<(u32, u32)> {
        MountTree::index(&self.mounts).resolve(path.as_bytes())
    }

    /// The mount point that holds `path` (longest matching prefix, by path
    /// components), with its device.
    pub fn mount_of(&self, path: &Path) -> Option<(&Path, (u32, u32))> {
        self.mounts
            .iter()
            .filter(|row| path.starts_with(&row.mount_point))
            .max_by_key(|row| row.mount_point.components().count())
            .map(|row| (row.mount_point.as_path(), row.dev))
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
    use std::time::Duration;

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
    fn a_mount_moved_over_a_newer_one_is_what_the_pathname_leads_to() {
        // The external review's second counterexample: A was mounted first
        // (row 40), B at /data after it, B bound at /b-alias, then A moved
        // over /data. The table keeps A's earlier row, so "the last row at
        // /data" is B, while what /data leads to is A (row 40's parent is
        // row 41). Selection follows the graph.
        let plan = plan_from("moved_mount.txt");
        assert_eq!(plan.visible_at("/data"), Some((8, 5)));
        assert_eq!(plan.visible_at("/b-alias"), Some((8, 2)));
        let restricted = plan.restrict_to(&["/data".to_owned()]);
        let devs: Vec<(u32, u32)> = restricted.targets().iter().map(|t| t.dev).collect();
        assert_eq!(devs, [(8, 5)]);
        assert_eq!(
            restricted.targets()[0].requested.as_deref(),
            Some(Path::new("/data"))
        );
        // B is still selectable by the name it is visible at.
        let restricted = plan.restrict_to(&["/b-alias".to_owned()]);
        let devs: Vec<(u32, u32)> = restricted.targets().iter().map(|t| t.dev).collect();
        assert_eq!(devs, [(8, 2)]);
        // A full freeze selects by nothing.
        assert!(plan.targets().iter().all(|t| t.requested.is_none()));
    }

    #[test]
    fn a_mount_under_an_overmounted_ancestor_is_hidden() {
        // /data/nested (row 41) hangs off row 40, which row 42 covers at
        // /data: /data/nested now leads into row 42's filesystem, where
        // nothing is mounted, so the name selects nothing; /data selects
        // row 42.
        let plan = plan_from("hidden_nested.txt");
        assert_eq!(plan.visible_at("/data/nested"), None);
        assert_eq!(plan.visible_at("/data"), Some((8, 4)));
        assert!(plan.restrict_to(&["/data/nested".to_owned()]).is_empty());
        let devs: Vec<(u32, u32)> = plan
            .restrict_to(&["/data".to_owned()])
            .targets()
            .iter()
            .map(|t| t.dev)
            .collect();
        assert_eq!(devs, [(8, 4)]);
        // The hidden superblock is still in the plan for a thaw to reach.
        assert!(plan.covers_device((8, 3)));
    }

    #[test]
    fn a_mount_over_a_directory_hides_the_mounts_beneath_it() {
        // The external review's third counterexample: A (8:2) at
        // /data/nested, then B (8:3) mounted at /data, a plain directory
        // until then, so A's parent is still the root mount; then C (8:4)
        // at the /data/nested B provides. /data/nested leads to C; A is
        // hidden by a mount over an intermediate directory, not over a
        // mount point, which following parent links alone misses.
        let plan = plan_from("directory_overmount.txt");
        assert_eq!(plan.visible_at("/data/nested"), Some((8, 4)));
        assert_eq!(plan.visible_at("/data"), Some((8, 3)));
        let restricted = plan.restrict_to(&["/data/nested".to_owned()]);
        let devs: Vec<(u32, u32)> = restricted.targets().iter().map(|t| t.dev).collect();
        assert_eq!(devs, [(8, 4)]);
        // A is in the plan (a thaw reaches it by its handle or its name
        // if it is ever visible again) but no requested name leads to it.
        assert!(plan.covers_device((8, 2)));
        let all = plan.restrict_to(&["/data".to_owned(), "/data/nested".to_owned()]);
        let devs: Vec<(u32, u32)> = all.targets().iter().map(|t| t.dev).collect();
        assert_eq!(devs, [(8, 3), (8, 4)]);
    }

    #[test]
    fn a_self_parented_root_is_the_root_of_the_namespace() {
        // proc_pid_mountinfo(5): the root of a mount namespace's tree may
        // carry its own id as its parent id; that is a valid table, not a
        // cycle. Such a root is walked from, and it is not its own child
        // at `/` (which would be a loop the bound ends in `None`).
        let plan = plan_from("self_parented_root.txt");
        assert_eq!(plan.visible_at("/data"), Some((8, 1)));
        assert_eq!(plan.visible_at("/"), Some((0, 1)));
        let devs: Vec<(u32, u32)> = plan
            .restrict_to(&["/data".to_owned()])
            .targets()
            .iter()
            .map(|t| t.dev)
            .collect();
        assert_eq!(devs, [(8, 1)]);
        // A parent that is neither absent nor the row itself is not a root:
        // an inconsistent table (every row under some other row) resolves
        // nothing rather than guessing.
        let text = "3 4 0:1 / / rw - rootfs rootfs rw\n4 3 8:1 / /data rw - ext4 /dev/vda1 rw\n";
        let plan = FreezePlan::build(&parse_mountinfo(text));
        assert_eq!(plan.visible_at("/data"), None);
        assert!(plan.restrict_to(&["/data".to_owned()]).is_empty());
    }

    #[test]
    fn resolution_costs_the_request_plus_the_table_not_their_product() {
        // The external review's amplification: 8 192 copies of a missing
        // name (a valid 41 KiB request) against 20 000 rows and 32 eligible
        // targets used to cost their product in comparisons. Each distinct
        // name is resolved once through an index built in one pass, so
        // the whole request costs the request plus the table.
        let mut text = String::from("27 1 8:1 / / rw - ext4 /dev/sda1 rw\n");
        for i in 0..20_000 {
            let (dev, fs, source) = if i % 625 == 0 {
                (format!("8:{}", 10 + i / 625), "ext4", "/dev/sdb1")
            } else {
                ("0:99".to_owned(), "tmpfs", "tmpfs")
            };
            text.push_str(&format!(
                "{} 27 {dev} / /m{i} rw - {fs} {source} rw\n",
                100 + i
            ));
        }
        let plan = FreezePlan::build(&parse_mountinfo(&text));
        assert_eq!(plan.len(), 33);
        let missing = vec!["/x".to_owned(); 8192];
        let started = std::time::Instant::now();
        assert!(plan.restrict_to(&missing).is_empty());
        let present = vec!["/m625".to_owned(); 8192];
        let restricted = plan.restrict_to(&present);
        assert_eq!(restricted.len(), 1);
        assert_eq!(restricted.targets()[0].dev, (8, 11));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
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
