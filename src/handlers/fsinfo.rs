//! `guest-get-fsinfo` (design §3, §4.5, §5.9; C-5, C-27).
//!
//! Lists every mounted filesystem (pseudo filesystems included, as
//! upstream does) with an opaque per-superblock identifier in `name`,
//! its type, mount point and sizes from `statfs(2)`. Raw mount sources
//! are never emitted because FUSE and network mount helpers can embed
//! credentials in the kernel-visible source field; aliases of the same
//! superblock share the same `fs-<n>` identifier so a snapshot
//! controller can still group them. A `statfs` failure omits the size
//! fields of that entry rather than dropping the entry or failing the
//! command. `disk` is always an empty array: qeminga does not walk sysfs
//! for the backing devices.
//!
//! Liveness (a deviation from upstream, recorded in `docs/tasks.md`):
//! `statfs` is not issued on network, FUSE and autofs mounts, whose server
//! or daemon may be gone (an uninterruptible `statfs` on a hard-mounted
//! share would block every later command), and `statfs(2)` on an autofs
//! trigger would mount it; those entries are listed without sizes. The
//! whole walk is also bounded by [`FSINFO_TIMEOUT`], and since a walk
//! that outlives its request cannot be cancelled (a started blocking
//! task runs to completion), the number of walks alive at once is bounded
//! by [`MAX_FSINFO_WALKS`] independently of the requests: past it the
//! command is refused at once rather than adding another stuck thread.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::dispatch::Context;
use crate::handlers::NoArgs;
use crate::mountinfo::{MountEntry, MountSource};
use crate::proto::{Error, Request, arguments};

/// The `statfs(2)` fields used for sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statfs {
    /// Total data blocks.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Block size in bytes.
    pub bsize: u64,
}

impl Statfs {
    /// `blocks * bsize`, saturating.
    pub fn total_bytes(&self) -> u64 {
        self.blocks.saturating_mul(self.bsize)
    }

    /// `(blocks - bfree) * bsize`, saturating.
    pub fn used_bytes(&self) -> u64 {
        self.blocks
            .saturating_sub(self.bfree)
            .saturating_mul(self.bsize)
    }
}

/// Where sizes come from; production opens the mount point, verifies its
/// superblock device against the inventory row, and calls `fstatfs(2)`.
pub trait StatfsSource: Send + Sync {
    /// Sizes of the filesystem mounted at `mount_point` when its descriptor
    /// still matches `expected_dev` (`(major, minor)` from the inventory row).
    fn statfs(&self, mount_point: &Path, expected_dev: (u32, u32)) -> Result<Statfs, Error>;
}

/// Production source over `open(2)` + `fstat(2)` + `fstatfs(2)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemStatfs;

impl StatfsSource for SystemStatfs {
    fn statfs(&self, mount_point: &Path, expected_dev: (u32, u32)) -> Result<Statfs, Error> {
        let fd = nix::fcntl::open(
            mount_point,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_CLOEXEC
                | nix::fcntl::OFlag::O_NOFOLLOW,
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|errno| Error::Internal(format!("statfs open failed: {errno}")))?;
        let st_dev = nix::sys::stat::fstat(&fd)
            .map_err(|errno| Error::Internal(format!("statfs fstat failed: {errno}")))?
            .st_dev;
        let found = (
            u32::try_from(nix::sys::stat::major(st_dev)).unwrap_or(u32::MAX),
            u32::try_from(nix::sys::stat::minor(st_dev)).unwrap_or(u32::MAX),
        );
        if found != expected_dev {
            return Err(Error::Internal("statfs device mismatch".into()));
        }
        let st = nix::sys::statfs::fstatfs(&fd)
            .map_err(|errno| Error::Internal(format!("fstatfs failed: {errno}")))?;
        Ok(Statfs {
            blocks: st.blocks(),
            bfree: st.blocks_free(),
            bsize: u64::try_from(st.block_size()).unwrap_or(0),
        })
    }
}

/// One `GuestFilesystemInfo` (C-5, C-27).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilesystemInfo {
    /// Opaque per-superblock identifier (`fs-1`, `fs-2`, …), shared by all
    /// visible valid-UTF-8 aliases of the same superblock within a single
    /// reply; never the raw mount source.
    pub name: String,
    /// Mount point, unescaped valid UTF-8 that round-trips byte-exact to its
    /// visible mount row.
    pub mountpoint: String,
    /// Filesystem type.
    #[serde(rename = "type")]
    pub fs_type: String,
    /// `(blocks - bfree) * bsize`; omitted when `statfs` failed or the live
    /// mount identity changed.
    #[serde(rename = "used-bytes", skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<u64>,
    /// `blocks * bsize`; omitted when `statfs` failed or the live mount
    /// identity changed.
    #[serde(rename = "total-bytes", skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// Always empty.
    pub disk: Vec<Value>,
}

/// Bound on the whole `statfs` walk; past it the command fails rather
/// than holding the session (the blocking thread is abandoned).
pub const FSINFO_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the walks alive at once, whatever became of the requests that
/// started them: a request past it is refused at once instead of adding a
/// blocking thread to the ones earlier, abandoned walks still hold.
pub const MAX_FSINFO_WALKS: usize = 2;

/// Bound on the encoded reply (§5.10): a mount table too large to answer
/// within it is an explicit error, never a truncated list (#43 §6). One
/// MiB is several thousand entries, well beyond any table the freeze
/// plan is meant for, while the 32 MiB the table read allows
/// (`MOUNTINFO_MAX_BYTES`) could otherwise become a reply of that order.
pub const MAX_FSINFO_REPLY_BYTES: usize = 1024 * 1024;

/// Filesystem types whose `statfs` may block indefinitely (network
/// shares, FUSE daemons) or have side effects (autofs triggers). Their
/// entries are reported without sizes.
pub fn sizes_are_queried(fs_type: &str) -> bool {
    const SKIPPED: [&str; 14] = [
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "ncpfs",
        "afs",
        "ceph",
        "glusterfs",
        "9p",
        "coda",
        "lustre",
        "autofs",
        "fuseblk",
    ];
    !(SKIPPED.contains(&fs_type) || fs_type.starts_with("fuse"))
}

/// Builds the reply for a mount table.
///
/// Only mounts that are both visible at their own mount point in the mount
/// tree ([`crate::freeze_plan::visible_mounts`]) and valid UTF-8 are emitted,
/// so every advertised `mountpoint` round-trips byte-exact to its row in
/// `guest-fsfreeze-freeze-list` and never collides via lossy `U+FFFD`
/// substitution. A filesystem mounted at a non-UTF-8 path with a visible
/// valid-UTF-8 bind alias is advertised via that alias; one with no visible
/// valid-UTF-8 mount point is omitted (full-guest `guest-fsfreeze-freeze`
/// remains byte-exact). Size queries verify the opened descriptor's device
/// against the inventory row before calling `fstatfs(2)` and omit sizes if
/// the mount identity changed.
///
/// Each distinct advertised superblock `(major, minor)` gets an opaque
/// `fs-<n>` identifier in order of first appearance, shared by all of its
/// visible valid-UTF-8 aliases. The identifier is valid only within a single
/// reply (rebuilt on each call); controllers group aliases from one reply and
/// use provisioned mount paths across requests. Raw mount sources and device
/// numbers are never placed in the reply (design §4.5, §5.9, AC27).
pub fn fs_info(
    mounts: &[MountEntry],
    statfs: &dyn StatfsSource,
) -> Result<Vec<FilesystemInfo>, Error> {
    let visible = crate::freeze_plan::visible_mounts(mounts)
        .map_err(|err| Error::Internal(format!("fsinfo: {err}")))?;
    let mut superblocks: HashMap<(u32, u32), usize> = HashMap::new();
    Ok(visible
        .into_iter()
        .filter_map(|m| {
            // Only advertise rows whose mount point is valid UTF-8 so the
            // JSON wire spelling round-trips byte-exact to this row in
            // `FreezePlan::restrict_to` without lossy U+FFFD collisions.
            let mountpoint = m.mount_point.to_str()?;
            let next = superblocks.len() + 1;
            let id = *superblocks.entry(m.dev()).or_insert(next);
            let sizes = sizes_are_queried(&m.fs_type)
                .then(|| statfs.statfs(&m.mount_point, m.dev()).ok())
                .flatten();
            Some(FilesystemInfo {
                name: format!("fs-{id}"),
                mountpoint: mountpoint.to_owned(),
                fs_type: m.fs_type.clone(),
                used_bytes: sizes.map(|s| s.used_bytes()),
                total_bytes: sizes.map(|s| s.total_bytes()),
                disk: Vec::new(),
            })
        })
        .collect())
}

/// `guest-get-fsinfo` handler. `statfs` may block, so the whole walk runs
/// on the blocking pool under [`FSINFO_TIMEOUT`]; a walk that does not
/// finish in time fails the command and the session moves on.
pub async fn handle(ctx: &Context, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    // The slot is taken before the walk is spawned and belongs to the walk
    // afterwards: a request that gives up leaves its walk holding the
    // slot until the closure returns, so abandoned walks never pile up on
    // the blocking pool that freeze and thaw need (`MAX_FSINFO_WALKS`).
    let slot = Arc::clone(&ctx.fsinfo_walks)
        .try_acquire_owned()
        .map_err(|_| {
            Error::Internal(format!(
                "fsinfo: {MAX_FSINFO_WALKS} earlier walks are still running; retry later"
            ))
        })?;
    let mounts: Arc<dyn MountSource> = Arc::clone(&ctx.mounts);
    let statfs: Arc<dyn StatfsSource> = Arc::clone(&ctx.statfs);
    let walk = tokio::task::spawn_blocking(move || {
        let _walk = slot;
        let entries = mounts.mounts()?;
        let info = fs_info(&entries, statfs.as_ref())?;
        crate::handlers::bounded_reply("fsinfo", &info, MAX_FSINFO_REPLY_BYTES)
    });
    let info = tokio::time::timeout(FSINFO_TIMEOUT, walk)
        .await
        .map_err(|_| {
            Error::Internal(format!(
                "fsinfo did not complete within {} s",
                FSINFO_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|err| Error::Internal(format!("fsinfo task failed: {err}")))??;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::{StaticMounts, parse_mountinfo};
    use serde_json::json;
    use std::collections::HashMap;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mountinfo")
                .join(name),
        )
        .unwrap()
    }

    struct FakeStatfs(HashMap<String, Statfs>);

    impl StatfsSource for FakeStatfs {
        fn statfs(&self, mount_point: &Path, _expected_dev: (u32, u32)) -> Result<Statfs, Error> {
            self.0
                .get(mount_point.to_string_lossy().as_ref())
                .copied()
                .ok_or_else(|| Error::Internal("EIO".into()))
        }
    }

    fn fake() -> FakeStatfs {
        FakeStatfs(HashMap::from([
            (
                "/".to_owned(),
                Statfs {
                    blocks: 1000,
                    bfree: 250,
                    bsize: 4096,
                },
            ),
            (
                "/home".to_owned(),
                Statfs {
                    blocks: 10,
                    bfree: 10,
                    bsize: 512,
                },
            ),
            (
                "/proc".to_owned(),
                Statfs {
                    blocks: 0,
                    bfree: 0,
                    bsize: 4096,
                },
            ),
        ]))
    }

    #[test]
    fn fsinfo_reports_name_type_mountpoint_and_sizes() {
        let mounts = parse_mountinfo(fixture("simple.txt"));
        let info = fs_info(&mounts, &fake()).unwrap();
        let root = info.iter().find(|f| f.mountpoint == "/").unwrap();
        assert_eq!(root.name, "fs-4");
        assert_eq!(root.fs_type, "ext4");
        assert_eq!(root.total_bytes, Some(1000 * 4096));
        assert_eq!(root.used_bytes, Some(750 * 4096));
        let home = info.iter().find(|f| f.mountpoint == "/home").unwrap();
        assert_eq!(home.name, "fs-5");
        assert_eq!(home.fs_type, "xfs");
        assert_eq!(home.total_bytes, Some(5120));
        assert_eq!(home.used_bytes, Some(0));
        let value = json!(root);
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "disk",
                "mountpoint",
                "name",
                "total-bytes",
                "type",
                "used-bytes"
            ]
        );
    }

    #[test]
    fn fsinfo_includes_pseudo_filesystems_and_disk_is_empty_array() {
        let mounts = parse_mountinfo(fixture("tmpfs_and_nfs.txt"));
        let info = fs_info(&mounts, &fake()).unwrap();
        assert_eq!(info.len(), mounts.len());
        let types: Vec<&str> = info.iter().map(|f| f.fs_type.as_str()).collect();
        assert!(types.contains(&"tmpfs"));
        assert!(types.contains(&"cgroup2"));
        assert!(types.contains(&"nfs4"));
        assert!(types.contains(&"overlay"));
        for entry in &info {
            assert!(entry.disk.is_empty());
            assert_eq!(json!(entry)["disk"], json!([]));
        }
        // Order is mount order.
        assert_eq!(info[0].mountpoint, "/");
        assert_eq!(info[1].mountpoint, "/run");
    }

    #[test]
    fn fsinfo_statfs_failure_omits_size_fields_not_the_entry() {
        let mounts = parse_mountinfo(fixture("tmpfs_and_nfs.txt"));
        let info = fs_info(&mounts, &fake()).unwrap();
        let nfs = info.iter().find(|f| f.fs_type == "nfs4").unwrap();
        assert_eq!(nfs.name, "fs-5");
        assert_eq!(nfs.used_bytes, None);
        assert_eq!(nfs.total_bytes, None);
        let value = json!(nfs);
        assert!(value.get("used-bytes").is_none());
        assert!(value.get("total-bytes").is_none());
        assert!(!value.to_string().contains("null"));
        // Escaped mount points are reported unescaped.
        let mounts = parse_mountinfo(fixture("escaped_paths.txt"));
        let info = fs_info(&mounts, &fake()).unwrap();
        assert_eq!(info[1].mountpoint, "/mnt/with space");
    }

    #[test]
    fn fsinfo_does_not_statfs_remote_fuse_or_autofs_mounts() {
        // Sizes are offered for every mount, yet the network, FUSE and 9p
        // entries are listed without them: their statfs is never issued.
        let mounts = parse_mountinfo(fixture("tmpfs_and_nfs.txt"));
        let sizes = Statfs {
            blocks: 1,
            bfree: 0,
            bsize: 4096,
        };
        let all = FakeStatfs(
            mounts
                .iter()
                .map(|m| (m.mount_point.to_string_lossy().into_owned(), sizes))
                .collect(),
        );
        let info = fs_info(&mounts, &all).unwrap();
        for entry in &info {
            let queried = entry.total_bytes.is_some();
            assert_eq!(
                queried,
                sizes_are_queried(&entry.fs_type),
                "{} ({})",
                entry.mountpoint,
                entry.fs_type
            );
        }
        let skipped: Vec<&str> = info
            .iter()
            .filter(|f| f.total_bytes.is_none())
            .map(|f| f.fs_type.as_str())
            .collect();
        assert_eq!(skipped, ["nfs4", "cifs", "fuse.sshfs", "9p"]);
        assert!(!sizes_are_queried("autofs"));
        assert!(!sizes_are_queried("fuseblk"));
        assert!(sizes_are_queried("ext4"));
        assert!(sizes_are_queried("virtiofs"));
    }

    #[test]
    fn non_utf8_mount_points_are_omitted_and_prefer_utf8_alias_without_fffd_collision() {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::Mutex;
        struct Recording(Mutex<Vec<(Vec<u8>, (u32, u32))>>);
        impl StatfsSource for Recording {
            fn statfs(
                &self,
                mount_point: &Path,
                expected_dev: (u32, u32),
            ) -> Result<Statfs, Error> {
                self.0
                    .lock()
                    .unwrap()
                    .push((mount_point.as_os_str().as_bytes().to_vec(), expected_dev));
                Err(Error::Internal("EIO".into()))
            }
        }
        // escaped_paths.txt: /mnt/caf\351 (8:9) has no valid UTF-8 alias and
        // must be omitted rather than emitted lossily with U+FFFD, while valid
        // escaped UTF-8 paths remain listed.
        let mounts = parse_mountinfo(fixture("escaped_paths.txt"));
        let recording = Recording(Mutex::new(Vec::new()));
        let info = fs_info(&mounts, &recording).unwrap();
        let paths: Vec<&str> = info.iter().map(|f| f.mountpoint.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/",
                "/mnt/with space",
                "/mnt/tab\there",
                "/mnt/back\\slash",
                "/mnt/nl\ninside",
            ]
        );
        let asked = recording.0.lock().unwrap();
        assert!(
            !asked.iter().any(|(p, _)| p == b"/mnt/caf\xe9"),
            "omitted non-UTF-8 mount must not be statfs'd: {asked:?}"
        );
        drop(asked);

        // Collision table: 8:9 is mounted at raw `/mnt/caf\351` AND bound at
        // valid UTF-8 `/mnt/cafe-alias`; 8:10 is mounted at literal UTF-8
        // `/mnt/caf\u{fffd}`; 8:11 is mounted only at raw `/mnt/raw\377`.
        // Discovery must prefer `/mnt/cafe-alias` for 8:9, advertise
        // `/mnt/caf\u{fffd}` once under 8:10's distinct `fs-N`, and omit 8:11.
        let table = concat!(
            "27 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
            "54 27 8:9 / /mnt/caf\\351 rw,relatime - ext4 /dev/sda9 rw\n",
            "55 27 8:9 / /mnt/cafe-alias rw,relatime - ext4 /dev/sda9 rw\n",
            "56 27 8:10 / /mnt/caf\u{fffd} rw,relatime - ext4 /dev/sda10 rw\n",
            "57 27 8:11 / /mnt/raw\\377 rw,relatime - ext4 /dev/sda11 rw\n",
        );
        let collision_mounts = parse_mountinfo(table);
        let recording = Recording(Mutex::new(Vec::new()));
        let info = fs_info(&collision_mounts, &recording).unwrap();
        let paths: Vec<&str> = info.iter().map(|f| f.mountpoint.as_str()).collect();
        assert_eq!(paths, ["/", "/mnt/cafe-alias", "/mnt/caf\u{fffd}"]);
        assert_eq!(
            info.iter()
                .filter(|f| f.mountpoint == "/mnt/caf\u{fffd}")
                .count(),
            1,
            "literal U+FFFD mountpoint must not collide with raw non-UTF-8 row: {info:?}"
        );
        let alias = info
            .iter()
            .find(|f| f.mountpoint == "/mnt/cafe-alias")
            .unwrap();
        let literal_fffd = info
            .iter()
            .find(|f| f.mountpoint == "/mnt/caf\u{fffd}")
            .unwrap();
        assert_ne!(alias.name, literal_fffd.name);
        let asked = recording.0.lock().unwrap();
        assert_eq!(
            *asked,
            [
                (b"/".to_vec(), (8, 1)),
                (b"/mnt/cafe-alias".to_vec(), (8, 9)),
                ("/mnt/caf\u{fffd}".as_bytes().to_vec(), (8, 10)),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_statfs_fails_the_command_instead_of_the_session() {
        struct Stuck(std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>);
        impl StatfsSource for Stuck {
            fn statfs(&self, _: &Path, _: (u32, u32)) -> Result<Statfs, Error> {
                // Blocks until the test drops the sender (a D-state statfs).
                let rx = self.0.lock().unwrap().take();
                if let Some(rx) = rx {
                    let _ = rx.recv();
                }
                Err(Error::Internal("EIO".into()))
            }
        }
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let ctx = Arc::new(
            Context::for_tests()
                .with_mounts(Arc::new(StaticMounts(fixture("simple.txt"))))
                .with_statfs(Arc::new(Stuck(std::sync::Mutex::new(Some(rx))))),
        );
        let req = crate::proto::parse_request(br#"{"execute":"guest-get-fsinfo"}"#).unwrap();
        // Paused time does not advance while a blocking task runs, so the
        // handler is started, allowed to arm its timer, and the clock is
        // moved past the bound by hand.
        let task = tokio::spawn({
            let ctx = Arc::clone(&ctx);
            async move { handle(&ctx, &req).await }
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(FSINFO_TIMEOUT + Duration::from_secs(1)).await;
        let err = task.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("did not complete"), "{err}");
        drop(tx);
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_walks_are_bounded_independently_of_request_timeouts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Every walk blocks in its first `statfs` until the test releases
        // the gate (a hard-mounted share whose server is gone).
        struct Gate {
            released: std::sync::Mutex<bool>,
            cv: std::sync::Condvar,
            walks: AtomicUsize,
        }
        impl StatfsSource for Gate {
            fn statfs(&self, _: &Path, _: (u32, u32)) -> Result<Statfs, Error> {
                let mut released = self.released.lock().unwrap();
                if !*released {
                    self.walks.fetch_add(1, Ordering::SeqCst);
                }
                while !*released {
                    released = self.cv.wait(released).unwrap();
                }
                Err(Error::Internal("EIO".into()))
            }
        }
        let gate = Arc::new(Gate {
            released: std::sync::Mutex::new(false),
            cv: std::sync::Condvar::new(),
            walks: AtomicUsize::new(0),
        });
        let ctx = Arc::new(
            Context::for_tests()
                .with_mounts(Arc::new(StaticMounts(fixture("simple.txt"))))
                .with_statfs(gate.clone()),
        );
        let req = crate::proto::parse_request(br#"{"execute":"guest-get-fsinfo"}"#).unwrap();
        // The first MAX_FSINFO_WALKS requests each time out and abandon a
        // stuck walk (the clock is moved by hand, as above).
        for _ in 0..MAX_FSINFO_WALKS {
            let task = tokio::spawn({
                let ctx = Arc::clone(&ctx);
                let req =
                    crate::proto::parse_request(br#"{"execute":"guest-get-fsinfo"}"#).unwrap();
                async move { handle(&ctx, &req).await }
            });
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            tokio::time::advance(FSINFO_TIMEOUT + Duration::from_secs(1)).await;
            let err = task.await.unwrap().unwrap_err();
            assert!(err.to_string().contains("did not complete"), "{err}");
        }
        // The bound is on the walks, not on the waits: the next request is
        // refused before any blocking task is spawned, so the abandoned
        // walks never outnumber the bound however many requests time out.
        let err = handle(&ctx, &req).await.unwrap_err();
        assert!(err.to_string().contains("still running"), "{err}");
        assert!(gate.walks.load(Ordering::SeqCst) <= MAX_FSINFO_WALKS);
        // Releasing the walks frees their slots: the permit is owned by
        // the walk (dropped when its closure returns), never by the
        // request that gave up on it.
        *gate.released.lock().unwrap() = true;
        gate.cv.notify_all();
        let mut result = handle(&ctx, &req).await;
        for _ in 0..2000 {
            if result.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
            tokio::task::yield_now().await;
            result = handle(&ctx, &req).await;
        }
        let list = result.unwrap();
        assert_eq!(
            list.as_array().unwrap().len(),
            5,
            "sizes omitted, entries listed"
        );
    }

    #[test]
    fn sizes_saturate_instead_of_overflowing() {
        let st = Statfs {
            blocks: u64::MAX,
            bfree: 0,
            bsize: 4096,
        };
        assert_eq!(st.total_bytes(), u64::MAX);
        assert_eq!(st.used_bytes(), u64::MAX);
        let st = Statfs {
            blocks: 5,
            bfree: 10,
            bsize: 4096,
        };
        assert_eq!(st.used_bytes(), 0, "bfree > blocks must not underflow");
    }

    #[test]
    fn system_statfs_reads_root_and_rejects_mismatched_device() {
        let meta = nix::sys::stat::stat(Path::new("/")).unwrap();
        let root_dev = (
            u32::try_from(nix::sys::stat::major(meta.st_dev)).unwrap(),
            u32::try_from(nix::sys::stat::minor(meta.st_dev)).unwrap(),
        );
        let st = SystemStatfs.statfs(Path::new("/"), root_dev).unwrap();
        assert!(st.bsize > 0);
        assert!(st.blocks >= st.bfree);
        // A racing mount replacement whose st_dev no longer matches the
        // inventory row must be rejected before fstatfs.
        let wrong_dev = (root_dev.0.wrapping_add(1), root_dev.1);
        assert!(
            SystemStatfs.statfs(Path::new("/"), wrong_dev).is_err(),
            "device mismatch must omit sizes"
        );
        assert!(
            SystemStatfs
                .statfs(Path::new("/nonexistent/qeminga"), (0, 0))
                .is_err()
        );
    }

    #[test]
    fn fsinfo_omits_sizes_when_statfs_detects_device_mismatch() {
        struct VerifiedStatfs(HashMap<String, ((u32, u32), Statfs)>);
        impl StatfsSource for VerifiedStatfs {
            fn statfs(
                &self,
                mount_point: &Path,
                expected_dev: (u32, u32),
            ) -> Result<Statfs, Error> {
                let (live_dev, st) = self
                    .0
                    .get(mount_point.to_str().unwrap())
                    .copied()
                    .ok_or_else(|| Error::Internal("ENOENT".into()))?;
                if live_dev != expected_dev {
                    return Err(Error::Internal("statfs device mismatch".into()));
                }
                Ok(st)
            }
        }
        let table = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
        );
        let mounts = parse_mountinfo(table);
        let statfs = VerifiedStatfs(HashMap::from([
            (
                "/".to_owned(),
                (
                    (8, 1),
                    Statfs {
                        blocks: 100,
                        bfree: 40,
                        bsize: 4096,
                    },
                ),
            ),
            // Simulate /data replaced live by a different filesystem (e.g. FUSE 0:99)
            // after mountinfo was read.
            (
                "/data".to_owned(),
                (
                    (0, 99),
                    Statfs {
                        blocks: 9999,
                        bfree: 0,
                        bsize: 4096,
                    },
                ),
            ),
        ]));
        let info = fs_info(&mounts, &statfs).unwrap();
        let root = info.iter().find(|f| f.mountpoint == "/").unwrap();
        let data = info.iter().find(|f| f.mountpoint == "/data").unwrap();
        assert_eq!(root.total_bytes, Some(100 * 4096));
        assert_eq!(data.total_bytes, None);
        assert_eq!(data.used_bytes, None);
    }

    #[tokio::test]
    async fn a_mount_table_whose_reply_exceeds_the_bound_is_an_explicit_error() {
        // #43 §6: a table of tens of thousands of mounts (within the 32 MiB
        // read bound) would make a reply of megabytes; the command fails
        // naming the bound and truncates nothing. A large but ordinary
        // table is answered whole.
        let table = |n: usize| -> String {
            std::iter::once("1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n".to_owned())
                .chain((0..n - 1).map(|i| {
                    format!(
                        "{} 1 0:{} / /var/lib/containers/overlay/{i:06}/merged rw,relatime - overlay overlay rw\n",
                        i + 10,
                        i + 100
                    )
                }))
                .collect()
        };
        let ctx = Context::for_tests()
            .with_mounts(Arc::new(StaticMounts(table(20_000))))
            .with_statfs(Arc::new(fake()));
        let req = crate::proto::parse_request(br#"{"execute":"guest-get-fsinfo"}"#).unwrap();
        let err = handle(&ctx, &req).await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("over the 1048576 byte bound") && text.contains("not truncated"),
            "{text}"
        );
        let ctx = Context::for_tests()
            .with_mounts(Arc::new(StaticMounts(table(2_000))))
            .with_statfs(Arc::new(fake()));
        let value = handle(&ctx, &req).await.unwrap();
        assert_eq!(value.as_array().unwrap().len(), 2_000, "answered whole");
        assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_FSINFO_REPLY_BYTES);
    }

    #[tokio::test]
    async fn handler_uses_context_sources_and_rejects_arguments() {
        let ctx = Context::for_tests()
            .with_mounts(Arc::new(StaticMounts(fixture("simple.txt"))))
            .with_statfs(Arc::new(fake()));
        let req = crate::proto::parse_request(br#"{"execute":"guest-get-fsinfo"}"#).unwrap();
        let value = handle(&ctx, &req).await.unwrap();
        let list = value.as_array().unwrap();
        assert_eq!(list.len(), 5);
        assert_eq!(list[3]["name"], "fs-4");
        assert_eq!(list[3]["type"], "ext4");
        assert_eq!(list[3]["total-bytes"], 1000 * 4096);
        let req =
            crate::proto::parse_request(br#"{"execute":"guest-get-fsinfo","arguments":{"a":1}}"#)
                .unwrap();
        assert!(matches!(
            handle(&ctx, &req).await,
            Err(Error::InvalidArguments(_))
        ));
    }

    #[test]
    fn fsinfo_uses_opaque_superblock_ids_and_never_discloses_mount_sources() {
        // CVM Blocker 1 (#53, AC27): FUSE/network mount helpers can put live
        // credentials in mountinfo's source field, and local device names or
        // major:minor pairs must not leak either. Aliases of one superblock
        // share one opaque identifier; distinct superblocks get distinct ones.
        let table = concat!(
            "10 1 8:1 / / rw,relatime - ext4 /dev/mapper/tenant-alpha-root rw\n",
            "11 10 8:1 /srv/www /var/www rw,relatime - ext4 /dev/mapper/tenant-alpha-root rw\n",
            "12 10 8:2 / /data rw,relatime - xfs /dev/nvme0n1p2 rw\n",
            "13 10 8:2 /exports /srv/exports rw,relatime - xfs /dev/nvme0n1p2 rw\n",
            "14 10 0:41 / /mnt/ftp rw,nosuid - fuse.curlftpfs curlftpfs#ftp://alice:super-secret-pass@ftp.internal/vault rw\n",
            "15 10 0:42 / /mnt/share rw - cifs //storage.internal/tenant-secret rw\n",
            "16 10 0:43 / /mnt/nfs rw - nfs4 filer.internal:/exports/tenant rw\n",
            "17 10 0:44 / /run rw - tmpfs tmpfs-custom-label-a rw\n",
            "18 10 0:45 / /tmp rw - tmpfs tmpfs-custom-label-b rw\n",
        );
        let mounts = parse_mountinfo(table);
        let info = fs_info(&mounts, &fake()).unwrap();
        assert_eq!(info.len(), 9);
        // Aliases of the same superblock share one opaque identifier.
        assert_eq!(info[0].name, info[1].name, "bind aliases of 8:1 share name");
        assert_eq!(info[2].name, info[3].name, "bind aliases of 8:2 share name");
        // Distinct superblocks — including two tmpfs mounts — get distinct ids.
        assert_ne!(info[0].name, info[2].name);
        assert_ne!(info[7].name, info[8].name);
        // Every name is an opaque `fs-<n>` identifier and never discloses raw
        // mount sources, credentials, hostnames, device paths or major:minor.
        let serialized = serde_json::to_string(&info).unwrap();
        for forbidden in [
            "tenant-alpha-root",
            "/dev/mapper",
            "/dev/nvme0n1p2",
            "curlftpfs#",
            "alice",
            "super-secret-pass",
            "ftp.internal",
            "vault",
            "storage.internal",
            "tenant-secret",
            "filer.internal",
            "tmpfs-custom-label",
            "8:1",
            "8:2",
            "0:41",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "fsinfo reply must not disclose {forbidden:?}: {serialized}"
            );
        }
        for entry in &info {
            let suffix = entry
                .name
                .strip_prefix("fs-")
                .unwrap_or_else(|| panic!("expected opaque fs-<n> name, got {:?}", entry.name));
            assert!(suffix.parse::<usize>().is_ok(), "{:?}", entry.name);
        }
    }

    #[test]
    fn fsinfo_omits_covered_mounts_and_never_attributes_covering_sizes() {
        // hidden_mount.txt: 8:2 is mounted at /data (covered by 8:3 at /data)
        // and reachable at /data-alias. Only the visible mounts (/, /data-alias,
        // /data on 8:3) may be advertised; /data must appear once with 8:3's
        // sizes, never under 8:2's opaque id.
        let mounts = parse_mountinfo(fixture("hidden_mount.txt"));
        let sizes = FakeStatfs(HashMap::from([
            (
                "/".to_owned(),
                Statfs {
                    blocks: 100,
                    bfree: 50,
                    bsize: 4096,
                },
            ),
            (
                "/data".to_owned(),
                Statfs {
                    blocks: 999,
                    bfree: 0,
                    bsize: 4096,
                },
            ),
            (
                "/data-alias".to_owned(),
                Statfs {
                    blocks: 200,
                    bfree: 100,
                    bsize: 4096,
                },
            ),
        ]));
        let info = fs_info(&mounts, &sizes).unwrap();
        let paths: Vec<&str> = info.iter().map(|f| f.mountpoint.as_str()).collect();
        assert_eq!(paths, ["/", "/data-alias", "/data"]);
        let alias = info.iter().find(|f| f.mountpoint == "/data-alias").unwrap();
        let data = info.iter().find(|f| f.mountpoint == "/data").unwrap();
        assert_ne!(
            alias.name, data.name,
            "8:2 and 8:3 have distinct opaque ids"
        );
        assert_eq!(alias.total_bytes, Some(200 * 4096));
        assert_eq!(data.total_bytes, Some(999 * 4096));
        assert_eq!(
            info.iter().filter(|f| f.mountpoint == "/data").count(),
            1,
            "covered /data must not be advertised"
        );

        // moved_mount.txt: 8:5 moved over 8:2 at /data; 8:2 remains visible at /b-alias.
        let moved = fs_info(&parse_mountinfo(fixture("moved_mount.txt")), &fake()).unwrap();
        let moved_paths: Vec<(&str, &str)> = moved
            .iter()
            .map(|f| (f.mountpoint.as_str(), f.fs_type.as_str()))
            .collect();
        assert_eq!(
            moved_paths,
            [("/", "ext4"), ("/data", "xfs"), ("/b-alias", "ext4")]
        );

        // directory_overmount.txt: 8:2 at /data/nested is hidden under 8:3 at /data;
        // 8:4 (xfs) is mounted at /data/nested under 8:3.
        let dir_over = fs_info(
            &parse_mountinfo(fixture("directory_overmount.txt")),
            &fake(),
        )
        .unwrap();
        let dir_paths: Vec<(&str, &str)> = dir_over
            .iter()
            .map(|f| (f.mountpoint.as_str(), f.fs_type.as_str()))
            .collect();
        assert_eq!(
            dir_paths,
            [("/", "ext4"), ("/data", "ext4"), ("/data/nested", "xfs")]
        );

        // hidden_nested.txt: 8:2 at /data and its child 8:3 at /data/nested are
        // both hidden by 8:4 (xfs) mounted at /data.
        let nested = fs_info(&parse_mountinfo(fixture("hidden_nested.txt")), &fake()).unwrap();
        let nested_paths: Vec<(&str, &str)> = nested
            .iter()
            .map(|f| (f.mountpoint.as_str(), f.fs_type.as_str()))
            .collect();
        assert_eq!(nested_paths, [("/", "ext4"), ("/data", "xfs")]);
    }

    #[tokio::test]
    async fn fsinfo_errors_on_nonempty_mount_table_without_root_and_allows_empty_table() {
        let req = crate::proto::parse_request(br#"{"execute":"guest-get-fsinfo"}"#).unwrap();
        // Empty mount table returns empty JSON array.
        let empty_ctx = Context::for_tests()
            .with_mounts(Arc::new(StaticMounts(String::new())))
            .with_statfs(Arc::new(fake()));
        assert_eq!(handle(&empty_ctx, &req).await.unwrap(), json!([]));

        // Chroot-style table with one child mount and omitted `/` parent must
        // fail with a fixed error rather than silently returning `[]`.
        let rootless_ctx = Context::for_tests()
            .with_mounts(Arc::new(StaticMounts(
                "40 27 8:2 / /data rw,relatime - ext4 /dev/sdb1 rw\n".to_owned(),
            )))
            .with_statfs(Arc::new(fake()));
        let err = handle(&rootless_ctx, &req).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "fsinfo: mount table has no recognizable root mount"
        );
    }
}
