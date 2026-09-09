//! `guest-get-fsinfo` (design §3; C-5).
//!
//! Lists every mounted filesystem (pseudo filesystems included, as
//! upstream does) with its source, type, mount point and sizes from
//! `statfs(2)`. A `statfs` failure omits the size fields of that entry
//! rather than dropping the entry or failing the command. `disk` is always
//! an empty array: qeminga does not walk sysfs for the backing devices.
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

/// Where sizes come from; production calls `statfs(2)`.
pub trait StatfsSource: Send + Sync {
    /// Sizes of the filesystem mounted at `mount_point`.
    fn statfs(&self, mount_point: &Path) -> Result<Statfs, Error>;
}

/// Production source over `nix::sys::statfs::statfs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemStatfs;

impl StatfsSource for SystemStatfs {
    fn statfs(&self, mount_point: &Path) -> Result<Statfs, Error> {
        let st = nix::sys::statfs::statfs(mount_point)
            .map_err(|errno| Error::Internal(format!("statfs failed: {errno}")))?;
        Ok(Statfs {
            blocks: st.blocks(),
            bfree: st.blocks_free(),
            bsize: u64::try_from(st.block_size()).unwrap_or(0),
        })
    }
}

/// One `GuestFilesystemInfo` (C-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilesystemInfo {
    /// Mount source (`/dev/sda1`, `tmpfs`, ...).
    pub name: String,
    /// Mount point, unescaped.
    pub mountpoint: String,
    /// Filesystem type.
    #[serde(rename = "type")]
    pub fs_type: String,
    /// `(blocks - bfree) * bsize`; omitted when `statfs` failed.
    #[serde(rename = "used-bytes", skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<u64>,
    /// `blocks * bsize`; omitted when `statfs` failed.
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
pub fn fs_info(mounts: &[MountEntry], statfs: &dyn StatfsSource) -> Vec<FilesystemInfo> {
    mounts
        .iter()
        .map(|m| {
            let sizes = sizes_are_queried(&m.fs_type)
                .then(|| statfs.statfs(&m.mount_point).ok())
                .flatten();
            FilesystemInfo {
                name: m.source.clone(),
                mountpoint: m.mount_point.to_string_lossy().into_owned(),
                fs_type: m.fs_type.clone(),
                used_bytes: sizes.map(|s| s.used_bytes()),
                total_bytes: sizes.map(|s| s.total_bytes()),
                disk: Vec::new(),
            }
        })
        .collect()
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
        let info = fs_info(&entries, statfs.as_ref());
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
        fn statfs(&self, mount_point: &Path) -> Result<Statfs, Error> {
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
        let info = fs_info(&mounts, &fake());
        let root = info.iter().find(|f| f.mountpoint == "/").unwrap();
        assert_eq!(root.name, "/dev/sda1");
        assert_eq!(root.fs_type, "ext4");
        assert_eq!(root.total_bytes, Some(1000 * 4096));
        assert_eq!(root.used_bytes, Some(750 * 4096));
        let home = info.iter().find(|f| f.mountpoint == "/home").unwrap();
        assert_eq!(home.name, "/dev/sda2");
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
        let info = fs_info(&mounts, &fake());
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
        let info = fs_info(&mounts, &fake());
        let nfs = info.iter().find(|f| f.fs_type == "nfs4").unwrap();
        assert_eq!(nfs.name, "filer:/export");
        assert_eq!(nfs.used_bytes, None);
        assert_eq!(nfs.total_bytes, None);
        let value = json!(nfs);
        assert!(value.get("used-bytes").is_none());
        assert!(value.get("total-bytes").is_none());
        assert!(!value.to_string().contains("null"));
        // Escaped mount points are reported unescaped.
        let mounts = parse_mountinfo(fixture("escaped_paths.txt"));
        let info = fs_info(&mounts, &fake());
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
        let info = fs_info(&mounts, &all);
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
    fn non_utf8_mount_points_are_reported_lossily_but_queried_byte_exact() {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::Mutex;
        struct Recording(Mutex<Vec<Vec<u8>>>);
        impl StatfsSource for Recording {
            fn statfs(&self, mount_point: &Path) -> Result<Statfs, Error> {
                self.0
                    .lock()
                    .unwrap()
                    .push(mount_point.as_os_str().as_bytes().to_vec());
                Err(Error::Internal("EIO".into()))
            }
        }
        let mounts = parse_mountinfo(fixture("escaped_paths.txt"));
        let recording = Recording(Mutex::new(Vec::new()));
        let info = fs_info(&mounts, &recording);
        assert_eq!(info.last().unwrap().mountpoint, "/mnt/caf\u{fffd}");
        let asked = recording.0.lock().unwrap();
        assert!(asked.contains(&b"/mnt/caf\xe9".to_vec()), "{asked:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_statfs_fails_the_command_instead_of_the_session() {
        struct Stuck(std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>);
        impl StatfsSource for Stuck {
            fn statfs(&self, _: &Path) -> Result<Statfs, Error> {
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
            fn statfs(&self, _: &Path) -> Result<Statfs, Error> {
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
    fn system_statfs_reads_root() {
        let st = SystemStatfs.statfs(Path::new("/")).unwrap();
        assert!(st.bsize > 0);
        assert!(st.blocks >= st.bfree);
        assert!(
            SystemStatfs
                .statfs(Path::new("/nonexistent/qeminga"))
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_mount_table_whose_reply_exceeds_the_bound_is_an_explicit_error() {
        // #43 §6: a table of tens of thousands of mounts (within the 32 MiB
        // read bound) would make a reply of megabytes; the command fails
        // naming the bound and truncates nothing. A large but ordinary
        // table is answered whole.
        let table = |n: usize| -> String {
            (0..n)
                .map(|i| {
                    format!(
                        "{} 1 0:{} / /var/lib/containers/overlay/{i:06}/merged rw,relatime - overlay overlay rw\n",
                        i + 10,
                        i + 100
                    )
                })
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
        assert_eq!(list[3]["name"], "/dev/sda1");
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
}
