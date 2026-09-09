//! Privileged end-to-end tests (T5.2): the real binary, the real kernel,
//! loop-mounted filesystems from `scripts/ci/mk-loop-fs.sh`. All are
//! `#[ignore]`d and named `privileged_*`; run serially as root:
//!
//! ```sh
//! eval "$(sudo scripts/ci/mk-loop-fs.sh setup)"
//! sudo -E cargo test --features seccomp,suspend_ram,test-fakes --locked -- --ignored --test-threads=1 privileged_
//! ```
//!
//! (`--all-features` would include `seccomp-log`, a build whose filter only
//! logs; the enforced feature set is the one CI gates on, AC15.)
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use e2e::{Agent, SpawnOptions};
use serde_json::{Value, json};

fn ext4_mount() -> String {
    std::env::var("QEMINGA_TEST_EXT4_MOUNT")
        .expect("QEMINGA_TEST_EXT4_MOUNT: run scripts/ci/mk-loop-fs.sh setup")
}

/// `(major, minor)` of the filesystem `path` currently leads to.
fn dev_of(path: &std::path::Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(path).unwrap().dev();
    (
        u32::try_from(nix::sys::stat::major(dev)).unwrap(),
        u32::try_from(nix::sys::stat::minor(dev)).unwrap(),
    )
}

/// A verified handle on whatever filesystem `path` leads to now (the
/// test's own view, with `CAP_SYS_ADMIN`).
fn handle(path: &std::path::Path) -> qeminga::kernel::Mount {
    use qeminga::kernel::KernelOps;
    qeminga::kernel::LinuxKernel
        .open_mount(path, dev_of(path))
        .unwrap_or_else(|err| panic!("open {}: {err}", path.display()))
}

/// Thaws the named mounts when dropped, whatever happened in between: a
/// failed assertion between freeze and thaw would otherwise leave the
/// loop filesystem frozen (the daemon is SIGKILLed by `Agent::drop`,
/// taking its watchdog with it), so every later test would get EBUSY and
/// a write to the mount would block in D state. `FITHAW` is repeated
/// until it fails (nested freezes), bounded.
struct ThawGuard(Vec<String>);

impl ThawGuard {
    fn new(mounts: &[String]) -> Self {
        ThawGuard(mounts.to_vec())
    }
}

impl Drop for ThawGuard {
    fn drop(&mut self) {
        use qeminga::kernel::KernelOps;
        for mount in &self.0 {
            let path = std::path::Path::new(mount);
            let Ok(handle) = qeminga::kernel::LinuxKernel.open_mount(path, dev_of(path)) else {
                continue;
            };
            for _ in 0..64 {
                if qeminga::kernel::LinuxKernel.fithaw(&handle).is_err() {
                    break;
                }
                eprintln!("ThawGuard: thawed {mount} left frozen by the test");
            }
        }
    }
}

/// The real kernel, and the default (enforced) hardening whenever this
/// build can provide it: the enforced privileged run therefore proves
/// the production profile end to end, while the `seccomp-log`
/// compatibility run opts out, as a development host must (#43 §4).
fn real_kernel(agent_extra: &str) -> SpawnOptions {
    SpawnOptions {
        fake_kernel: false,
        agent_extra: agent_extra.to_owned(),
        enforce_hardening: qeminga::daemon::seccomp_mode() == "enforce",
        ..SpawnOptions::default()
    }
}

fn freeze_list(agent: &mut Agent, mounts: &[String]) -> Value {
    let req =
        json!({"execute": "guest-fsfreeze-freeze-list", "arguments": {"mountpoints": mounts}});
    agent.request(&req.to_string())
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_freeze_sigkill_restart_recovery_thaw() {
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let mut agent = Agent::spawn_with(real_kernel(""));
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert!(agent.state_dir().join("frozen").exists());
    // Crash.
    let dir = agent.kill();
    assert!(
        dir.path().join("frozen").exists(),
        "marker survives SIGKILL"
    );
    // Restart with the same configuration and state directory.
    let mut agent = Agent::spawn_with(SpawnOptions {
        state_dir: Some(dir),
        ..real_kernel("")
    });
    assert_eq!(
        agent.execute("guest-fsfreeze-status")["return"],
        "frozen",
        "recovery mode"
    );
    let reply = agent.execute("guest-get-osinfo");
    assert_eq!(
        reply["error"]["desc"],
        "filesystems are frozen; retry after thaw"
    );
    let reply = agent.execute("guest-fstrim");
    assert_eq!(reply["error"]["class"], "GenericError");
    // Thaw drains the real filesystem.
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert!(thawed["return"].as_u64().unwrap() >= 1, "{thawed}");
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "thawed");
    assert!(!agent.state_dir().join("frozen").exists(), "marker gone");
    // The filesystem really is thawed: a write completes.
    std::fs::write(format!("{mount}/after-thaw"), b"ok").unwrap();
    agent.wait_for_stderr("\"event\":\"recovery_mode\"", e2e::REPLY_TIMEOUT);
    assert!(agent.stop().success());
}

/// A second, independent filesystem for tests that need two: the xfs
/// loop mount when `mk-loop-fs.sh` made one, else an ext4 image of its
/// own on a loop device, detached on drop.
struct SecondFs {
    mount: String,
    loop_dev: Option<String>,
    _dir: Option<tempfile::TempDir>,
}

impl SecondFs {
    fn new() -> Self {
        if let Ok(mount) = std::env::var("QEMINGA_TEST_XFS_MOUNT") {
            return SecondFs {
                mount,
                loop_dev: None,
                _dir: None,
            };
        }
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("second.img");
        let mount = dir.path().join("second");
        std::fs::create_dir(&mount).unwrap();
        let ok = |cmd: &str, args: &[&str]| {
            let out = std::process::Command::new(cmd).args(args).output().unwrap();
            assert!(
                out.status.success(),
                "{cmd} {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        ok("truncate", &["-s", "64M", image.to_str().unwrap()]);
        ok("mkfs.ext4", &["-q", image.to_str().unwrap()]);
        let loop_dev = ok("losetup", &["--find", "--show", image.to_str().unwrap()]);
        ok("mount", &[&loop_dev, mount.to_str().unwrap()]);
        SecondFs {
            mount: mount.to_str().unwrap().to_owned(),
            loop_dev: Some(loop_dev),
            _dir: Some(dir),
        }
    }
}

impl Drop for SecondFs {
    fn drop(&mut self) {
        if let Some(loop_dev) = &self.loop_dev {
            let _ = std::process::Command::new("umount")
                .arg(&self.mount)
                .status();
            let _ = std::process::Command::new("losetup")
                .args(["-d", loop_dev])
                .status();
        }
    }
}

/// The external review's arrangement, on real mounts in a private tmpfs:
/// A bound first (`staging-a`), B bound at `data` and again at `b-alias`,
/// then A moved over `data`. A keeps its earlier row in the mount table
/// while it is what `data` leads to. Unmounted in reverse on drop.
struct MovedMount {
    base: tempfile::TempDir,
}

impl MovedMount {
    fn arrange(a: &str, b: &str) -> Self {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().to_str().unwrap().to_owned();
        let sh = |args: &[&str]| {
            let out = std::process::Command::new("mount")
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "mount {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        sh(&["-t", "tmpfs", "tmpfs", &root]);
        sh(&["--make-private", &root]);
        for d in ["staging-a", "data", "b-alias"] {
            std::fs::create_dir(base.path().join(d)).unwrap();
        }
        sh(&["--bind", a, &format!("{root}/staging-a")]);
        sh(&["--bind", b, &format!("{root}/data")]);
        sh(&["--bind", b, &format!("{root}/b-alias")]);
        // A bind mount joins its source's peer group: on a host whose
        // mounts are shared (systemd's default), the move onto B's bind
        // would otherwise propagate A over every peer of B, its original
        // mount point included. The subtree is private before the move.
        sh(&["--make-rprivate", &root]);
        sh(&[
            "--move",
            &format!("{root}/staging-a"),
            &format!("{root}/data"),
        ]);
        MovedMount { base }
    }

    fn data(&self) -> String {
        format!("{}/data", self.base.path().to_str().unwrap())
    }

    fn b_alias(&self) -> String {
        format!("{}/b-alias", self.base.path().to_str().unwrap())
    }
}

impl Drop for MovedMount {
    fn drop(&mut self) {
        let root = self.base.path().to_str().unwrap().to_owned();
        for target in [
            format!("{root}/data"),
            format!("{root}/data"),
            format!("{root}/b-alias"),
            root,
        ] {
            let _ = std::process::Command::new("umount").arg(&target).status();
        }
    }
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_a_mount_moved_over_a_newer_one_is_what_the_request_freezes() {
    // The external review's counterexample on the real kernel: with A
    // moved over B at `data`, a request for `data` must freeze A (what
    // the pathname leads to) and not B (the later row at that path, still
    // reachable at `b-alias`), and the count must be 1. Proven on the
    // superblocks themselves: FIFREEZE on A's original mount answers
    // EBUSY (already frozen), on B's it succeeds (thawed again at once).
    use qeminga::kernel::KernelOps;
    let b = ext4_mount();
    let second = SecondFs::new();
    let a = second.mount.clone();
    let _thaw = ThawGuard::new(&[a.clone(), b.clone()]);
    let arranged = MovedMount::arrange(&a, &b);
    let data = arranged.data();
    assert_eq!(
        dev_of(std::path::Path::new(&data)),
        dev_of(std::path::Path::new(&a)),
        "A is what data leads to"
    );
    assert_eq!(
        dev_of(std::path::Path::new(&b)),
        dev_of(std::path::Path::new(&arranged.b_alias())),
        "B still leads to its own superblock: the move did not propagate"
    );
    let kernel = qeminga::kernel::LinuxKernel;
    // Both superblocks start thawed (a freeze and thaw of each succeed),
    // so a freeze found afterwards is the request's.
    for (name, mount) in [("A", &a), ("B", &b)] {
        let handle = handle(std::path::Path::new(mount));
        kernel
            .fifreeze(&handle)
            .unwrap_or_else(|err| panic!("{name} is frozen before the request: {err}"));
        kernel.fithaw(&handle).unwrap();
    }
    let rows = || {
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .filter(|row| row.contains(&a) || row.contains(&b) || row.contains(&data))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mut agent = Agent::spawn_with(real_kernel(""));
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&data)),
        json!({"return": 1})
    );
    let frozen = kernel.fifreeze(&handle(std::path::Path::new(&a)));
    assert!(
        matches!(
            frozen,
            Err(qeminga::kernel::KernelError::Errno(
                nix::errno::Errno::EBUSY
            ))
        ),
        "A is frozen: {frozen:?}\nmounts:\n{}\ndaemon stderr:\n{}",
        rows(),
        agent.stderr_text()
    );
    let b_handle = handle(std::path::Path::new(&b));
    if let Err(err) = kernel.fifreeze(&b_handle) {
        panic!(
            "B is not frozen: {err}\nmounts:\n{}\ndaemon stderr:\n{}",
            rows(),
            agent.stderr_text()
        );
    }
    kernel.fithaw(&b_handle).unwrap();
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert_eq!(thawed["return"], 1, "{thawed}");
    std::fs::write(format!("{a}/after-moved-mount-thaw"), b"ok").unwrap();
    std::fs::write(format!("{b}/after-moved-mount-thaw"), b"ok").unwrap();
    assert!(agent.stop().success());
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_every_thread_carries_the_dropped_ceiling() {
    // §5.4 (external review, finding 3): capability sets and the bounding
    // set are per thread, and the drop trims the calling thread's, so a
    // thread created before it would keep the unit's bounding set. Every
    // thread is created after the drop (the audit writer at step 5b, the
    // runtime's after the filter): after a freeze and thaw have put the
    // blocking pool to work, every thread of the daemon shows the dropped
    // uid, the final sets, the trimmed bounding set, no-new-privs and the
    // filter, not only the main thread.
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let mut agent = Agent::spawn_with(real_kernel(""));
    agent.wait_for_stderr("\"event\":\"privileges_dropped\"", e2e::REPLY_TIMEOUT);
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    assert!(
        agent.execute("guest-fsfreeze-thaw")["return"]
            .as_u64()
            .unwrap()
            >= 1
    );
    let threads = e2e::thread_statuses(agent.pid());
    let names: Vec<&str> = threads.iter().map(|t| t.name.as_str()).collect();
    assert!(
        names.contains(&"qeminga-audit") && names.iter().any(|n| n.starts_with("qeminga-work")),
        "the audit writer and the runtime's workers are there: {names:?}"
    );
    assert!(threads.len() >= 3, "{names:?}");
    // CAP_DAC_READ_SEARCH (2), CAP_SYS_ADMIN (21), CAP_SYS_BOOT (22).
    for t in &threads {
        assert!(
            t.field("Uid:").starts_with("600\t600"),
            "{}: {}",
            t.name,
            t.field("Uid:")
        );
        for set in ["CapEff:", "CapPrm:", "CapBnd:"] {
            assert_eq!(t.field(set), "0000000000600004", "{} {set}", t.name);
        }
        assert_eq!(t.field("CapInh:"), "0000000000000000", "{}", t.name);
        assert_eq!(t.field("CapAmb:"), "0000000000000000", "{}", t.name);
        assert_eq!(t.field("NoNewPrivs:"), "1", "{}", t.name);
        if cfg!(feature = "seccomp") {
            assert_eq!(t.field("Seccomp:"), "2", "{}", t.name);
        }
    }
    assert!(agent.stop().success());
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_watchdog_idle_and_hard_cap_on_real_fs() {
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let mut agent = Agent::spawn_with(real_kernel(
        "fsfreeze_idle_timeout_secs = 2\nfsfreeze_max_timeout_secs = 5\n",
    ));
    // Idle: no heartbeat, thawed after ~2 s.
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    std::thread::sleep(Duration::from_millis(3500));
    assert_eq!(
        agent.execute("guest-fsfreeze-status")["return"],
        "thawed",
        "idle timeout"
    );
    assert!(!agent.state_dir().join("frozen").exists());
    std::fs::write(format!("{mount}/idle"), b"ok").unwrap();
    // Hard cap: heartbeats every second, thawed after ~5 s regardless.
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    let start = Instant::now();
    let mut thawed_at = None;
    while start.elapsed() < Duration::from_secs(9) {
        std::thread::sleep(Duration::from_secs(1));
        let status = agent.execute("guest-fsfreeze-status");
        if status["return"] == "thawed" {
            thawed_at = Some(start.elapsed());
            break;
        }
    }
    let at = thawed_at.expect("hard cap thawed the filesystem");
    assert!(
        at >= Duration::from_secs(4) && at <= Duration::from_secs(8),
        "{at:?}"
    );
    std::fs::write(format!("{mount}/cap"), b"ok").unwrap();
    assert!(agent.stop().success());
}

/// A bind mount made by the test, unmounted and removed on drop.
struct BindMount(std::path::PathBuf);

impl BindMount {
    fn of(source: &str, at: std::path::PathBuf) -> Self {
        let _ = std::fs::remove_dir(&at);
        std::fs::create_dir(&at).unwrap();
        let status = std::process::Command::new("mount")
            .arg("--bind")
            .arg(source)
            .arg(&at)
            .status()
            .unwrap();
        assert!(status.success(), "mount --bind failed");
        BindMount(at)
    }

    /// A bind mount taken out of its source's peer group: a mount placed
    /// over the source afterwards does not propagate onto it. On a host
    /// whose mounts are shared (systemd's default for `/`, and the CI
    /// runner) a plain bind mount is a peer of its source, so an
    /// overmount on the source covers the bind too and the superblock is
    /// hidden under every pathname at once.
    fn private_of(source: &str, at: std::path::PathBuf) -> Self {
        let bind = Self::of(source, at);
        let status = std::process::Command::new("mount")
            .arg("--make-private")
            .arg(&bind.0)
            .status()
            .unwrap();
        assert!(status.success(), "mount --make-private failed");
        bind
    }
}

impl Drop for BindMount {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount").arg(&self.0).status();
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_raw_byte_mount_point_survives_startup_fsinfo_and_freeze() {
    // A mount point whose name carries a raw non-UTF-8 byte: the kernel
    // writes it raw into mountinfo (only space, tab, newline and backslash
    // are escaped), so the table is not text. The parser must keep the
    // byte, the ioctls must get it byte-exact, and the daemon must start
    // (its state_path check reads the table), report the mount lossily in
    // fsinfo, and freeze/thaw with it present.
    use qeminga::kernel::{KernelOps, LinuxKernel};
    use qeminga::mountinfo::{MountSource, ProcMounts};
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let base = std::path::Path::new(&mount).parent().unwrap().to_path_buf();
    let bind = BindMount::of(&mount, base.join(OsStr::from_bytes(b"caf\xe9-bind")));
    let dir = bind.0.clone();
    let table = qeminga::mountinfo::read_mountinfo_bounded(std::path::Path::new(
        qeminga::mountinfo::MOUNTINFO_PATH,
    ))
    .unwrap();
    assert!(
        std::str::from_utf8(&table).is_err(),
        "the kernel wrote the byte raw: the table is not UTF-8"
    );
    let entries = ProcMounts.mounts().unwrap();
    let entry = entries
        .iter()
        .find(|e| e.mount_point == dir)
        .expect("the raw-byte mount point is parsed byte-exact");
    assert_eq!(entry.fs_type, "ext4");
    let origin = entries
        .iter()
        .find(|e| e.mount_point == std::path::Path::new(&mount))
        .unwrap();
    assert_eq!(entry.dev(), origin.dev(), "same superblock as its origin");
    // The kernel accepts the byte-exact path for the freeze ioctls.
    let raw = LinuxKernel
        .open_mount(&dir, entry.dev())
        .expect("open the raw-byte path on its device");
    LinuxKernel
        .fifreeze(&raw)
        .expect("FIFREEZE on the raw-byte path");
    LinuxKernel
        .fithaw(&raw)
        .expect("FITHAW on the raw-byte path");
    // The daemon: startup, fsinfo (lossy name), freeze-list, thaw.
    let mut agent = Agent::spawn_with(real_kernel(""));
    let lossy = dir.to_string_lossy().into_owned();
    assert!(lossy.contains('\u{fffd}'));
    let fsinfo = agent.execute("guest-get-fsinfo");
    let reported = fsinfo["return"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fs| fs["mountpoint"] == lossy)
        .unwrap_or_else(|| panic!("fsinfo lists the mount lossily: {fsinfo}"));
    assert_eq!(reported["type"], "ext4");
    let reply = freeze_list(&mut agent, &[mount.clone(), lossy]);
    assert_eq!(
        reply,
        json!({"return": 1}),
        "the ext4 superblock frozen once; the lossy name matches nothing"
    );
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert!(thawed["return"].as_u64().unwrap() >= 1, "{thawed}");
    std::fs::write(dir.join("after"), b"ok").unwrap();
    assert!(agent.stop().success());
}

#[test]
#[ignore = "needs root, a loop-mounted ext4 with a bind mount and a 0700 mountpoint (scripts/ci/mk-loop-fs.sh)"]
fn privileged_freeze_with_tmpfs_bind_and_0700_mountpoint() {
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let bind = std::env::var("QEMINGA_TEST_EXT4_BIND").expect("QEMINGA_TEST_EXT4_BIND");
    let mode = std::fs::metadata(&mount).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        mode.mode() & 0o777,
        0o700,
        "the script makes the mountpoint 0700"
    );
    let mut agent = Agent::spawn_with(real_kernel(""));
    // Both the mount and its bind mount are requested; tmpfs (/dev/shm,
    // /run) is never in the plan; the 0700 mountpoint is opened with
    // CAP_DAC_READ_SEARCH as the dropped user.
    let reply = freeze_list(
        &mut agent,
        &[mount.clone(), bind.clone(), "/dev/shm".to_owned()],
    );
    assert_eq!(
        reply,
        json!({"return": 1}),
        "bind mount de-duplicated, tmpfs ignored"
    );
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    // A concurrent freezer (this test, with CAP_SYS_ADMIN) sees EBUSY,
    // proving the superblock really is frozen.
    use qeminga::kernel::KernelOps;
    let err = qeminga::kernel::LinuxKernel
        .fifreeze(&handle(std::path::Path::new(&mount)))
        .unwrap_err();
    assert!(err.is_busy(), "{err}");
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert!(thawed["return"].as_u64().unwrap() >= 1, "{thawed}");
    std::fs::write(format!("{mount}/after"), b"ok").unwrap();
    assert!(agent.stop().success());
}

/// A tmpfs mounted over an existing pathname, unmounted on drop: what
/// the pathname leads to is then a different superblock that answers
/// "not frozen" to any thaw.
struct OverMount(std::path::PathBuf);

impl OverMount {
    fn tmpfs_at(path: &str) -> Self {
        let status = std::process::Command::new("mount")
            .args(["-t", "tmpfs", "none", path])
            .status()
            .unwrap();
        assert!(status.success(), "mount -t tmpfs over {path} failed");
        OverMount(std::path::PathBuf::from(path))
    }
}

impl Drop for OverMount {
    fn drop(&mut self) {
        let status = std::process::Command::new("umount").arg(&self.0).status();
        assert!(
            matches!(status, Ok(s) if s.success()),
            "umount {}",
            self.0.display()
        );
    }
}

/// `true` when a write under `dir` completes within `timeout`; a write on
/// a frozen filesystem blocks in D state instead (the thread is left to
/// complete once the guard thaws).
fn writable_within(dir: &std::path::Path, name: &str, timeout: Duration) -> bool {
    let path = dir.join(name);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let ok = std::fs::write(&path, b"ok").is_ok();
        let _ = tx.send(ok);
    });
    rx.recv_timeout(timeout).unwrap_or(false)
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_thaw_reaches_the_frozen_filesystem_hidden_by_an_overmount() {
    // The loop ext4 has a bind alias; after each freeze a tmpfs is mounted
    // over the original pathname, so that pathname leads to a filesystem
    // that is not frozen and would answer EINVAL to a thaw. The thaw must
    // reach the ext4 all the same, and the marker may only disappear once
    // it did: (1) in the same process, through the handle the freeze
    // opened; (2) after a SIGKILL and a restart, through the alias; (3)
    // with the alias gone too, not at all: the marker and the frozen gate
    // are retained until a pathname leads there again.
    //
    // The alias is a private mount: with shared propagation (the default
    // on a systemd host and on the CI runner) the overmount would
    // propagate onto a peer bind mount and hide the ext4 under the alias
    // as well, which is case (3), not case (2).
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let base = std::path::Path::new(&mount).parent().unwrap().to_path_buf();
    let alias = BindMount::private_of(&mount, base.join("ext4-alias"));
    let ext4 = dev_of(std::path::Path::new(&mount));
    let frozen = |dir: &std::path::Path| {
        use qeminga::kernel::KernelOps;
        // A concurrent FIFREEZE on a frozen superblock answers EBUSY.
        let h = qeminga::kernel::LinuxKernel.open_mount(dir, ext4).unwrap();
        qeminga::kernel::LinuxKernel
            .fifreeze(&h)
            .unwrap_err()
            .is_busy()
    };

    // (1) Same process: the handle the freeze opened.
    let mut agent = Agent::spawn_with(real_kernel(""));
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    let over = OverMount::tmpfs_at(&mount);
    assert_ne!(
        dev_of(std::path::Path::new(&mount)),
        ext4,
        "the pathname leads elsewhere"
    );
    assert!(
        writable_within(
            std::path::Path::new(&mount),
            "on-tmpfs",
            Duration::from_secs(5)
        ),
        "the tmpfs over the pathname is not frozen"
    );
    assert!(frozen(&alias.0), "the ext4 is frozen");
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert_eq!(thawed, json!({"return": 1}), "{thawed}");
    assert!(!agent.state_dir().join("frozen").exists(), "marker gone");
    assert!(
        writable_within(&alias.0, "after-handle-thaw", Duration::from_secs(10)),
        "the ext4 is thawed, not the tmpfs in its place"
    );
    agent.wait_for_stderr("\"event\":\"fsfreeze_thawed\"", e2e::REPLY_TIMEOUT);

    // (2) Restart: nothing held, the alias is how the ext4 is reached.
    drop(over);
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    let dir = agent.kill();
    assert!(
        dir.path().join("frozen").exists(),
        "marker survives SIGKILL"
    );
    let over = OverMount::tmpfs_at(&mount);
    let mut agent = Agent::spawn_with(SpawnOptions {
        state_dir: Some(dir),
        ..real_kernel("")
    });
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert_eq!(thawed, json!({"return": 1}), "{thawed}");
    assert!(!agent.state_dir().join("frozen").exists(), "marker gone");
    assert!(
        writable_within(&alias.0, "after-alias-thaw", Duration::from_secs(10)),
        "recovery thawed the ext4 through its alias"
    );
    agent.wait_for_stderr("\"event\":\"fsfreeze_alias\"", e2e::REPLY_TIMEOUT);

    // (3) Restart with no pathname leading to the ext4 at all (every
    // mount of its device is covered, the loop script's own bind mount
    // included): the thaw reports it unreachable and keeps the recovery
    // state; once a pathname leads there again, the next thaw completes.
    drop(over);
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    let dir = agent.kill();
    drop(alias);
    let hidden: Vec<OverMount> = {
        use qeminga::mountinfo::MountSource;
        qeminga::mountinfo::ProcMounts
            .mounts()
            .unwrap()
            .iter()
            .filter(|e| e.dev() == ext4)
            .map(|e| OverMount::tmpfs_at(e.mount_point.to_str().unwrap()))
            .collect()
    };
    assert!(!hidden.is_empty());
    let mut agent = Agent::spawn_with(SpawnOptions {
        state_dir: Some(dir),
        ..real_kernel("")
    });
    let reply = agent.execute("guest-fsfreeze-thaw");
    let desc = reply["error"]["desc"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"));
    assert!(desc.contains("no mount point leads to"), "{desc}");
    assert!(desc.contains("not on the planned"), "{desc}");
    assert!(desc.contains("marker retained"), "{desc}");
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert!(agent.state_dir().join("frozen").exists(), "marker retained");
    drop(hidden);
    assert!(
        frozen(std::path::Path::new(&mount)),
        "still frozen meanwhile"
    );
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert_eq!(thawed, json!({"return": 1}), "{thawed}");
    assert!(!agent.state_dir().join("frozen").exists());
    assert!(
        writable_within(
            std::path::Path::new(&mount),
            "after-reachable",
            Duration::from_secs(10)
        ),
        "thawed once reachable"
    );
    assert!(agent.stop().success());
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_channel_eof_during_freeze_preserves_marker() {
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let mut agent = Agent::spawn_with(real_kernel(""));
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    agent.reopen_channel();
    assert!(
        agent.state_dir().join("frozen").exists(),
        "marker preserved across EOF"
    );
    let status = agent.request_timeout(
        r#"{"execute":"guest-fsfreeze-status"}"#,
        e2e::REOPEN_TIMEOUT,
    );
    assert_eq!(status["return"], "frozen");
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert!(thawed["return"].as_u64().unwrap() >= 1, "{thawed}");
    assert!(!agent.state_dir().join("frozen").exists());
    std::fs::write(format!("{mount}/after-reopen"), b"ok").unwrap();
    assert!(agent.stop().success());
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_journald_pipe_full_does_not_deadlock_thaw() {
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let mut agent = Agent::spawn_with(SpawnOptions {
        stderr_pipe: true,
        ..real_kernel("")
    });
    let mut stderr = agent.take_stderr_pipe().unwrap();
    // Keep the "journald" side draining until the freeze is in place.
    let mut drained = Vec::new();
    let drain = |stderr: &mut std::fs::File, drained: &mut Vec<u8>| {
        let mut buf = [0u8; 8192];
        // Non-blocking drain of whatever is there.
        use std::os::fd::AsFd;
        let fd = stderr.as_fd();
        let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).unwrap();
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFL(
                nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK,
            ),
        )
        .unwrap();
        loop {
            match stderr.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => drained.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
    };
    drain(&mut stderr, &mut drained);
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    drain(&mut stderr, &mut drained);
    let drained_before = drained.len();
    // "journald" stops reading (its own filesystem is frozen). Sustained
    // logging volume: > 64 KiB of audit records while frozen.
    for i in 0..600 {
        let reply = agent.request(&format!(
            r#"{{"execute":"guest-fsfreeze-status","id":{i}}}"#
        ));
        assert_eq!(reply["return"], "frozen");
    }
    // Nothing reached the pipe meanwhile (ring mode): the daemon never
    // wrote to a descriptor that could block.
    drain(&mut stderr, &mut drained);
    assert_eq!(
        drained.len(),
        drained_before,
        "no bytes to stderr while frozen (AC13)"
    );
    // The §9.1 hazard proper: journald has stopped reading and its pipe
    // is full, so any write to stderr blocks. Fill it to capacity from the
    // test's own write end and leave it full while the thaw runs.
    // O_NONBLOCK is a status flag of the *open file description*, which
    // this dup shares with the daemon's stderr: it is set only while the
    // pipe is being filled and cleared again before the thaw, so that the
    // daemon's own writes block as journald's would make them.
    let mut writer = agent.take_stderr_writer().unwrap();
    let set_nonblock = |writer: &std::fs::File, on: bool| {
        use std::os::fd::AsFd;
        let fd = writer.as_fd();
        let flags = nix::fcntl::OFlag::from_bits_retain(
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).unwrap(),
        );
        let flags = if on {
            flags | nix::fcntl::OFlag::O_NONBLOCK
        } else {
            flags - nix::fcntl::OFlag::O_NONBLOCK
        };
        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags)).unwrap();
    };
    set_nonblock(&writer, true);
    let mut filled = 0usize;
    loop {
        match writer.write(&[b'#'; 4096]) {
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(err) => panic!("filling the pipe: {err}"),
        }
    }
    assert!(filled > 0, "the pipe was filled to capacity");
    set_nonblock(&writer, false);
    // Thaw with the pipe full and left full (#43 §3: the pipe is not
    // drained first, which would hide a dependency on the sink). The
    // FITHAW drain is proved from the filesystem itself: a write to the
    // mount blocks in D state while frozen and completes as soon as the
    // drain has thawed it; and the reply arrives while the pipe is still
    // full, because delivery of the audit records is the writer thread's
    // business, not the thaw's finalisation.
    agent.send_line(r#"{"execute":"guest-fsfreeze-thaw","id":9999}"#);
    let probe_path = format!("{mount}/probe-during-full-pipe");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = std::fs::write(&probe_path, b"ok");
        let _ = done_tx.send(result);
    });
    match done_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(result) => result.expect("write to the thawed mount"),
        Err(_) => panic!(
            "the filesystem was not thawed within 20 s while stderr was blocked: the drain waited on the flush (§9.1)"
        ),
    }
    // The reply is delivered while the pipe is still full: state, marker
    // and reply never waited for journald.
    let reply = agent
        .read_line(Duration::from_secs(10))
        .expect("the thaw reply while stderr is blocked (#43 §3)");
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert!(reply["return"].as_u64().unwrap() >= 1, "{reply}");
    assert_eq!(
        agent.execute("guest-fsfreeze-status")["return"],
        "thawed",
        "status served while stderr is blocked"
    );
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1}),
        "a subsequent permitted operation completes while stderr is blocked"
    );
    assert!(
        agent.execute("guest-fsfreeze-thaw")["return"]
            .as_u64()
            .unwrap()
            >= 1
    );
    // journald comes back: drain the pipe and the queued records follow,
    // the ring's loss record among them.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        drain(&mut stderr, &mut drained);
        let text = String::from_utf8_lossy(&drained);
        if text.contains("\"event\":\"fsfreeze_thawed\"") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "queued records not delivered after draining; drained {} bytes",
            drained.len()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    drain(&mut stderr, &mut drained);
    let text = String::from_utf8_lossy(&drained);
    assert!(
        text.contains("\"event\":\"audit_records_lost\""),
        "ring overflow reported: {}",
        &text[text.len().saturating_sub(500)..]
    );
    assert!(text.contains("\"event\":\"fsfreeze_thawed\""));
    std::fs::write(format!("{mount}/after-pipe"), b"ok").unwrap();
    drop(stderr);
    assert!(agent.stop().success());
    let _ = std::io::stdout().flush();
}

#[test]
#[ignore = "needs root (changes and restores the mode of /sys/power/state)"]
fn privileged_tmpfiles_rule_makes_sys_power_state_writable_for_the_service_account() {
    // OQ-6: applying packaging/tmpfiles.d/qeminga-suspend.conf must leave
    // /sys/power/state writable for uid/gid 600 (the dropped daemon has no
    // capability that bypasses the file mode). The original owner and
    // mode are restored afterwards.
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path = std::path::Path::new("/sys/power/state");
    let before = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            eprintln!("skipped: {}: {err}", path.display());
            return;
        }
    };
    let group = nix::unistd::Group::from_name("qeminga")
        .unwrap()
        .expect("the qeminga group (packaging/sysusers.d/qeminga.conf)");
    let conf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packaging/tmpfiles.d/qeminga-suspend.conf");
    let output = std::process::Command::new("systemd-tmpfiles")
        .arg("--create")
        .arg(&conf)
        .output()
        .expect("systemd-tmpfiles");
    let restore = || {
        let _ = nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(before.uid())),
            Some(nix::unistd::Gid::from_raw(before.gid())),
        );
        let _ = std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(before.mode() & 0o7777),
        );
    };
    if !output.status.success() {
        restore();
        panic!(
            "systemd-tmpfiles --create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let after = std::fs::metadata(path).unwrap();
    restore();
    assert_eq!(after.gid(), group.gid.as_raw(), "group qeminga");
    assert_eq!(after.mode() & 0o777, 0o664, "group-writable");
    let restored = std::fs::metadata(path).unwrap();
    assert_eq!(restored.mode() & 0o777, before.mode() & 0o777);
    assert_eq!(restored.gid(), before.gid());
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_seccomp_matrix_log_then_enforce() {
    // Runs the full allowed-command matrix through the real binary with
    // the real kernel. The CI job runs this test twice: with the
    // `seccomp-log` build and with the enforced build, whose feature set
    // deliberately excludes `seccomp-log` (AC15).
    let mount = ext4_mount();
    let _thaw = ThawGuard::new(std::slice::from_ref(&mount));
    let audit_lines = || -> Option<usize> {
        std::process::Command::new("dmesg")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .matches("type=1326")
                    .count()
            })
    };
    let before = audit_lines();
    let mut agent = Agent::spawn_with(real_kernel(""));
    agent.wait_for_stderr("\"event\":\"seccomp\"", e2e::REPLY_TIMEOUT);
    let stderr = agent.stderr_text();
    let installed = stderr.contains("\"event\":\"seccomp\",\"installed\":true");
    assert_eq!(installed, cfg!(feature = "seccomp"), "{stderr}");
    // Prove which policy this run exercises: the daemon is built with the
    // same features as this test, and its startup record names the mode.
    let mode = qeminga::daemon::seccomp_mode();
    assert!(
        stderr.contains(&format!("\"mode\":\"{mode}\"")),
        "expected seccomp mode {mode}: {stderr}"
    );
    println!("seccomp matrix under mode={mode}");
    for method in [
        "guest-ping",
        "guest-info",
        "guest-get-osinfo",
        "guest-network-get-interfaces",
        "guest-get-fsinfo",
        "guest-fsfreeze-status",
    ] {
        let reply = agent.execute(method);
        assert!(reply.get("return").is_some(), "{method}: {reply}");
    }
    assert_eq!(
        agent.request(r#"{"execute":"guest-sync","arguments":{"id":5}}"#)["return"],
        5
    );
    assert_eq!(
        agent.request(r#"{"execute":"guest-sync-delimited","arguments":{"id":6}}"#)["return"],
        6
    );
    assert_eq!(
        freeze_list(&mut agent, std::slice::from_ref(&mount)),
        json!({"return": 1})
    );
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert!(
        agent.execute("guest-fsfreeze-thaw")["return"]
            .as_u64()
            .unwrap()
            >= 1
    );
    let trim = agent.execute("guest-fstrim");
    assert!(trim["return"]["paths"].is_array(), "{trim}");
    let exec = agent.execute("guest-exec");
    assert_eq!(exec["error"]["class"], "CommandNotFound");
    assert!(agent.stop().success());
    if let (Some(b), Some(a)) = (before, audit_lines()) {
        assert_eq!(
            a, b,
            "seccomp audit lines appeared in dmesg (a syscall is missing from the profile)"
        );
    }
}
