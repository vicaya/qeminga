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

fn real_kernel(agent_extra: &str) -> SpawnOptions {
    SpawnOptions {
        fake_kernel: false,
        agent_extra: agent_extra.to_owned(),
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
    let stderr = agent.stderr_text();
    assert!(stderr.contains("\"event\":\"recovery_mode\""), "{stderr}");
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
    assert!(
        agent
            .stderr_text()
            .contains("\"event\":\"fsfreeze_thawed\"")
    );

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
    let stderr = agent.stderr_text();
    assert!(stderr.contains("\"event\":\"fsfreeze_alias\""), "{stderr}");

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
    // Thaw with the pipe full. The proof that the FITHAW drain completed
    // comes from the filesystem itself, not from the daemon's reply (which
    // cannot be written until the flush that precedes it unblocks): a
    // write to the mount blocks in D state while frozen and completes as
    // soon as the drain has thawed it.
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
    // Nothing more reached the pipe (still full) and no reply yet: the
    // flush, and the reply after it, wait for journald, not the drain.
    assert!(
        agent.read_line(Duration::from_millis(300)).is_none(),
        "the reply is written only after the flush, which is blocked"
    );
    // journald comes back: drain the pipe, and the flush and reply follow.
    let deadline = Instant::now() + Duration::from_secs(20);
    let reply = loop {
        drain(&mut stderr, &mut drained);
        if let Some(line) = agent.read_line(Duration::from_millis(50)) {
            break line;
        }
        assert!(
            Instant::now() < deadline,
            "no thaw reply after draining; drained {} bytes",
            drained.len()
        );
    };
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert!(reply["return"].as_u64().unwrap() >= 1, "{reply}");
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
