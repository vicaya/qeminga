//! Privileged end-to-end tests (T5.2): the real binary, the real kernel,
//! loop-mounted filesystems from `scripts/ci/mk-loop-fs.sh`. All are
//! `#[ignore]`d and named `privileged_*`; run serially as root:
//!
//! ```sh
//! eval "$(sudo scripts/ci/mk-loop-fs.sh setup)"
//! sudo -E cargo test --all-features -- --ignored --test-threads=1 privileged_
//! ```
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

#[test]
#[ignore = "needs root, a loop-mounted ext4 with a bind mount and a 0700 mountpoint (scripts/ci/mk-loop-fs.sh)"]
fn privileged_freeze_with_tmpfs_bind_and_0700_mountpoint() {
    let mount = ext4_mount();
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
        .fifreeze(std::path::Path::new(&mount))
        .unwrap_err();
    assert!(err.is_busy(), "{err}");
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert!(thawed["return"].as_u64().unwrap() >= 1, "{thawed}");
    std::fs::write(format!("{mount}/after"), b"ok").unwrap();
    assert!(agent.stop().success());
}

#[test]
#[ignore = "needs root and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_channel_eof_during_freeze_preserves_marker() {
    let mount = ext4_mount();
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
    // Thaw: the flush goes to the pipe; drain it concurrently so the
    // reply can arrive, as journald would once its filesystem thawed.
    agent.send_line(r#"{"execute":"guest-fsfreeze-thaw","id":9999}"#);
    let deadline = Instant::now() + Duration::from_secs(20);
    let reply = loop {
        drain(&mut stderr, &mut drained);
        if let Some(line) = agent.read_line(Duration::from_millis(50)) {
            break line;
        }
        assert!(
            Instant::now() < deadline,
            "thaw deadlocked; drained {} bytes",
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
