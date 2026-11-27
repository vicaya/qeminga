//! End-to-end tests for OQ-10 two-process parser/executor isolation (#78).
//!
//! Spawns the real `qeminga` binary and inspects both the executor and its
//! isolated `--internal-parser` child process through `/proc`, verifying:
//! - distinct parser child PID, single-threaded `ppoll` loop, `/dev/null` on
//!   fds `0`/`1`/`2` (never sharing the executor's `stderr` audit sink), pinned
//!   `IPC_FD = 3` in both processes, no leaked marker/stderr fds in parser, and
//!   executor closing its copy of the verified channel fd immediately after
//!   handing it to the parser;
//! - `PR_SET_PDEATHSIG(SIGKILL)` terminating the parser when the executor dies;
//! - parser crash (`SIGKILL`) while `Thawed` causing executor to reap and exit
//!   non-zero;
//! - parser crash (`SIGKILL`) while `Frozen` keeping `FreezeState`, marker, and
//!   watchdog alive until autonomous thaw completes, and only then exiting
//!   non-zero;
//! - default `channel_transport = "virtio-serial"` failing closed on both a
//!   PTY slave and a regular file without ever handing the descriptor to the
//!   parser.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use e2e::{Agent, SpawnOptions};
use nix::sys::signal::{Signal, kill};
use nix::sys::stat::{major, minor};
use nix::unistd::Pid;
use serde_json::json;

/// Discovers direct child PIDs of `parent_pid` from `/proc`.
fn child_pids(parent_pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{parent_pid}/task")) {
        for entry in tasks.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path().join("children")) {
                for tok in text.split_whitespace() {
                    if let Ok(pid) = tok.parse::<u32>()
                        && !out.contains(&pid)
                    {
                        out.push(pid);
                    }
                }
            }
        }
    }
    if !out.is_empty() {
        return out;
    }
    // Fallback when `/proc/<pid>/task/*/children` is unavailable.
    let ppid_line = format!("PPid:\t{parent_pid}");
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if let Ok(status) = std::fs::read_to_string(entry.path().join("status"))
                && status.lines().any(|l| l.trim() == ppid_line)
            {
                out.push(pid);
            }
        }
    }
    out
}

fn wait_for_parser_child(executor_pid: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let children = child_pids(executor_pid);
        if children.len() == 1 {
            return children[0];
        }
        assert!(
            Instant::now() < deadline,
            "expected exactly one parser child of {executor_pid}, found {children:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_pid_gone(pid: u32, timeout: Duration) {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    let deadline = Instant::now() + timeout;
    while proc_dir.exists() {
        // Reap zombies check: if `/proc/{pid}/status` shows State: Z it's dead.
        if let Ok(status) = std::fs::read_to_string(proc_dir.join("status"))
            && status.lines().any(|l| l.starts_with("State:\tZ"))
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process {pid} did not exit within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn status_field(status: &str, key: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("{key} missing in:\n{status}"))
        .trim()
        .to_owned()
}

#[test]
fn isolated_parser_process_has_single_thread_dev_null_stdio_and_no_executor_fds() {
    let mut agent = Agent::spawn();
    assert_eq!(
        agent.request(r#"{"execute":"guest-ping","id":1}"#),
        json!({"return": {}, "id": 1})
    );

    let exec_pid = agent.pid();
    let parser_pid = wait_for_parser_child(exec_pid);
    assert_ne!(parser_pid, exec_pid);

    let stderr = agent.stderr_text();
    assert!(
        stderr.contains("\"event\":\"parser_spawned\"")
            && stderr.contains(&format!("\"parser_pid\":{parser_pid}")),
        "expected parser_spawned with parser_pid={parser_pid} in stderr:\n{stderr}"
    );

    // Parser runs a single-threaded ppoll loop with seccomp active when compiled in.
    let parser_status = std::fs::read_to_string(format!("/proc/{parser_pid}/status")).unwrap();
    assert_eq!(status_field(&parser_status, "Name:"), "qeminga-parser");
    assert_eq!(status_field(&parser_status, "PPid:"), exec_pid.to_string());
    assert_eq!(status_field(&parser_status, "Threads:"), "1");
    if cfg!(feature = "seccomp") {
        assert_eq!(status_field(&parser_status, "NoNewPrivs:"), "1");
        assert_eq!(status_field(&parser_status, "Seccomp:"), "2");
    }
    if nix::unistd::geteuid().is_root() {
        assert!(
            status_field(&parser_status, "Uid:").starts_with("601\t601"),
            "{parser_status}"
        );
        assert!(
            status_field(&parser_status, "Gid:").starts_with("601\t601"),
            "{parser_status}"
        );
        for set in ["CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"] {
            assert_eq!(
                status_field(&parser_status, set),
                "0000000000000000",
                "parser {set} must be zero"
            );
        }
    }

    // Backing kernel object check on parser fds 0/1/2: must be /dev/null char(1,3)
    // and distinct from executor's inherited stderr audit sink.
    let exec_stderr_meta = std::fs::metadata(format!("/proc/{exec_pid}/fd/2")).unwrap();
    for fd_num in [0, 1, 2] {
        let meta = std::fs::metadata(format!("/proc/{parser_pid}/fd/{fd_num}")).unwrap();
        assert!(
            meta.file_type().is_char_device(),
            "parser fd {fd_num} must be char device"
        );
        assert_eq!(
            (major(meta.rdev()), minor(meta.rdev())),
            (1, 3),
            "parser fd {fd_num} must be /dev/null (1, 3)"
        );
        assert_ne!(
            (meta.dev(), meta.ino()),
            (exec_stderr_meta.dev(), exec_stderr_meta.ino()),
            "parser fd {fd_num} must never alias executor stderr audit sink"
        );
    }

    // Both processes pin IPC_FD = 3 to a Unix socket; parser has no marker or
    // stderr fds, and executor has closed its copy of the PTY channel fd.
    let parser_ipc_link = std::fs::read_link(format!("/proc/{parser_pid}/fd/3")).unwrap();
    let exec_ipc_link = std::fs::read_link(format!("/proc/{exec_pid}/fd/3")).unwrap();
    assert!(
        parser_ipc_link.to_string_lossy().starts_with("socket:["),
        "parser fd 3: {parser_ipc_link:?}"
    );
    assert!(
        exec_ipc_link.to_string_lossy().starts_with("socket:["),
        "executor fd 3: {exec_ipc_link:?}"
    );

    let state_dir = agent.state_dir().to_string_lossy().into_owned();
    let mut parser_has_pts = false;
    for entry in std::fs::read_dir(format!("/proc/{parser_pid}/fd"))
        .unwrap()
        .flatten()
    {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let s = target.to_string_lossy();
            assert!(
                !s.contains(&state_dir),
                "parser must not hold state_dir/marker/stderr fd: {s}"
            );
            if s.starts_with("/dev/pts/") {
                parser_has_pts = true;
            }
        }
    }
    assert!(parser_has_pts, "parser must own the open PTY channel fd");

    for entry in std::fs::read_dir(format!("/proc/{exec_pid}/fd"))
        .unwrap()
        .flatten()
    {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let s = target.to_string_lossy();
            assert!(
                !s.starts_with("/dev/pts/"),
                "executor must close its copy of the channel fd immediately after handoff: {s}"
            );
        }
    }

    let status = agent.stop();
    assert!(status.success(), "{status}");
    wait_for_pid_gone(parser_pid, Duration::from_secs(5));
}

#[test]
fn executor_sigkill_terminates_parser_via_pdeathsig() {
    let mut agent = Agent::spawn();
    assert_eq!(agent.execute("guest-ping"), json!({"return": {}}));
    let parser_pid = wait_for_parser_child(agent.pid());
    let _dir = agent.kill();
    wait_for_pid_gone(parser_pid, Duration::from_secs(5));
}

#[test]
fn parser_crash_while_thawed_causes_executor_to_reap_and_exit_nonzero() {
    let mut agent = Agent::spawn();
    assert_eq!(agent.execute("guest-ping"), json!({"return": {}}));
    let parser_pid = wait_for_parser_child(agent.pid());

    kill(Pid::from_raw(parser_pid as i32), Signal::SIGKILL).unwrap();

    let status = agent
        .wait_exit(Duration::from_secs(5))
        .expect("executor should exit after parser crash while Thawed");
    assert!(
        !status.success(),
        "executor must exit non-zero on parser crash, got {status}"
    );
    let stderr = agent.stderr_text();
    assert!(
        stderr.contains("\"event\":\"parser_exited\""),
        "expected parser_exited in stderr:\n{stderr}"
    );
    wait_for_pid_gone(parser_pid, Duration::from_secs(5));
}

#[test]
#[cfg_attr(
    not(feature = "test-fakes"),
    ignore = "needs test-fakes so watchdog thaw completes unprivileged"
)]
fn parser_crash_while_frozen_keeps_watchdog_alive_until_thaw() {
    let mut agent = Agent::spawn_with(SpawnOptions {
        recovery_marker: true,
        agent_extra: "fsfreeze_idle_timeout_secs = 1\n".to_owned(),
        ..SpawnOptions::default()
    });
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert!(agent.state_dir().join("frozen").exists());

    let parser_pid = wait_for_parser_child(agent.pid());
    kill(Pid::from_raw(parser_pid as i32), Signal::SIGKILL).unwrap();

    // Executor must NOT exit immediately while Frozen; it must wait for the
    // 1 s idle watchdog to thaw and remove the recovery marker before exiting.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        agent.is_running(),
        "executor exited prematurely while still Frozen; stderr:\n{}",
        agent.stderr_text()
    );

    let status = agent
        .wait_exit(Duration::from_secs(10))
        .expect("executor should exit once watchdog thaw finishes");
    assert!(
        !status.success(),
        "executor must exit non-zero after parser crash + watchdog thaw, got {status}"
    );
    assert!(
        !agent.state_dir().join("frozen").exists(),
        "watchdog must remove recovery marker before executor exits"
    );
    let stderr = agent.stderr_text();
    assert!(
        stderr.contains("\"event\":\"parser_exited\""),
        "expected parser_exited in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("\"event\":\"watchdog_thaw\"")
            || stderr.contains("\"event\":\"fsfreeze_thawed\""),
        "expected watchdog thaw audit record in stderr:\n{stderr}"
    );
    wait_for_pid_gone(parser_pid, Duration::from_secs(5));
}

#[test]
fn virtio_serial_transport_rejects_pty_and_regular_file() {
    use std::os::unix::fs::PermissionsExt;
    e2e::require_service_account_when_root();
    // Default `channel_transport = "virtio-serial"` must fail closed on both a
    // regular file and a PTY slave, never handing either fd to the parser.
    let dir = tempfile::Builder::new()
        .prefix("qeminga-virtio-reject-")
        .tempdir_in("/dev/shm")
        .expect("tmpfs at /dev/shm");
    if nix::unistd::geteuid().is_root() {
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let regular = dir.path().join("not-a-channel");
    std::fs::write(&regular, b"{\"execute\":\"guest-ping\"}\n").unwrap();
    if nix::unistd::geteuid().is_root() {
        std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o666)).unwrap();
    }

    let master = nix::pty::posix_openpt(
        nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NOCTTY | nix::fcntl::OFlag::O_CLOEXEC,
    )
    .unwrap();
    nix::pty::grantpt(&master).unwrap();
    nix::pty::unlockpt(&master).unwrap();
    let slave_path = nix::pty::ptsname_r(&master).unwrap();
    let _slave_holder = nix::fcntl::open(
        Path::new(&slave_path),
        nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NOCTTY | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .unwrap();
    if nix::unistd::geteuid().is_root() {
        std::fs::set_permissions(&slave_path, std::fs::Permissions::from_mode(0o666)).unwrap();
    }

    for (label, target, expected_err) in [
        (
            "regular_file",
            regular.to_str().unwrap(),
            "not a character device",
        ),
        ("pty_slave", slave_path.as_str(), "sysfs"),
    ] {
        let sub = dir.path().join(label);
        std::fs::create_dir(&sub).unwrap();
        if nix::unistd::geteuid().is_root()
            && let Some(user) = nix::unistd::User::from_name("qeminga").unwrap()
        {
            nix::unistd::chown(&sub, Some(user.uid), Some(user.gid)).unwrap();
        }
        let cfg = sub.join("config.toml");
        std::fs::write(
            &cfg,
            format!(
                "[agent]\nchannel_path = \"{target}\"\nstate_path = \"{}\"\nlog_level = \"debug\"\nhardening = \"unenforced-development-only\"\n[features]\nseccomp = true\n",
                sub.join("frozen").display()
            ),
        )
        .unwrap();
        let stderr_path = sub.join("stderr.log");
        let stderr_file = std::fs::File::create(&stderr_path).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_qeminga"))
            .arg("--config")
            .arg(&cfg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut logs = String::new();
        while Instant::now() < deadline {
            logs = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            if logs.contains("\"event\":\"channel_open_failed\"")
                && logs.contains("\"event\":\"channel_open_retry\"")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            logs.contains("\"event\":\"channel_open_failed\"")
                && logs.contains("\"event\":\"channel_open_retry\"")
                && logs.contains(expected_err),
            "{label}: expected channel_open_failed and channel_open_retry mentioning {expected_err:?}; logs:\n{logs}"
        );
        assert!(
            !logs.contains("\"event\":\"channel_open\""),
            "{label}: unverified channel must never open; logs:\n{logs}"
        );

        kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();
        let status = child.wait().unwrap();
        assert!(
            status.success(),
            "{label}: SIGTERM status {status}; logs:\n{logs}"
        );
    }
}
