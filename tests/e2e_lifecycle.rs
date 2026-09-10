//! End-to-end: shutdown silence (AC12) and channel reopen during a freeze
//! (AC18, unprivileged half).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

use e2e::{Agent, SpawnOptions};
use serde_json::json;
use std::time::Duration;

#[test]
#[cfg_attr(
    not(feature = "test-fakes"),
    ignore = "build with --features test-fakes to observe guest-shutdown without rebooting"
)]
fn shutdown_emits_no_reply() {
    assert!(Agent::has_fake_kernel());
    let mut agent = Agent::spawn();
    agent.send_line(r#"{"execute":"guest-shutdown","arguments":{"mode":"reboot"},"id":9}"#);
    assert!(
        agent.read_line(Duration::from_millis(500)).is_none(),
        "AC12: no success reply"
    );
    // The daemon is still alive (fake reboot) and the channel is intact.
    assert_eq!(
        agent.request(r#"{"execute":"guest-ping","id":10}"#),
        json!({"return": {}, "id": 10})
    );
    agent.wait_for_stderr("\"method\":\"guest-shutdown\"", e2e::REPLY_TIMEOUT);
    agent.wait_for_stderr("\"event\":\"fake_kernel\"", e2e::REPLY_TIMEOUT);
    // Errors are still reported: the shutdown class allows 2/min.
    agent.send_line(r#"{"execute":"guest-shutdown"}"#);
    assert!(agent.read_line(Duration::from_millis(500)).is_none());
    let third = agent.execute("guest-shutdown");
    assert_eq!(third["error"]["desc"], "rate limit exceeded for shutdown");
    assert!(agent.stop().success());
}

#[test]
#[cfg_attr(
    not(feature = "test-fakes"),
    ignore = "build with --features test-fakes to observe guest-shutdown without rebooting"
)]
fn shutdown_behind_a_full_stderr_pipe_still_reaches_the_kernel() {
    // journald has stopped reading and the daemon's stderr pipe is full:
    // the writer thread is blocked inside a write, holding the process's
    // stderr lock. `guest-shutdown` gives its record the bounded grace
    // and then must reach `sync`/`reboot` (#43 §3): nothing on its path
    // may wait on that lock. The fake kernel's reboot returns, so the
    // proof is the next serial command being answered behind it.
    assert!(Agent::has_fake_kernel());
    let mut agent = Agent::spawn_with(SpawnOptions {
        stderr_pipe: true,
        ..SpawnOptions::default()
    });
    agent.fill_stderr_pipe();
    // Records queued behind the full pipe: the writer is now blocked in
    // the sink, not parked.
    for id in 1..=3 {
        assert_eq!(
            agent.request(&format!(r#"{{"execute":"guest-ping","id":{id}}}"#))["id"],
            id
        );
    }
    std::thread::sleep(Duration::from_millis(200));
    let started = std::time::Instant::now();
    agent.send_line(r#"{"execute":"guest-shutdown","arguments":{"mode":"reboot"},"id":9}"#);
    assert!(
        agent.read_line(Duration::from_millis(500)).is_none(),
        "AC12: no success reply"
    );
    // A serial command waits behind the shutdown for its lane: it is
    // answered once the shutdown has run, within the grace plus a margin.
    let reply = agent.request_timeout(
        r#"{"execute":"guest-get-osinfo","id":10}"#,
        Duration::from_secs(15),
    );
    assert_eq!(reply["id"], 10, "{reply}");
    assert!(reply.get("return").is_some(), "{reply}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the shutdown waited beyond its grace: {:?}",
        started.elapsed()
    );
    // The pipe is still full: the daemon never waited for it (one read
    // returns what is there; the write end stays open, so never EOF).
    let mut stderr = agent.take_stderr_pipe().unwrap();
    let mut buf = vec![0u8; 4096];
    let n = std::io::Read::read(&mut stderr, &mut buf).unwrap();
    assert!(n > 0);
    assert!(agent.stop().success());
}

#[test]
fn channel_eof_then_reopen_preserves_state() {
    // A frozen agent without any ioctl (works unprivileged and without
    // fakes): the daemon starts in recovery mode behind a marker left by
    // a previous instance (§4.4). A freeze of zero filesystems would not
    // do: it is a zero-work operation and settles `Thawed` (#43 §2). The
    // idle timeout is raised so the watchdog cannot thaw during the
    // reopen backoff.
    let mut agent = Agent::spawn_with(SpawnOptions {
        recovery_marker: true,
        agent_extra: "fsfreeze_idle_timeout_secs = 300\n".to_owned(),
        ..SpawnOptions::default()
    });
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert!(agent.state_dir().join("frozen").exists(), "marker present");
    let zero =
        agent.request(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":[]}}"#);
    assert_eq!(
        zero["error"]["desc"], "filesystems are frozen; retry after thaw",
        "no second freeze while recovering"
    );
    let osinfo = agent.execute("guest-get-osinfo");
    assert_eq!(
        osinfo["error"]["desc"],
        "filesystems are frozen; retry after thaw"
    );

    // Close the master and reopen a new pty at the same path.
    agent.reopen_channel();
    assert!(agent.is_running());
    assert!(
        agent.state_dir().join("frozen").exists(),
        "marker survives the reconnect"
    );
    let status = agent.request_timeout(
        r#"{"execute":"guest-fsfreeze-status"}"#,
        e2e::REOPEN_TIMEOUT,
    );
    assert_eq!(status["return"], "frozen", "state survives");
    // The frozen gate still applies over the new session (a partial frame
    // left before the EOF is covered by `partial_frame_is_dropped_on_reconnect`).
    let osinfo = agent.execute("guest-get-osinfo");
    assert_eq!(
        osinfo["error"]["desc"],
        "filesystems are frozen; retry after thaw"
    );
    // Thaw completes over the new connection. The drain issues a real
    // `FITHAW` on every planned filesystem (design §4.3), so without
    // CAP_SYS_ADMIN the first call is denied and, per OQ-3, the agent
    // stays `Frozen` with the marker retained; the privileged half of
    // AC18 (a successful thaw) lives in tests/privileged_e2e.rs.
    let thawed = agent.execute("guest-fsfreeze-thaw");
    if thawed.get("return").is_some() {
        assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "thawed");
        assert!(!agent.state_dir().join("frozen").exists());
        // The thaw flushed the audit ring, so both channel events are
        // visible (once the writer thread has delivered them), and a
        // zero-work freeze now settles thawed at once.
        agent.wait_for_stderr("\"event\":\"channel_closed\"", e2e::REPLY_TIMEOUT);
        agent.wait_for_stderr_count("\"event\":\"channel_open\"", 2, e2e::REPLY_TIMEOUT);
        let zero = agent
            .request(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":[]}}"#);
        assert_eq!(zero, json!({"return": 0}));
        assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "thawed");
        assert!(!agent.state_dir().join("frozen").exists(), "no marker left");
        assert!(agent.stop().success());
    } else {
        let desc = thawed["error"]["desc"].as_str().unwrap_or_default();
        assert!(
            desc.contains("EPERM") || desc.contains("EACCES"),
            "unexpected thaw failure: {thawed}"
        );
        assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
        assert!(agent.state_dir().join("frozen").exists(), "marker retained");
        // Still frozen: the audit records are held in the ring and a
        // graceful stop would be deferred, so `Drop` kills the process.
        drop(agent);
    }
}

#[test]
fn partial_frame_is_dropped_on_reconnect() {
    let mut agent = Agent::spawn();
    agent.send(b"{\"execute\":\"guest-pi");
    agent.reopen_channel();
    let reply = agent.request_timeout(r#"{"execute":"guest-ping","id":3}"#, e2e::REOPEN_TIMEOUT);
    assert_eq!(reply, json!({"return": {}, "id": 3}));
    agent.wait_for_stderr("\"event\":\"channel_closed\"", e2e::REPLY_TIMEOUT);
    agent.wait_for_stderr_count("\"event\":\"channel_open\"", 2, e2e::REPLY_TIMEOUT);
    assert!(agent.stop().success());
}
