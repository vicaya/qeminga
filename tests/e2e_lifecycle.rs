//! End-to-end: shutdown silence (AC12) and channel reopen during a freeze
//! (AC18, unprivileged half).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

use e2e::Agent;
use serde_json::json;
use std::time::Duration;

#[test]
fn shutdown_emits_no_reply() {
    if !Agent::has_fake_kernel() {
        eprintln!("skipped: build with --features test-fakes to observe guest-shutdown");
        return;
    }
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
    let stderr = agent.stderr_text();
    assert!(stderr.contains("\"method\":\"guest-shutdown\""));
    assert!(stderr.contains("\"event\":\"fake_kernel\""));
    // Errors are still reported: the shutdown class allows 2/min.
    agent.send_line(r#"{"execute":"guest-shutdown"}"#);
    assert!(agent.read_line(Duration::from_millis(500)).is_none());
    let third = agent.execute("guest-shutdown");
    assert_eq!(third["error"]["desc"], "rate limit exceeded for shutdown");
    assert!(agent.stop().success());
}

#[test]
fn channel_eof_then_reopen_preserves_state() {
    let mut agent = Agent::spawn();
    // Freeze zero filesystems: no ioctl needed, but the state becomes
    // Frozen and the marker exists (works unprivileged and without fakes).
    let frozen =
        agent.request(r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":[]}}"#);
    assert_eq!(frozen, json!({"return": 0}));
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert!(agent.state_dir().join("frozen").exists(), "marker present");
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
    // A partial frame before the EOF must not leak into the new session.
    let osinfo = agent.execute("guest-get-osinfo");
    assert_eq!(
        osinfo["error"]["desc"],
        "filesystems are frozen; retry after thaw"
    );
    // Thaw completes over the new connection.
    let thawed = agent.execute("guest-fsfreeze-thaw");
    assert!(thawed.get("return").is_some(), "{thawed}");
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "thawed");
    assert!(!agent.state_dir().join("frozen").exists());
    let stderr = agent.stderr_text();
    assert!(stderr.contains("\"event\":\"channel_closed\""));
    assert_eq!(stderr.matches("\"event\":\"channel_open\"").count(), 2);
    assert!(agent.stop().success());
}

#[test]
fn partial_frame_is_dropped_on_reconnect() {
    let mut agent = Agent::spawn();
    agent.send(b"{\"execute\":\"guest-pi");
    agent.reopen_channel();
    let reply = agent.request_timeout(r#"{"execute":"guest-ping","id":3}"#, e2e::REOPEN_TIMEOUT);
    assert_eq!(reply, json!({"return": {}, "id": 3}));
    let stderr = agent.stderr_text();
    assert!(stderr.contains("\"event\":\"channel_closed\""), "{stderr}");
    assert_eq!(stderr.matches("\"event\":\"channel_open\"").count(), 2);
    assert!(agent.stop().success());
}
