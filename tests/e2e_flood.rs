//! End-to-end: AC5, a 1000-ping flood in one write is rate-limited and
//! the daemon keeps serving.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

use e2e::Agent;
use serde_json::Value;
use std::time::{Duration, Instant};

#[test]
fn flood_of_1000_pings_within_one_second_is_rate_limited_and_status_still_served() {
    let mut agent = Agent::spawn();
    let flood: Vec<u8> = (0..1000)
        .flat_map(|i| format!("{{\"execute\":\"guest-ping\",\"id\":{i}}}\n").into_bytes())
        .collect();
    let started = Instant::now();
    agent.send(&flood);
    let mut ok = 0;
    let mut denied = 0;
    for _ in 0..1000 {
        let line = agent
            .read_line(Duration::from_secs(20))
            .expect("1000 replies");
        let value: Value = serde_json::from_slice(&line).unwrap();
        if value.get("return").is_some() {
            ok += 1;
        } else {
            assert_eq!(value["error"]["class"], "GenericError", "{value}");
            assert_eq!(value["error"]["desc"], "rate limit exceeded for ping_sync");
            denied += 1;
        }
    }
    let elapsed = started.elapsed();
    // 120 tokens plus at most one refill per 500 ms of wall-clock time: a
    // slow runner may legitimately admit more than 120, so the bound
    // scales with elapsed time rather than assuming the fake-clock figure
    // (≥ 880 denials) of the T1.7 unit test.
    let max_ok = 120 + (elapsed.as_millis() / 500) as usize + 1;
    assert!(ok <= max_ok, "ok={ok} denied={denied} elapsed={elapsed:?}");
    assert_eq!(denied, 1000 - ok, "every frame was answered exactly once");
    assert!(ok >= 120, "the bucket's 120 tokens are admitted: ok={ok}");
    // The unlimited class is unaffected and the daemon is healthy.
    let status = agent.execute("guest-fsfreeze-status");
    assert_eq!(status["return"], "thawed");
    // The thaw is a recovery drain from Thawed: with CAP_SYS_ADMIN it
    // succeeds; unprivileged (CI runner) FITHAW is denied, which is
    // reported but leaves the state Thawed.
    let thaw = agent.execute("guest-fsfreeze-thaw");
    assert!(
        thaw.get("return").is_some()
            || thaw["error"]["desc"]
                .as_str()
                .unwrap_or("")
                .contains("EPERM"),
        "{thaw}"
    );
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "thawed");
    assert!(agent.stop().success());
}
