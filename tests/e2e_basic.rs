//! End-to-end: protocol basics through the real binary (AC1, AC4, AC19).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

use e2e::{Agent, DENIED};
use serde_json::{Value, json};

#[test]
fn ping_round_trip() {
    let mut agent = Agent::spawn();
    assert_eq!(
        agent.request(r#"{"execute":"guest-ping","id":1}"#),
        json!({"return": {}, "id": 1})
    );
    assert_eq!(agent.execute("guest-ping"), json!({"return": {}}));
    let status = agent.stop();
    assert!(status.success(), "{status}");
}

#[test]
fn sync_delimited_resyncs_after_garbage() {
    let mut agent = Agent::spawn();
    agent.send(b"garbage");
    agent.send(b"\xFF{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":1}}\n");
    let raw = agent.read_line(e2e::REPLY_TIMEOUT).expect("reply");
    assert_eq!(raw[0], 0xFF, "sentinel-prefixed reply: {raw:?}");
    let value: Value = serde_json::from_slice(&raw[1..]).unwrap();
    assert_eq!(value, json!({"return": 1}));
    // Plain sync has no sentinel.
    let raw = agent.request_raw(r#"{"execute":"guest-sync","arguments":{"id":2}}"#);
    assert_eq!(raw, b"{\"return\":2}");
    assert!(agent.stop().success());
}

#[test]
fn guest_exec_and_every_denied_command_return_command_not_found() {
    let mut agent = Agent::spawn();
    for method in DENIED {
        let reply = agent.execute(method);
        assert_eq!(
            reply["error"]["class"], "CommandNotFound",
            "{method}: {reply}"
        );
        assert_eq!(
            reply["error"]["desc"],
            format!("The command {method} has not been found")
        );
    }
    let reply = agent.request(r#"{"execute":"guest-exec","arguments":{"path":"/bin/sh"},"id":7}"#);
    assert_eq!(reply["error"]["class"], "CommandNotFound");
    assert_eq!(reply["id"], 7);
    assert!(agent.execute("guest-ping").get("return").is_some());
    agent.wait_for_stderr_count(
        "\"reason\":\"command_not_found\"",
        DENIED.len() + 1,
        e2e::REPLY_TIMEOUT,
    );
    assert!(agent.stop().success());
}

#[test]
fn oversized_frame_then_valid_command() {
    let mut agent = Agent::spawn();
    let mut blob = vec![b'x'; 65_537];
    blob.push(b'\n');
    agent.send(&blob);
    // Nothing is replied to the blob; the next command is handled.
    assert_eq!(
        agent.request(r#"{"execute":"guest-ping","id":2}"#),
        json!({"return": {}, "id": 2})
    );
    assert!(
        agent
            .read_line(std::time::Duration::from_millis(200))
            .is_none()
    );
    agent.wait_for_stderr("\"reason\":\"oversized_frame\"", e2e::REPLY_TIMEOUT);
    // An exactly-64 KiB frame is parsed (and rejected as JSON, not as size).
    let mut exact = vec![b'y'; 65_536];
    exact.push(b'\n');
    agent.send(&exact);
    let reply: Value =
        serde_json::from_slice(&agent.read_line(e2e::REPLY_TIMEOUT).unwrap()).unwrap();
    assert_eq!(reply["error"]["class"], "GenericError");
    assert!(agent.stop().success());
}

#[test]
fn guest_info_matches_capability_contract() {
    let mut agent = Agent::spawn();
    let info = agent.execute("guest-info");
    let ret = &info["return"];
    assert_eq!(ret["version"], qeminga::VERSION);
    let commands = ret["supported_commands"].as_array().unwrap();
    assert_eq!(commands.len(), 14);
    let mut names: Vec<&str> = commands
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 14);
    for c in commands {
        let obj = c.as_object().unwrap();
        assert_eq!(obj.len(), 3, "{c}");
        assert!(obj["enabled"].is_boolean());
        assert!(obj["success-response"].is_boolean());
    }
    let shutdown = commands
        .iter()
        .find(|c| c["name"] == "guest-shutdown")
        .unwrap();
    assert_eq!(shutdown["success-response"], false);
    let suspend = commands
        .iter()
        .find(|c| c["name"] == "guest-suspend-ram")
        .unwrap();
    assert_eq!(suspend["enabled"], false, "opt-in, off by default");
    assert_eq!(
        suspend["success-response"], false,
        "upstream contract: no reply after a suspend (OQ-2)"
    );
    assert_eq!(
        commands
            .iter()
            .filter(|c| c["success-response"] == false)
            .count(),
        2,
        "shutdown and suspend-ram are the only commands without a success reply"
    );
    for method in DENIED {
        assert!(!commands.iter().any(|c| c["name"] == *method), "{method}");
    }
    assert!(agent.stop().success());
}

#[test]
fn guest_get_osinfo_and_interfaces_and_fsinfo_return_well_formed_json() {
    let mut agent = Agent::spawn();
    let os = agent.execute("guest-get-osinfo");
    let os = os["return"].as_object().unwrap();
    for key in ["kernel-release", "kernel-version", "machine"] {
        assert!(os[key].is_string(), "{key}");
    }
    let allowed = [
        "kernel-release",
        "kernel-version",
        "machine",
        "id",
        "name",
        "pretty-name",
        "version",
        "version-id",
        "variant",
        "variant-id",
    ];
    for key in os.keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "unexpected osinfo key {key}"
        );
        assert!(os[key].is_string());
    }
    assert!(!os.contains_key("machine-id"));

    let ifaces = agent.execute("guest-network-get-interfaces");
    for iface in ifaces["return"].as_array().unwrap() {
        assert!(iface["name"].is_string());
        assert_ne!(iface["name"], "lo");
        for addr in iface["ip-addresses"].as_array().unwrap() {
            let ip: std::net::IpAddr = addr["ip-address"].as_str().unwrap().parse().unwrap();
            assert!(!ip.is_loopback());
            let ty = addr["ip-address-type"].as_str().unwrap();
            assert!(ty == "ipv4" || ty == "ipv6");
            assert!(addr["prefix"].as_u64().unwrap() <= 128);
        }
    }

    let fs = agent.execute("guest-get-fsinfo");
    let entries = fs["return"].as_array().unwrap();
    assert!(!entries.is_empty());
    for e in entries {
        assert!(e["name"].is_string());
        assert!(e["mountpoint"].is_string());
        assert!(e["type"].is_string());
        assert_eq!(e["disk"], json!([]));
    }
    assert!(entries.iter().any(|e| e["mountpoint"] == "/"));
    assert!(agent.stop().success());
}
