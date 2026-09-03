//! The shipped packaging files match the design (T5.3): systemd unit
//! (§8.4, C-20), udev rule (§8.3, byte-for-byte), sysusers entry (§5.4),
//! and the example configuration (§8.2).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use qeminga::config::Config;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Parses an INI-style unit into `section -> key -> values` (a key may
/// repeat).
fn parse_unit(text: &str) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut out: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_owned();
            continue;
        }
        let (key, value) = line.split_once('=').expect(line);
        out.entry(section.clone())
            .or_default()
            .entry(key.trim().to_owned())
            .or_default()
            .push(value.trim().to_owned());
    }
    out
}

fn values<'a>(
    unit: &'a BTreeMap<String, BTreeMap<String, Vec<String>>>,
    section: &str,
    key: &str,
) -> Vec<&'a str> {
    unit.get(section)
        .and_then(|s| s.get(key))
        .map(|v| v.iter().flat_map(|x| x.split_whitespace()).collect())
        .unwrap_or_default()
}

/// The fenced block that follows `marker` in docs/design.md.
fn design_block(marker: &str) -> String {
    let design = read("docs/design.md");
    let start = design.find(marker).expect(marker);
    let fence = design[start..].find("```").unwrap() + start;
    let body_start = design[fence..].find('\n').unwrap() + fence + 1;
    let end = design[body_start..].find("```").unwrap() + body_start;
    design[body_start..end].to_owned()
}

#[test]
fn unit_conflicts_with_and_orders_after_qemu_guest_agent() {
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));
    assert!(values(&unit, "Unit", "Conflicts").contains(&"qemu-guest-agent.service"));
    assert!(values(&unit, "Unit", "After").contains(&"qemu-guest-agent.service"));
}

#[test]
fn unit_binds_to_the_virtio_port_device() {
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));
    let device = "dev-virtio\\x2dports-org.qemu.guest_agent.0.device";
    assert!(values(&unit, "Unit", "BindsTo").contains(&device));
    assert!(values(&unit, "Unit", "After").contains(&device));
    assert!(values(&unit, "Unit", "Before").contains(&"multi-user.target"));
}

#[test]
fn unit_provisions_and_preserves_the_runtime_directory() {
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));
    assert_eq!(values(&unit, "Service", "RuntimeDirectory"), ["qeminga"]);
    assert_eq!(
        values(&unit, "Service", "RuntimeDirectoryPreserve"),
        ["yes"]
    );
    assert_eq!(values(&unit, "Service", "Restart"), ["always"]);
    assert_eq!(
        values(&unit, "Service", "Type"),
        ["simple"],
        "no pid file (C-16)"
    );
    let exec = values(&unit, "Service", "ExecStart");
    assert_eq!(exec[0], "/usr/bin/qeminga");
    assert!(exec.contains(&"/etc/qeminga/config.toml"));
    // The daemon drops privileges itself; systemd must not pre-empt it.
    assert!(values(&unit, "Service", "User").is_empty());
    assert!(values(&unit, "Service", "NoNewPrivileges").is_empty());
    let caps = values(&unit, "Service", "CapabilityBoundingSet");
    for needed in [
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_DAC_READ_SEARCH",
        "CAP_SETUID",
        "CAP_SETGID",
        "CAP_SETPCAP",
    ] {
        assert!(caps.contains(&needed), "{needed}");
    }
}

#[test]
fn timeout_stop_exceeds_the_freeze_cap_plus_margin() {
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));
    let stop = values(&unit, "Service", "TimeoutStopSec")[0];
    let secs: u64 = stop.strip_suffix('s').unwrap_or(stop).parse().unwrap();
    let config = Config::parse(&read("packaging/config.toml")).unwrap();
    let cap = config.agent.fsfreeze_max_timeout_secs;
    assert!(
        secs >= cap + 30,
        "TimeoutStopSec={secs} must be >= {cap} + 30 (§8.4)"
    );
    assert_eq!(secs, 330);
}

#[test]
fn udev_rule_matches_design_byte_for_byte() {
    let shipped: String = read("packaging/udev/99-qeminga.rules")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    let design = design_block("udev rule must be installed");
    assert_eq!(shipped, design);
    assert!(shipped.contains("OWNER=\"qeminga\""));
    assert!(shipped.contains("MODE=\"0600\""));
}

#[test]
fn sysusers_creates_qeminga_600_without_login_shell() {
    let text = read("packaging/sysusers.d/qeminga.conf");
    let user = text
        .lines()
        .find(|l| l.starts_with("u "))
        .expect("a `u` line");
    let fields: Vec<&str> = user.split_whitespace().collect();
    assert_eq!(fields[1], "qeminga");
    assert_eq!(fields[2], "600:600");
    assert!(user.ends_with("/usr/sbin/nologin"), "{user}");
    let group = text
        .lines()
        .find(|l| l.starts_with("g "))
        .expect("a `g` line");
    assert_eq!(
        group.split_whitespace().collect::<Vec<_>>(),
        ["g", "qeminga", "600"]
    );
}

#[test]
fn example_config_equals_the_design_block_and_parses() {
    let shipped = read("packaging/config.toml");
    let design = design_block("qeminga reads a TOML configuration file");
    assert_eq!(
        shipped, design,
        "packaging/config.toml must be the §8.2 block"
    );
    let config = Config::parse(&shipped).unwrap();
    assert_eq!(config, Config::default());
    assert_eq!(shipped, read("tests/fixtures/config/default.toml"));
}

#[test]
fn systemd_analyze_verify_accepts_the_unit_when_available() {
    // `systemd-analyze verify` needs the ExecStart binary to exist; CI
    // installs it. Locally, run only when both are present.
    if !Path::new("/usr/bin/qeminga").exists() {
        eprintln!("skipped: /usr/bin/qeminga not installed");
        return;
    }
    let output = match std::process::Command::new("systemd-analyze")
        .args(["verify", "--man=no"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/systemd/qeminga.service"))
        .output()
    {
        Ok(o) => o,
        Err(_) => {
            eprintln!("skipped: systemd-analyze not available");
            return;
        }
    };
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
