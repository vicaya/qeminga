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
fn unit_does_not_bind_to_the_virtio_port_device() {
    // A crash while frozen must be recovered whether or not the port is
    // there (OQ-7): the daemon retries the open itself, so the unit must
    // not be held by the device unit.
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));
    let device = "dev-virtio\\x2dports-org.qemu.guest_agent.0.device";
    assert!(values(&unit, "Unit", "BindsTo").is_empty());
    assert!(values(&unit, "Unit", "Requires").is_empty());
    assert!(!values(&unit, "Unit", "After").contains(&device));
    assert!(values(&unit, "Unit", "Before").contains(&"multi-user.target"));
    assert_eq!(values(&unit, "Service", "Restart"), ["always"]);
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
    // Without User= the runtime directory is created root-owned and 0700;
    // the marker is created after the drop to `qeminga`, so the directory
    // must be handed over first, with full privileges (`+`).
    let pre = values(&unit, "Service", "ExecStartPre");
    assert_eq!(pre[0], "+/usr/bin/chown", "{pre:?}");
    assert_eq!(pre[1], "qeminga:qeminga", "{pre:?}");
    assert_eq!(pre[2], "/run/qeminga", "{pre:?}");
    assert_eq!(values(&unit, "Service", "RuntimeDirectoryMode"), ["0700"]);
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
fn tmpfiles_rule_hands_sys_power_state_to_the_service_account() {
    // OQ-6: after the drop the daemon cannot write the 0644 root:root
    // file; the (optional) rule gives group qeminga write access.
    let text = read("packaging/tmpfiles.d/qeminga-suspend.conf");
    let rules: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(rules.len(), 1, "{rules:?}");
    assert_eq!(
        rules[0].split_whitespace().collect::<Vec<_>>(),
        ["z", "/sys/power/state", "0664", "root", "qeminga", "-"]
    );
    assert!(
        text.contains("suspend_ram = true"),
        "the header says when to install it"
    );
    let readme = read("packaging/README.md");
    assert!(readme.contains("tmpfiles.d/qeminga-suspend.conf"));
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

/// The files the privileged unit test installs, removed on drop (the
/// service stopped first) whatever happened.
struct InstalledUnit {
    backup: Option<std::path::PathBuf>,
}

impl InstalledUnit {
    const UNIT: &'static str = "/run/systemd/system/qeminga.service";
    const DROPIN_DIR: &'static str = "/run/systemd/system/qeminga.service.d";
    const CONFIG: &'static str = "/etc/qeminga/config.toml";
    const BIN: &'static str = "/usr/bin/qeminga";
}

impl Drop for InstalledUnit {
    fn drop(&mut self) {
        // A daemon that never thawed defers SIGTERM (C-21) and the unit's
        // TimeoutStopSec is 330 s: kill first, then stop, so a failed run
        // does not hold the job.
        let _ = std::process::Command::new("systemctl")
            .args(["kill", "--signal=SIGKILL", "qeminga.service"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "qeminga.service"])
            .status();
        let _ = std::fs::remove_file(Self::UNIT);
        let _ = std::fs::remove_dir_all(Self::DROPIN_DIR);
        let _ = std::fs::remove_file(Self::CONFIG);
        let _ = std::fs::remove_file("/run/qeminga/frozen");
        match &self.backup {
            Some(backup) => {
                let _ = std::fs::rename(backup, Self::BIN);
            }
            None => {
                let _ = std::fs::remove_file(Self::BIN);
            }
        }
        let _ = std::process::Command::new("systemctl")
            .args(["daemon-reload"])
            .status();
    }
}

fn sh(program: &str, args: &[&str]) -> (bool, String) {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{program}: {e}"));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

/// The installed unit, not just the binary: a marker from a previous
/// instance and no channel device at all. systemd must start the service
/// (nothing binds it to the device), and the daemon must run its
/// recovery and remove the marker without the port ever appearing
/// (§4.4, OQ-7). Needs root and a running systemd; the built binary is
/// installed as /usr/bin/qeminga for the duration (a previous one is put
/// back), the unit goes under /run/systemd/system.
#[test]
#[ignore = "needs root and a running systemd (installs the shipped unit for the duration)"]
fn privileged_installed_unit_recovers_without_the_channel_device() {
    use std::time::{Duration, Instant};
    assert!(nix::unistd::geteuid().is_root(), "run as root");
    // A container without systemd cannot run this; CI's privileged job
    // sets QEMINGA_REQUIRE_SYSTEMD so the check can never pass vacuously.
    if !Path::new("/run/systemd/system").is_dir() {
        assert!(
            std::env::var_os("QEMINGA_REQUIRE_SYSTEMD").is_none(),
            "systemd is not the running service manager"
        );
        eprintln!("skipped: systemd is not the running service manager");
        return;
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    // Install.
    let backup = Path::new(InstalledUnit::BIN)
        .exists()
        .then(|| std::path::PathBuf::from("/usr/bin/qeminga.qeminga-test-backup"));
    if let Some(backup) = &backup {
        std::fs::rename(InstalledUnit::BIN, backup).unwrap();
    }
    let installed = InstalledUnit { backup };
    std::fs::copy(env!("CARGO_BIN_EXE_qeminga"), InstalledUnit::BIN).unwrap();
    std::fs::set_permissions(
        InstalledUnit::BIN,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .unwrap();
    let (ok, text) = sh(
        "systemd-sysusers",
        &[repo
            .join("packaging/sysusers.d/qeminga.conf")
            .to_str()
            .unwrap()],
    );
    assert!(ok, "{text}");
    std::fs::create_dir_all("/etc/qeminga").unwrap();
    std::fs::write(
        InstalledUnit::CONFIG,
        "[agent]\nchannel_path = \"/dev/virtio-ports/qeminga-test-no-such-port\"\nfsfreeze_idle_timeout_secs = 1\n",
    )
    .unwrap();
    std::fs::copy(
        repo.join("packaging/systemd/qeminga.service"),
        InstalledUnit::UNIT,
    )
    .unwrap();
    std::fs::create_dir_all(InstalledUnit::DROPIN_DIR).unwrap();
    // The fake kernel (test-fakes builds): the recovery drain issues no
    // real ioctl. A build without the feature ignores the variable and
    // drains with real FITHAWs, which answer EINVAL on an unfrozen host.
    std::fs::write(
        Path::new(InstalledUnit::DROPIN_DIR).join("50-test.conf"),
        "[Service]\nEnvironment=QEMINGA_TEST_FAKE_KERNEL=1\nTimeoutStopSec=15s\n",
    )
    .unwrap();
    // The marker of a previous instance, in the preserved runtime directory.
    std::fs::create_dir_all("/run/qeminga").unwrap();
    std::fs::write("/run/qeminga/frozen", b"").unwrap();
    let (ok, text) = sh("systemctl", &["daemon-reload"]);
    assert!(ok, "{text}");
    let (_, fragment) = sh(
        "systemctl",
        &["show", "-p", "FragmentPath", "--value", "qeminga.service"],
    );
    assert_eq!(
        fragment.trim(),
        InstalledUnit::UNIT,
        "another qeminga.service shadows the test copy"
    );
    let _ = sh("systemctl", &["reset-failed", "qeminga.service"]);
    let started = Instant::now();
    let (ok, text) = sh("systemctl", &["start", "--no-block", "qeminga.service"]);
    assert!(ok, "systemctl start: {text}");
    // Recovery: the service is active with no device, the open was
    // deferred, the watchdog drained and the marker is gone.
    let journal = || {
        sh(
            "journalctl",
            &[
                "-u",
                "qeminga.service",
                "--no-pager",
                "-o",
                "cat",
                "--since",
                "-2min",
            ],
        )
        .1
    };
    let deadline = started + Duration::from_secs(30);
    let mut log = String::new();
    while Instant::now() < deadline {
        log = journal();
        if !Path::new("/run/qeminga/frozen").exists()
            && log.contains("\"event\":\"channel_open_deferred\"")
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    // Everything a failure needs to be understood from the CI log: the
    // unit's view, the process's capabilities and where it is blocked,
    // the runtime directory, and the journal with its metadata.
    let diagnose = || {
        let (_, status) = sh(
            "systemctl",
            &["status", "--no-pager", "-l", "qeminga.service"],
        );
        let (_, show) = sh(
            "systemctl",
            &[
                "show",
                "-p",
                "ExecMainPID,Environment,CapabilityBoundingSet,Result,NRestarts",
                "qeminga.service",
            ],
        );
        let (_, pid) = sh(
            "systemctl",
            &["show", "-p", "MainPID", "--value", "qeminga.service"],
        );
        let pid = pid.trim().to_owned();
        let proc_ =
            |name: &str| std::fs::read_to_string(format!("/proc/{pid}/{name}")).unwrap_or_default();
        let tasks = std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|t| {
                        let tid = t.file_name().to_string_lossy().into_owned();
                        let stack =
                            std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stack"))
                                .unwrap_or_default();
                        let wchan =
                            std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/wchan"))
                                .unwrap_or_default();
                        format!("task {tid} wchan={wchan}\n{stack}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let (_, journal_full) = sh(
            "journalctl",
            &[
                "-u",
                "qeminga.service",
                "--no-pager",
                "-o",
                "short-precise",
                "--since",
                "-2min",
            ],
        );
        let (_, runtime_dir) = sh("ls", &["-la", "/run/qeminga"]);
        format!(
            "== systemctl status\n{status}\n== systemctl show\n{show}\n== /proc/{pid}/status\n{}\n== stderr target\n{}\n== tasks\n{tasks}\n== /run/qeminga\n{runtime_dir}\n== journal\n{journal_full}",
            proc_("status"),
            std::fs::read_link(format!("/proc/{pid}/fd/2"))
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        )
    };
    let (_, active) = sh("systemctl", &["is-active", "qeminga.service"]);
    assert_eq!(
        active.trim(),
        "active",
        "the service is held back:\n{}",
        diagnose()
    );
    assert!(
        log.contains("\"event\":\"channel_open_deferred\""),
        "no deferred open in the journal (marker present: {}):\n{}",
        Path::new("/run/qeminga/frozen").exists(),
        diagnose()
    );
    assert!(
        log.contains("\"recovery\":true"),
        "not started in recovery mode: {log}"
    );
    assert!(
        !Path::new("/run/qeminga/frozen").exists(),
        "the marker was not recovered with no channel: {log}"
    );
    assert!(
        log.contains("\"event\":\"watchdog_thaw\"")
            || log.contains("\"event\":\"fsfreeze_thawed\""),
        "no drain in the journal: {log}"
    );
    // And it stops while the port is still missing.
    let (ok, text) = sh("systemctl", &["stop", "qeminga.service"]);
    assert!(ok, "systemctl stop: {text}");
    let (_, active) = sh("systemctl", &["is-active", "qeminga.service"]);
    assert_ne!(active.trim(), "active");
    drop(installed);
}
