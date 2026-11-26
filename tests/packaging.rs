//! The shipped packaging files match the design (T5.3): systemd unit
//! (§8.4, C-20), udev rule (§8.3, byte-for-byte), sysusers entry (§5.4),
//! and the example configuration (§8.2).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

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
fn unit_provisions_the_state_directory_for_the_service_account() {
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));
    assert_eq!(values(&unit, "Service", "Restart"), ["always"]);
    assert_eq!(
        values(&unit, "Service", "Type"),
        ["simple"],
        "no pid file (C-16)"
    );
    let exec = values(&unit, "Service", "ExecStart");
    assert_eq!(exec[0], "/usr/bin/qeminga");
    assert!(exec.contains(&"/etc/qeminga/config.toml"));
    // The marker is created and removed after the drop to `qeminga`, so
    // the directory must belong to that account before ExecStart, with
    // full privileges (`+`). RuntimeDirectory= must not be used: with no
    // User= systemd re-applies root ownership before every ExecStart and
    // undoes the hand-over (found by the installed-unit test below).
    let pre = values(&unit, "Service", "ExecStartPre");
    assert_eq!(
        pre,
        [
            "+/usr/bin/mkdir",
            "-p",
            "/run/qeminga",
            "+/usr/bin/chown",
            "qeminga:qeminga",
            "/run/qeminga",
            "+/usr/bin/chmod",
            "0700",
            "/run/qeminga",
        ],
        "{pre:?}"
    );
    for key in [
        "RuntimeDirectory",
        "RuntimeDirectoryMode",
        "RuntimeDirectoryPreserve",
    ] {
        assert!(
            values(&unit, "Service", key).is_empty(),
            "{key} must not be set"
        );
    }
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
fn unit_constrains_filesystem_writes_to_marker_directory() {
    // #66: the packaged unit remounts the filesystem hierarchy read-only
    // (ProtectSystem=strict + ProtectHome=read-only, MNT_READONLY — compatible
    // with FIFREEZE on O_RDONLY|O_DIRECTORY handles including separate /home
    // mounts), punches only -/run/qeminga for ordinary file writes (with `-`
    // so ExecStartPre=+ can create an absent directory on cold start), locks
    // /sys and /dev (plus every filesystem already mounted beneath /dev, such
    // as /dev/shm and /dev/mqueue) recursively read-only via
    // BindReadOnlyPaths=/sys /dev while keeping character-device O_RDWR open
    // and reopen working, locks /run, prevents remounting via ~@mount, sets
    // UMask=0077, and deliberately keeps PrivateTmp=no and PrivateDevices
    // unset so real /tmp and /dev/virtio-ports stay reachable.
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));
    assert_eq!(values(&unit, "Service", "ProtectSystem"), ["strict"]);
    assert_eq!(
        values(&unit, "Service", "ReadWritePaths"),
        ["-/run/qeminga"]
    );
    assert_eq!(values(&unit, "Service", "ProtectKernelTunables"), ["yes"]);
    let bro = values(&unit, "Service", "BindReadOnlyPaths");
    assert!(bro.contains(&"/sys"), "{bro:?}");
    assert!(bro.contains(&"/dev"), "{bro:?}");
    let ro = values(&unit, "Service", "ReadOnlyPaths");
    assert!(ro.contains(&"/run"), "{ro:?}");
    let sc = values(&unit, "Service", "SystemCallFilter");
    assert!(sc.contains(&"~@mount"), "{sc:?}");
    assert_eq!(values(&unit, "Service", "UMask"), ["0077"]);
    assert_eq!(values(&unit, "Service", "PrivateTmp"), ["no"]);
    assert_eq!(values(&unit, "Service", "ProtectHome"), ["read-only"]);
    assert!(
        values(&unit, "Service", "PrivateDevices").is_empty(),
        "PrivateDevices=yes would hide /dev/virtio-ports/org.qemu.guest_agent.0"
    );
}

#[test]
fn packaging_docs_cover_write_confinement_custom_marker_suspend_and_baseline() {
    // #66: inventory writable objects during startup and after drop,
    // residual writable locations, custom state_path drop-in with its
    // trusted-parent requirement, optional suspend_ram
    // ReadWritePaths=/sys/power/state drop-in, and the supported systemd
    // baseline.
    let readme = read("packaging/README.md");
    let suspend_tmpfiles = read("packaging/tmpfiles.d/qeminga-suspend.conf");
    let design = read("docs/design.md");
    for needle in [
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=-/run/qeminga",
        "ProtectKernelTunables=yes",
        "BindReadOnlyPaths=/sys /dev",
        "ReadOnlyPaths=/run",
        "~@mount",
        "UMask=0077",
        "ReadWritePaths=/sys/power/state",
        "ReadWritePaths=-/run/custom-qeminga",
        "ExecStartPre=",
        "state_path",
        "systemd 245",
        "PrivateTmp=no",
        "PrivateDevices",
    ] {
        assert!(
            readme.contains(needle),
            "packaging/README.md missing {needle:?}"
        );
    }
    let lower_readme = readme.to_ascii_lowercase();
    assert!(
        lower_readme.contains("during privileged startup")
            && lower_readme.contains("after privilege drop")
            && lower_readme.contains("residual writable"),
        "packaging/README.md must inventory startup, post-drop, and residual writable locations"
    );
    assert!(
        lower_readme.contains("system-manager mount namespace")
            && lower_readme.contains("after the service starts")
            && !lower_readme.contains("mounted on the host"),
        "packaging/README.md must document guest system-manager mount propagation of post-start mounts without calling the guest 'the host'"
    );
    assert!(
        !readme.contains("ReadOnlyPaths=/run -/dev/shm"),
        "packaging/README.md must not retain stale ReadOnlyPaths=/run -/dev/shm directives"
    );
    assert!(
        lower_readme.contains("ancestor")
            && lower_readme.contains("entire lifetime")
            && readme.contains("Marker::open")
            && !lower_readme.contains("fchown"),
        "packaging/README.md must require lifetime trusted ancestry across ExecStartPre, ReadWritePaths, and Marker::open without a mutable-ancestry workaround"
    );
    assert!(
        suspend_tmpfiles.contains("ReadWritePaths=/sys/power/state")
            && suspend_tmpfiles.contains("BindReadOnlyPaths=/sys"),
        "packaging/tmpfiles.d/qeminga-suspend.conf must note BindReadOnlyPaths=/sys and ReadWritePaths=/sys/power/state"
    );
    for needle in [
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=-/run/qeminga",
        "ProtectKernelTunables=yes",
        "BindReadOnlyPaths=/sys /dev",
        "ReadOnlyPaths=/run",
        "SystemCallFilter=~@mount",
        "ReadWritePaths=/sys/power/state",
        "systemd 245",
    ] {
        assert!(design.contains(needle), "docs/design.md missing {needle:?}");
    }
    let lower_design = design.to_ascii_lowercase();
    assert!(
        lower_design.contains("ancestor")
            && lower_design.contains("entire lifetime")
            && design.contains("Marker::open")
            && !lower_design.contains("before ownership/mode changes"),
        "docs/design.md §8.4 must require lifetime trusted ancestry for custom state_path without a mutable-ancestry workaround"
    );
}

#[test]
fn tmpfiles_rule_provisions_the_state_directory_at_boot() {
    // C-20: /run is cleared at boot; the directory the dropped daemon
    // creates its marker in must exist and belong to the service account.
    let text = read("packaging/tmpfiles.d/qeminga.conf");
    let rules: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(rules.len(), 1, "{rules:?}");
    assert_eq!(
        rules[0].split_whitespace().collect::<Vec<_>>(),
        ["d", "/run/qeminga", "0700", "qeminga", "qeminga", "-"]
    );
    let readme = read("packaging/README.md");
    assert!(readme.contains("tmpfiles.d/qeminga.conf"));
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
fn data_protection_example_parses_and_keeps_only_the_snapshot_authority() {
    // #43 §5: the shipped data-protection configuration is valid, enforced,
    // and grants no reboot, information or trim authority.
    let config =
        qeminga::config::Config::parse(&read("packaging/config-data-protection.toml")).unwrap();
    assert!(config.agent.hardening.is_enforced());
    assert!(config.features.seccomp);
    assert_eq!(
        config.authority(),
        qeminga::config::Authority::data_protection()
    );
    assert!(!config.shutdown_enabled());
    assert!(!config.information_enabled());
    assert!(!config.fstrim_enabled());
    // Everything not about authority equals the default.
    let mut expected = qeminga::config::Config::default();
    expected.features.shutdown = false;
    expected.features.information = false;
    expected.features.fstrim = false;
    assert_eq!(config, expected);
}

#[test]
fn cvm_installation_defaults_to_data_protection_profile_and_documents_single_freezer() {
    // #53 CVM release blockers (AC27): the documented installation ships
    // the data-protection profile as the CVM default (disabling inventory
    // and trim together), warns that guest-fstrim discloses eligible mount
    // paths even when information = false, and states the v1 single-freezer
    // assumption explicitly.
    let readme = read("packaging/README.md");
    let start = readme
        .find("To migrate by hand:")
        .expect("installation section");
    let fence = readme[start..].find("```").unwrap() + start;
    let body_start = readme[fence..].find('\n').unwrap() + fence + 1;
    let end = readme[body_start..].find("```").unwrap() + body_start;
    let install = &readme[body_start..end];
    assert!(
        install.contains("packaging/config-data-protection.toml /etc/qeminga/config.toml"),
        "default install command must install config-data-protection.toml:\n{install}"
    );
    assert!(
        !install.contains("packaging/config.toml /etc/qeminga/config.toml"),
        "default install command must not install the full lifecycle config.toml:\n{install}"
    );
    assert!(
        install.contains("packaging/tmpfiles.d/qeminga.conf")
            && install.contains("systemd-tmpfiles --create"),
        "default install command must provision tmpfiles.d/qeminga.conf:\n{install}"
    );
    assert!(
        readme.contains("fstrim")
            && readme.contains("information = false")
            && readme.contains("mount paths"),
        "packaging/README.md must warn that guest-fstrim discloses mount paths even when information = false"
    );
    let lower = readme.to_ascii_lowercase();
    assert!(
        lower.contains("single freezer") || lower.contains("single-freezer"),
        "packaging/README.md must state the v1 single-freezer assumption for CVMs"
    );
    assert!(
        readme.contains("EBUSY") && readme.contains("independent"),
        "packaging/README.md must explain the independent-freezer / EBUSY / recovery-drain hazard"
    );
    assert!(
        readme.contains("single reply") && readme.contains("fs-N"),
        "packaging/README.md must document that fs-N is valid only within one reply"
    );
    assert!(
        lower.contains("mount-binding") && readme.contains("intended volume"),
        "packaging/README.md must state the v1 mount-binding assumption"
    );
}

#[test]
fn documented_cvm_capabilities_files_and_sockets_match_executable_profile() {
    // #65: operator guidance in docs/design.md (§5.5, §5.9, §12) and
    // packaging/README.md must agree with the shipped executable policy
    // (packaging/systemd/qeminga.service, packaging/config*.toml,
    // src/config.rs, src/kernel/caps.rs, src/seccomp.rs, src/lib.rs).
    use std::collections::BTreeSet;

    let design = read("docs/design.md");
    let packaging = read("packaging/README.md");
    let unit = parse_unit(&read("packaging/systemd/qeminga.service"));

    let dp_cfg = Config::parse(&read("packaging/config-data-protection.toml")).unwrap();
    let gen_cfg = Config::parse(&read("packaging/config.toml")).unwrap();
    let empty_cfg = Config::parse("").unwrap();
    let dp_auth = dp_cfg.authority();
    let gen_auth = gen_cfg.authority();
    let empty_auth = empty_cfg.authority();
    assert_eq!(
        empty_auth, gen_auth,
        "empty TOML defaults must still match the general-VM lifecycle authority"
    );

    let cap_names = |auth: &qeminga::config::Authority| -> BTreeSet<String> {
        qeminga::kernel::caps::final_capability_set(auth)
            .into_iter()
            .map(|c| format!("{c:?}"))
            .collect()
    };
    let dp_caps = cap_names(&dp_auth);
    let gen_caps = cap_names(&gen_auth);
    let dropped_in_dp: BTreeSet<&String> = gen_caps.difference(&dp_caps).collect();
    assert!(
        dropped_in_dp.iter().any(|c| c.as_str() == "CAP_SYS_BOOT"),
        "expected CAP_SYS_BOOT to be dropped in data-protection profile: {dp_caps:?} vs {gen_caps:?}"
    );

    // Extract §5.9 up to §5.10 so assertions target the authority section.
    let s59_start = design
        .find("### 5.9 Authority Follows the Configuration")
        .expect("design §5.9");
    let s59_end = design[s59_start..]
        .find("### 5.10 ")
        .map(|off| s59_start + off)
        .expect("design §5.10");
    let s59 = &design[s59_start..s59_end];

    let readme = read("README.md");
    let normalize_ws = |s: &str| -> String { s.split_whitespace().collect::<Vec<_>>().join(" ") };

    // 1. Compare unit filesystem-confinement settings against docs/design.md
    //    §5.9, packaging/README.md (specifically the compromised-parser
    //    "Ordinary file writes" summary, not only the earlier write-confinement
    //    section), and README.md so changing the unit without updating every
    //    doc (or leaving stale unconfined wording) fails.
    let ordinary_writes_start = packaging
        .find("*Ordinary file writes:*")
        .expect("Ordinary file writes paragraph in packaging/README.md");
    let ordinary_writes_end = packaging[ordinary_writes_start..]
        .find("*Sockets and IPC:*")
        .map(|off| ordinary_writes_start + off)
        .expect("Sockets and IPC paragraph in packaging/README.md");
    let ordinary_writes_norm = normalize_ws(&packaging[ordinary_writes_start..ordinary_writes_end]);
    let s59_norm = normalize_ws(s59);
    let packaging_norm = normalize_ws(&packaging);
    let readme_norm = normalize_ws(&readme);

    let single_value_keys = [
        "ProtectSystem",
        "ProtectHome",
        "PrivateTmp",
        "ReadWritePaths",
        "ProtectKernelTunables",
        "ReadOnlyPaths",
        "SystemCallFilter",
        "UMask",
    ];
    let mut unit_directives: Vec<String> = Vec::new();
    for key in single_value_keys {
        let vals = values(&unit, "Service", key);
        assert_eq!(
            vals.len(),
            1,
            "qeminga.service must specify exactly one {key}= value: {vals:?}"
        );
        unit_directives.push(format!("{key}={}", vals[0]));
    }
    let bro_vals = values(&unit, "Service", "BindReadOnlyPaths");
    assert_eq!(
        bro_vals.len(),
        2,
        "qeminga.service BindReadOnlyPaths must list /sys and /dev: {bro_vals:?}"
    );
    unit_directives.push(format!("BindReadOnlyPaths={}", bro_vals.join(" ")));

    for directive in &unit_directives {
        for (name, text) in [
            ("docs/design.md §5.9", &s59_norm),
            (
                "packaging/README.md (*Ordinary file writes:*)",
                &ordinary_writes_norm,
            ),
            ("README.md", &readme_norm),
        ] {
            assert!(
                text.contains(directive.as_str()),
                "{name} must match shipped unit directive `{directive}`"
            );
        }
    }
    for (name, text) in [
        ("docs/design.md §5.9", &s59_norm),
        (
            "packaging/README.md (*Ordinary file writes:*)",
            &ordinary_writes_norm,
        ),
        ("README.md", &readme_norm),
    ] {
        assert!(
            !text.contains("ProtectSystem=no")
                && !text.contains("ProtectHome=no")
                && !text.contains("does not yet enforce a read-only filesystem namespace")
                && !text.contains("does not yet confine writes")
                && !text.contains("world-writable directories such as /tmp"),
            "{name} must not retain stale unconfined-unit wording"
        );
    }
    assert!(
        !packaging_norm.contains("ProtectSystem=no")
            && !packaging_norm.contains("does not yet confine writes"),
        "packaging/README.md must not retain stale ProtectSystem=no or unconfined-unit wording"
    );

    // 2. Parse the §5.9 profile comparison table column-by-column and compare
    //    each profile cell against the corresponding config's derived authority.
    let split_md_cells = |line: &str| -> Vec<String> {
        let mut cells = Vec::new();
        let mut cur = String::new();
        let mut escaped = false;
        for ch in line.trim_matches('|').chars() {
            if escaped {
                cur.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '|' {
                cells.push(cur.trim().to_owned());
                cur.clear();
            } else {
                cur.push(ch);
            }
        }
        if escaped {
            cur.push('\\');
        }
        cells.push(cur.trim().to_owned());
        cells
    };
    let table_rows: Vec<Vec<String>> = s59
        .lines()
        .filter(|l| l.starts_with('|'))
        .map(split_md_cells)
        .collect();
    let header = table_rows.first().expect("§5.9 profile comparison header");
    assert_eq!(header.len(), 3, "expected 3-column table: {header:?}");
    assert!(
        header[1].contains("config-data-protection.toml") && header[2].contains("config.toml"),
        "§5.9 table columns must be CVM (col 1) and general-VM (col 2): {header:?}"
    );

    let row_by_prefix = |prefix: &str| -> &[String] {
        table_rows
            .iter()
            .find(|r| r.len() == 3 && r[0].starts_with(prefix))
            .unwrap_or_else(|| panic!("missing §5.9 table row starting with `{prefix}`"))
    };

    let cap_row = row_by_prefix("Post-drop UID/GID and capabilities");
    let (cvm_caps_cell, gen_caps_cell) = (cap_row[1].as_str(), cap_row[2].as_str());
    for set in ["CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"] {
        assert!(
            cvm_caps_cell.contains(set) && gen_caps_cell.contains(set),
            "§5.9 capability cells must name all five sets ({set}): CVM={cvm_caps_cell:?} GEN={gen_caps_cell:?}"
        );
    }
    for cap in &dp_caps {
        assert!(
            cvm_caps_cell.contains(cap.as_str()),
            "CVM capability cell must include {cap}: {cvm_caps_cell}"
        );
    }
    for cap in &dropped_in_dp {
        assert!(
            cvm_caps_cell.contains(&format!("`{cap}` absent")),
            "CVM capability cell must state `{cap}` is absent: {cvm_caps_cell}"
        );
        assert!(
            !gen_caps_cell.contains(&format!("`{cap}` absent")),
            "general-VM capability cell must not claim `{cap}` is absent: {gen_caps_cell}"
        );
    }
    for cap in &gen_caps {
        assert!(
            gen_caps_cell.contains(cap.as_str()),
            "general-VM capability cell must include {cap}: {gen_caps_cell}"
        );
    }

    let seccomp_row = row_by_prefix("Seccomp filter differences");
    assert!(!dp_auth.information && gen_auth.information);
    assert!(
        seccomp_row[1].contains("Omits")
            && seccomp_row[1].contains("`socket`")
            && seccomp_row[1].contains("SOCK_STREAM")
            && seccomp_row[1].contains("peerless `recvfrom`")
            && seccomp_row[1].contains("peerless `sendto`"),
        "CVM seccomp cell must distinguish omitted socket from narrowed socketpair and peerless sendto/recvfrom: {}",
        seccomp_row[1]
    );
    assert!(
        seccomp_row[2].contains("AF_NETLINK")
            && seccomp_row[2].contains("NETLINK_ROUTE")
            && seccomp_row[2].contains("addrlen == 12"),
        "general-VM seccomp cell must describe NETLINK_ROUTE and inventory sendto rules: {}",
        seccomp_row[2]
    );

    // 3. CVM installation default vs. TOML schema defaults must stay distinct.
    assert!(
        s59.contains("CVM installation default vs. TOML schema defaults")
            && s59.contains("default to `true`")
            && packaging.contains("Custom CVM configs must disable features explicitly")
            && packaging.contains("default to `true`"),
        "both docs/design.md §5.9 and packaging/README.md must warn that omitted TOML feature keys default to true"
    );

    // 4. Residual authority: no overbroad write/socket claim, explicit enforcing
    //    seccomp prerequisite, and accurate narrowed socket/IPC rules.
    assert!(
        !s59.contains("no configuration enables execution, arbitrary file writes, network egress")
            && !s59.contains("No allowed protocol command writes guest files"),
        "§5.9 must not claim seccomp/unit prevents arbitrary file writes or that protocol operations never write the marker/power state"
    );
    for (name, text) in [
        ("docs/design.md §5.9", &s59_norm),
        ("packaging/README.md", &packaging_norm),
        ("README.md", &readme_norm),
    ] {
        assert!(
            !text.contains("protocol unrestricted")
                && !text.contains("AF_NETLINK family check only")
                && !text.contains("no argument or peer restriction")
                && !text.contains("leaves the netlink protocol")
                && !text.contains("unrestricted socketpair"),
            "{name} must not retain stale unrestricted-netlink or unrestricted-IPC wording"
        );
    }
    let lifecycle_start = packaging
        .find("**General-VM / lifecycle profile")
        .expect("General-VM / lifecycle profile paragraph in packaging/README.md");
    let lifecycle_end = packaging[lifecycle_start..]
        .find("- **Custom CVM configs")
        .map(|off| lifecycle_start + off)
        .expect("Custom CVM configs paragraph in packaging/README.md");
    let lifecycle_norm = normalize_ws(&packaging[lifecycle_start..lifecycle_end]);
    assert!(
        lifecycle_norm.contains("NETLINK_ROUTE") && lifecycle_norm.contains("addrlen == 12"),
        "packaging/README.md General-VM profile paragraph must describe NETLINK_ROUTE and inventory sendto: {lifecycle_norm}"
    );
    assert!(
        s59.contains("Unix permissions")
            && s59.contains("no general-purpose file-write command")
            && s59.contains("CAP_DAC_READ_SEARCH")
            && s59.contains("host channel")
            && s59.contains("unenforced-development-only")
            && s59.contains("may be absent or logging-only")
            && s59.contains("installed, enforcing seccomp filter")
            && s59.contains("NETLINK_ROUTE")
            && s59.contains("peerless `sendto`")
            && s59.contains("addrlen == 12"),
        "§5.9 must document permissions, broad reads, enforcing-filter scope, and narrowed socket/IPC rules"
    );

    // 5. Reconcile AC3 and AC25 with the five Linux capability sets and shutdown switch.
    let ac_row = |id: &str| -> &str {
        design
            .lines()
            .find(|l| l.starts_with(&format!("| {id} |")))
            .unwrap_or_else(|| panic!("missing {id} row in docs/design.md"))
    };
    let ac3 = ac_row("AC3");
    let ac25 = ac_row("AC25");
    for set in ["CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"] {
        assert!(ac3.contains(set), "AC3 must name {set}: {ac3}");
        assert!(ac25.contains(set), "AC25 must name {set}: {ac25}");
    }
    assert!(
        ac3.contains("[features] shutdown = true") && ac3.contains("shutdown = false"),
        "AC3 must qualify CAP_SYS_BOOT by [features] shutdown: {ac3}"
    );
    assert!(
        !ac25.contains("in every set") && ac25.contains("absent from all five sets"),
        "AC25 must name the five sets accurately instead of saying 'in every set': {ac25}"
    );

    // 6. Packaging guide, README, and §5.5: build instructions must name debug_assertions,
    //    not attribute a release startup failure to `seccomp-log`, and match #67 socket rules.
    assert!(
        !packaging
            .contains("and `seccomp-log` would fail the enforced hardening\ncheck at startup"),
        "packaging/README.md must not attribute a release startup failure to seccomp-log"
    );
    assert!(
        design.contains("debug_assertions")
            && packaging.contains("debug_assertions")
            && packaging.contains("test-fakes")
            && packaging.contains("unenforced-development-only")
            && packaging.contains("NETLINK_ROUTE")
            && packaging.contains("addrlen == 12")
            && packaging.contains("peerless")
            && readme.contains("NETLINK_ROUTE")
            && readme.contains("addrlen == 12")
            && readme.contains("peerless"),
        "docs/design.md, packaging/README.md, and README.md must align on debug_assertions, enforcing-filter scope, and #67 narrowed socket/IPC rules"
    );
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

/// `Some(guard)` once the shipped unit, the built binary, the service
/// account and a config with `channel_path` are installed for the
/// duration; `None` when there is no systemd to install into (and CI did
/// not insist). The unit gets a drop-in for the fake kernel (test-fakes
/// builds: no real ioctl; a build without the feature ignores the
/// variable and drains with real FITHAWs, which answer EINVAL on an
/// unfrozen host) and a short stop timeout.
fn install_unit(channel_path: &str) -> Option<InstalledUnit> {
    install_unit_with(channel_path, false)
}

/// As [`install_unit`]; with `production` the shipped defaults apply
/// (enforced hardening, the real kernel, no drop-in environment), which
/// is the profile a distributed artifact runs under, and the binary
/// installed is the distributed artifact itself when
/// `QEMINGA_RELEASE_BINARY` names it (CI's enforced privileged run builds
/// `--release --features seccomp` and points here), else this test build.
/// The development installs (`production == false`) always use the test
/// build: their fake-kernel drop-in needs `test-fakes`, which a release
/// cannot carry.
fn install_unit_with(channel_path: &str, production: bool) -> Option<InstalledUnit> {
    assert!(nix::unistd::geteuid().is_root(), "run as root");
    // A container without systemd cannot run this; CI's privileged job
    // sets QEMINGA_REQUIRE_SYSTEMD so the check can never pass vacuously.
    if !Path::new("/run/systemd/system").is_dir() {
        assert!(
            std::env::var_os("QEMINGA_REQUIRE_SYSTEMD").is_none(),
            "systemd is not the running service manager"
        );
        eprintln!("skipped: systemd is not the running service manager");
        return None;
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let backup = Path::new(InstalledUnit::BIN)
        .exists()
        .then(|| std::path::PathBuf::from("/usr/bin/qeminga.qeminga-test-backup"));
    if let Some(backup) = &backup {
        std::fs::rename(InstalledUnit::BIN, backup).unwrap();
    }
    let installed = InstalledUnit { backup };
    let test_build = std::path::PathBuf::from(env!("CARGO_BIN_EXE_qeminga"));
    let binary = match std::env::var_os("QEMINGA_RELEASE_BINARY") {
        Some(release) if production => std::path::PathBuf::from(release),
        _ => test_build,
    };
    eprintln!("installing {} as {}", binary.display(), InstalledUnit::BIN);
    std::fs::copy(&binary, InstalledUnit::BIN)
        .unwrap_or_else(|e| panic!("copy {}: {e}", binary.display()));
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
    let hardening = if production {
        ""
    } else {
        "hardening = \"unenforced-development-only\"\n"
    };
    std::fs::write(
        InstalledUnit::CONFIG,
        format!(
            "[agent]\nchannel_path = \"{channel_path}\"\nfsfreeze_idle_timeout_secs = 1\n{hardening}"
        ),
    )
    .unwrap();
    std::fs::copy(
        repo.join("packaging/systemd/qeminga.service"),
        InstalledUnit::UNIT,
    )
    .unwrap();
    std::fs::create_dir_all(InstalledUnit::DROPIN_DIR).unwrap();
    let dropin = if production {
        "[Service]\nTimeoutStopSec=15s\n"
    } else {
        "[Service]\nEnvironment=QEMINGA_TEST_FAKE_KERNEL=1\nTimeoutStopSec=15s\n"
    };
    std::fs::write(
        Path::new(InstalledUnit::DROPIN_DIR).join("50-test.conf"),
        dropin,
    )
    .unwrap();
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
    Some(installed)
}

/// A pty whose slave is the daemon's channel; requests go in and replies
/// come out through the master.
struct PtyChannel {
    master: std::fs::File,
    slave_path: String,
}

impl PtyChannel {
    fn open() -> Self {
        use nix::fcntl::OFlag;
        let master =
            nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).unwrap();
        nix::pty::grantpt(&master).unwrap();
        nix::pty::unlockpt(&master).unwrap();
        let slave_path = nix::pty::ptsname_r(&master).unwrap();
        let mut termios = nix::sys::termios::tcgetattr(&master).unwrap();
        nix::sys::termios::cfmakeraw(&mut termios);
        nix::sys::termios::tcsetattr(&master, nix::sys::termios::SetArg::TCSANOW, &termios)
            .unwrap();
        PtyChannel {
            master: std::fs::File::from(std::os::fd::OwnedFd::from(master)),
            slave_path,
        }
    }

    fn open_for_qeminga() -> Self {
        let pty = Self::open();
        let (ok, text) = sh("chown", &["600:600", &pty.slave_path]);
        assert!(ok, "chown {}: {text}", pty.slave_path);
        let (ok, text) = sh("chmod", &["0600", &pty.slave_path]);
        assert!(ok, "chmod {}: {text}", pty.slave_path);
        pty
    }

    /// Sends one request line and returns the reply line, or panics after
    /// ten seconds.
    fn request(&mut self, json: &str) -> String {
        use std::io::{Read, Write};
        use std::os::fd::AsFd;
        self.master.write_all(json.as_bytes()).unwrap();
        self.master.write_all(b"\n").unwrap();
        let mut line = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(
                !left.is_zero(),
                "no reply to {json}: {:?}",
                String::from_utf8_lossy(&line)
            );
            let mut fds = [nix::poll::PollFd::new(
                self.master.as_fd(),
                nix::poll::PollFlags::POLLIN,
            )];
            let ready =
                nix::poll::poll(&mut fds, nix::poll::PollTimeout::try_from(left).unwrap()).unwrap();
            if ready == 0 {
                continue;
            }
            let mut byte = [0u8; 1];
            assert!(
                self.master.read(&mut byte).unwrap() != 0,
                "channel closed before a reply to {json}"
            );
            if byte[0] == b'\n' {
                return String::from_utf8(line).unwrap();
            }
            line.push(byte[0]);
        }
    }
}

/// Removes a test file or symlink on drop.
struct PathGuard(std::path::PathBuf);

impl Drop for PathGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Removes a unique test-owned directory tree on drop.
struct DirGuard(std::path::PathBuf);

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Atomically points symlink `link` at `target`.
fn repoint_symlink(link: &Path, target: &str) {
    let tmp = link.with_extension("next");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp).unwrap();
    std::fs::rename(&tmp, link).unwrap();
}

/// Returns `(mnt_id, vfs_opts, mount_point)` for the mount actually serving
/// `target` inside `pid`'s mount namespace by opening `target` inside that
/// namespace, reading `mnt_id:` from `/proc/self/fdinfo/3`, and looking up the
/// exact row in `/proc/self/mountinfo`.
fn effective_mount_in_ns(pid: &str, target: &str) -> (u64, String, String) {
    let ns_arg = format!("--mount=/proc/{pid}/ns/mnt");
    let output = std::process::Command::new("nsenter")
        .env("LC_ALL", "C")
        .args([
            &ns_arg,
            "--",
            "/bin/sh",
            "-c",
            concat!(
                "exec 3<\"$1\" || exit 1; ",
                "id=\"$(awk '$1 == \"mnt_id:\" { print $2; exit }' /proc/self/fdinfo/3)\"; ",
                "[ -n \"$id\" ] || exit 1; ",
                "awk -v id=\"$id\" '$1 == id { print $1, $6, $5; found = 1; exit } END { exit(found ? 0 : 1) }' /proc/self/mountinfo",
            ),
            "_",
            target,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    assert!(
        output.status.success(),
        "effective_mount_in_ns({pid}, {target}) failed: stdout={stdout:?} stderr={stderr:?}"
    );
    let mut parts = stdout.splitn(3, ' ');
    let mnt_id: u64 = parts
        .next()
        .unwrap_or_else(|| panic!("missing mnt_id in {stdout:?}"))
        .parse()
        .unwrap();
    let vfs_opts = parts
        .next()
        .unwrap_or_else(|| panic!("missing vfs_opts in {stdout:?}"))
        .to_owned();
    let mount_point = parts
        .next()
        .unwrap_or_else(|| panic!("missing mount_point in {stdout:?}"))
        .to_owned();
    (mnt_id, vfs_opts, mount_point)
}

fn vfs_opts_has(opts: &str, flag: &str) -> bool {
    opts.split(',').any(|opt| opt == flag)
}

/// Runs `script` with argument `arg` as UID/GID 600 inside `pid`'s mount
/// namespace.
fn run_as_qeminga_in_ns(pid: &str, script: &str, arg: &str) -> (bool, String) {
    let ns_arg = format!("--mount=/proc/{pid}/ns/mnt");
    let output = std::process::Command::new("nsenter")
        .env("LC_ALL", "C")
        .args([
            &ns_arg,
            "--",
            "setpriv",
            "--reuid",
            "600",
            "--regid",
            "600",
            "--clear-groups",
            "--",
            "/bin/sh",
            "-c",
            script,
            "_",
            arg,
        ])
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

/// Creates a unique test-owned directory under `parent`, sets UID/GID 600 and
/// mode `0700` on its open directory descriptor, creates `"probe"` and
/// `"unlink-outside"` exclusively with `O_CREAT|O_EXCL|O_NOFOLLOW` and
/// descriptor-based `fchown`/`fchmod`, confirms UID 600 can genuinely write and
/// unlink outside confinement, then asserts both fail with `EROFS` inside
/// `pid`'s mount namespace and leaves only this run's directory to drop.
fn assert_ro_dir_confinement(pid: &str, parent: &Path) {
    use nix::fcntl::{OFlag, open, openat};
    use nix::sys::stat::{Mode, fchmod};
    use nix::unistd::{Gid, Uid, fchown, write};

    let dir = tempfile::Builder::new()
        .prefix("qeminga-confinement-")
        .tempdir_in(parent)
        .unwrap_or_else(|e| panic!("tempdir in {}: {e}", parent.display()));
    let uid = Some(Uid::from_raw(600));
    let gid = Some(Gid::from_raw(600));
    let dfd = open(
        dir.path(),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    fchown(&dfd, uid, gid).unwrap();
    fchmod(&dfd, Mode::from_bits_truncate(0o700)).unwrap();

    for name in ["probe", "unlink-outside"] {
        let fd = openat(
            &dfd,
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        fchown(&fd, uid, gid).unwrap();
        fchmod(&fd, Mode::from_bits_truncate(0o600)).unwrap();
        let written = write(&fd, b"intact\n").unwrap();
        assert_eq!(written, b"intact\n".len());
    }

    let probe = dir.path().join("probe");
    let unlink_outside = dir.path().join("unlink-outside");

    // Outside confinement, UID 600 must genuinely be able to write and unlink.
    let (ok, text) = sh(
        "setpriv",
        &[
            "--reuid",
            "600",
            "--regid",
            "600",
            "--clear-groups",
            "--",
            "/bin/sh",
            "-c",
            "printf 'intact\\n' > \"$1\"",
            "_",
            probe.to_str().unwrap(),
        ],
    );
    assert!(
        ok,
        "uid 600 must be able to write {} outside unit: {text}",
        probe.display()
    );
    let (ok, text) = sh(
        "setpriv",
        &[
            "--reuid",
            "600",
            "--regid",
            "600",
            "--clear-groups",
            "--",
            "/bin/rm",
            "--",
            unlink_outside.to_str().unwrap(),
        ],
    );
    assert!(
        ok,
        "uid 600 must be able to unlink {} outside unit: {text}",
        unlink_outside.display()
    );
    assert!(!unlink_outside.exists());

    // Inside the service mount namespace, both write and unlink must fail EROFS.
    let (ok, text) = run_as_qeminga_in_ns(
        pid,
        "printf 'tampered\\n' > \"$1\"",
        probe.to_str().unwrap(),
    );
    assert!(
        !ok && text.contains("Read-only file system"),
        "write under {} must fail with EROFS: ok={ok} text={text}",
        parent.display()
    );
    let (ok, text) = run_as_qeminga_in_ns(pid, "/bin/rm -- \"$1\"", probe.to_str().unwrap());
    assert!(
        !ok && text.contains("Read-only file system"),
        "unlink under {} must fail with EROFS: ok={ok} text={text}",
        parent.display()
    );
    assert_eq!(
        std::fs::read_to_string(&probe).unwrap(),
        "intact\n",
        "probe file under {} must remain untouched",
        parent.display()
    );
}

/// Verifies #66 write confinement inside `qeminga.service`'s mount namespace:
/// unique UID-600-owned directories under `/var/tmp`, `/home`, `/run`, `/dev`,
/// and `/dev/shm` allow write+unlink outside confinement but fail both with
/// `EROFS` inside it; the effective mounts serving `/`, `/sys`,
/// `/sys/power/state` (when present), `/run`, `/home`, `/dev`, and `/dev/shm`
/// are `ro`; and `/run/qeminga` stays writable to UID 600.
fn assert_unit_write_confinement(pid: &str) {
    assert_ro_dir_confinement(pid, Path::new("/var/tmp"));
    assert_ro_dir_confinement(pid, Path::new("/home"));
    assert_ro_dir_confinement(pid, Path::new("/run"));
    assert_ro_dir_confinement(pid, Path::new("/dev"));
    assert_ro_dir_confinement(pid, Path::new("/dev/shm"));

    let mut ro_targets = vec!["/", "/sys", "/run", "/home", "/dev", "/dev/shm"];
    if Path::new("/sys/power/state").exists() {
        ro_targets.push("/sys/power/state");
    }
    for target in ro_targets {
        let (mnt_id, vfs_opts, mp) = effective_mount_in_ns(pid, target);
        assert!(
            vfs_opts_has(&vfs_opts, "ro"),
            "effective mount for {target} must be ro (mnt_id={mnt_id} opts={vfs_opts:?} mp={mp:?})"
        );
    }

    let (ok, text) = run_as_qeminga_in_ns(
        pid,
        "p=\"$(mktemp \"$1/confinement-probe.XXXXXX\")\" && printf 'ok\\n' > \"$p\" && /bin/rm -- \"$p\"",
        "/run/qeminga",
    );
    assert!(
        ok,
        "/run/qeminga must remain writable to uid 600 in service mount namespace: {text}"
    );
}

/// Creates `name` inside `dir` owned by UID/GID 600 mode `0600` exclusively
/// through open directory and file descriptors.
fn create_qeminga_file(dir: &Path, name: &str) {
    use nix::fcntl::{OFlag, open, openat};
    use nix::sys::stat::{Mode, fchmod};
    use nix::unistd::{Gid, Uid, fchown};

    let dfd = open(
        dir,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let fd = openat(
        &dfd,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    fchown(&fd, Some(Uid::from_raw(600)), Some(Gid::from_raw(600))).unwrap();
    fchmod(&fd, Mode::from_bits_truncate(0o600)).unwrap();
}

/// The installed unit, not just the binary, freezes and thaws: the
/// daemon started by systemd, dropped to `qeminga`, must be able to
/// create its marker in /run/qeminga and remove it again. (With
/// RuntimeDirectory= it could not: systemd re-applied root ownership
/// before ExecStart and every freeze failed on the marker.) Also removes
/// `/run/qeminga` before starting so `ExecStartPre=+` creating it ahead
/// of `ReadWritePaths=-/run/qeminga` is exercised (#66), and confirms an
/// existing marker is preserved across restarts. The channel is a pty
/// the test holds the master of.
#[test]
#[ignore = "needs root and a running systemd (installs the shipped unit for the duration)"]
fn privileged_installed_unit_freezes_and_thaws_over_a_pty() {
    use std::os::unix::fs::MetadataExt;
    let mut pty = PtyChannel::open();
    let Some(installed) = install_unit(&pty.slave_path) else {
        return;
    };
    let _ = std::fs::remove_dir_all("/run/qeminga");
    let (ok, text) = sh("systemctl", &["start", "qeminga.service"]);
    assert!(ok, "systemctl start from absent /run/qeminga: {text}");
    let reply = pty.request(r#"{"execute":"guest-ping"}"#);
    assert_eq!(reply, r#"{"return":{}}"#);
    let reply = pty.request(r#"{"execute":"guest-fsfreeze-freeze"}"#);
    assert!(
        reply.starts_with(r#"{"return":"#),
        "freeze under the unit: {reply}"
    );
    let marker = std::fs::metadata("/run/qeminga/frozen")
        .unwrap_or_else(|e| panic!("marker not created by the dropped daemon: {e}"));
    assert_eq!(marker.uid(), 600, "created by the service account");
    assert_eq!(
        marker.mode() & 0o777,
        0o600,
        "marker mode 0600 (UMask=0077)"
    );
    let dir = std::fs::metadata("/run/qeminga").unwrap();
    assert_eq!(
        (dir.uid(), dir.mode() & 0o777),
        (600, 0o700),
        "owned by the service account"
    );
    assert_eq!(
        pty.request(r#"{"execute":"guest-fsfreeze-status"}"#),
        r#"{"return":"frozen"}"#
    );
    let reply = pty.request(r#"{"execute":"guest-fsfreeze-thaw"}"#);
    assert!(
        reply.starts_with(r#"{"return":"#),
        "thaw under the unit: {reply}"
    );
    assert!(
        !Path::new("/run/qeminga/frozen").exists(),
        "marker removed by the dropped daemon"
    );
    // Restarting with a pre-existing marker must preserve it across ExecStartPre=+
    // so the restarted daemon enters recovery mode and drains/removes it.
    let (ok, text) = sh("systemctl", &["stop", "qeminga.service"]);
    assert!(ok, "systemctl stop: {text}");
    let (_, since_raw) = sh("date", &["-u", "+%Y-%m-%d %H:%M:%S UTC"]);
    let since = since_raw.trim();
    create_qeminga_file(Path::new("/run/qeminga"), "frozen");
    let (ok, text) = sh("systemctl", &["start", "qeminga.service"]);
    assert!(ok, "systemctl start with existing marker: {text}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while Path::new("/run/qeminga/frozen").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let (_, log) = sh(
        "journalctl",
        &[
            "-u",
            "qeminga.service",
            "--no-pager",
            "-o",
            "cat",
            "--since",
            since,
        ],
    );
    assert!(
        !Path::new("/run/qeminga/frozen").exists(),
        "restarted unit must preserve and recover a pre-existing marker:\n{log}"
    );
    assert!(
        log.contains("\"recovery\":true"),
        "restarted unit must enter recovery mode from preserved marker:\n{log}"
    );
    assert_eq!(
        pty.request(r#"{"execute":"guest-fsfreeze-status"}"#),
        r#"{"return":"thawed"}"#
    );
    let (ok, text) = sh("systemctl", &["stop", "qeminga.service"]);
    assert!(ok, "systemctl stop: {text}");
    drop(installed);
}

/// Exercises the documented custom-marker drop-in recipe (#66) starting from
/// an absent custom directory: `ExecStartPre=+` provisions it owned by UID 600
/// mode `0700` without `226/NAMESPACE`, `/run` outside the custom directory
/// stays `ro`, freeze/thaw creates and removes the custom marker, and a
/// pre-existing marker is preserved across restarts for recovery.
#[test]
#[ignore = "needs root and a running systemd (installs the shipped unit for the duration)"]
fn privileged_installed_unit_custom_marker_path_from_absent_dir() {
    use std::os::unix::fs::MetadataExt;
    let mut pty = PtyChannel::open();
    let custom_dir =
        std::path::PathBuf::from(format!("/run/qeminga-custom-{}", std::process::id()));
    let custom_marker = custom_dir.join("frozen");
    let _custom_guard = DirGuard(custom_dir.clone());
    let Some(installed) = install_unit(&pty.slave_path) else {
        return;
    };
    let _ = std::fs::remove_dir_all(&custom_dir);
    assert!(!custom_dir.exists());

    std::fs::write(
        InstalledUnit::CONFIG,
        format!(
            "[agent]\nchannel_path = \"{}\"\nstate_path = \"{}\"\nfsfreeze_idle_timeout_secs = 1\nhardening = \"unenforced-development-only\"\n",
            pty.slave_path,
            custom_marker.display()
        ),
    )
    .unwrap();
    let custom_str = custom_dir.to_str().unwrap();
    std::fs::write(
        Path::new(InstalledUnit::DROPIN_DIR).join("60-custom-marker.conf"),
        format!(
            "[Service]\nExecStartPre=\nExecStartPre=+/usr/bin/mkdir -p {custom_str}\nExecStartPre=+/usr/bin/chown qeminga:qeminga {custom_str}\nExecStartPre=+/usr/bin/chmod 0700 {custom_str}\nReadWritePaths=\nReadWritePaths=-{custom_str}\n"
        ),
    )
    .unwrap();
    let (ok, text) = sh("systemctl", &["daemon-reload"]);
    assert!(ok, "daemon-reload: {text}");

    let (ok, text) = sh("systemctl", &["start", "qeminga.service"]);
    assert!(
        ok,
        "systemctl start from absent custom marker dir {custom_str}: {text}"
    );
    assert_eq!(
        pty.request(r#"{"execute":"guest-ping"}"#),
        r#"{"return":{}}"#
    );
    let (_, pid_raw) = sh(
        "systemctl",
        &["show", "-p", "MainPID", "--value", "qeminga.service"],
    );
    let pid = pid_raw.trim();
    let (run_id, run_opts, _) = effective_mount_in_ns(pid, "/run");
    assert!(
        vfs_opts_has(&run_opts, "ro"),
        "/run must stay ro under custom marker drop-in (mnt_id={run_id} opts={run_opts:?})"
    );
    let (cust_id, cust_opts, _) = effective_mount_in_ns(pid, custom_str);
    assert!(
        vfs_opts_has(&cust_opts, "rw") && cust_id != run_id,
        "{custom_str} must be rw on a distinct mount (mnt_id={cust_id} run_id={run_id} opts={cust_opts:?})"
    );

    let reply = pty.request(r#"{"execute":"guest-fsfreeze-freeze"}"#);
    assert!(reply.starts_with(r#"{"return":"#), "freeze: {reply}");
    let dir = std::fs::metadata(&custom_dir).unwrap();
    assert_eq!((dir.uid(), dir.mode() & 0o777), (600, 0o700));
    let marker = std::fs::metadata(&custom_marker).unwrap();
    assert_eq!((marker.uid(), marker.mode() & 0o777), (600, 0o600));
    let reply = pty.request(r#"{"execute":"guest-fsfreeze-thaw"}"#);
    assert!(reply.starts_with(r#"{"return":"#), "thaw: {reply}");
    assert!(!custom_marker.exists());

    // Restart with a pre-existing custom marker: ExecStartPre=+ must preserve it
    // and the restarted daemon must enter recovery mode and drain/remove it.
    let (ok, text) = sh("systemctl", &["stop", "qeminga.service"]);
    assert!(ok, "systemctl stop: {text}");
    let (_, since_raw) = sh("date", &["-u", "+%Y-%m-%d %H:%M:%S UTC"]);
    let since = since_raw.trim();
    create_qeminga_file(&custom_dir, "frozen");
    let (ok, text) = sh("systemctl", &["start", "qeminga.service"]);
    assert!(ok, "systemctl start with existing custom marker: {text}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while custom_marker.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let (_, log) = sh(
        "journalctl",
        &[
            "-u",
            "qeminga.service",
            "--no-pager",
            "-o",
            "cat",
            "--since",
            since,
        ],
    );
    assert!(
        !custom_marker.exists(),
        "restarted unit must preserve and recover pre-existing custom marker:\n{log}"
    );
    assert!(
        log.contains("\"recovery\":true"),
        "restarted unit must enter recovery mode from preserved custom marker:\n{log}"
    );
    assert_eq!(
        pty.request(r#"{"execute":"guest-fsfreeze-status"}"#),
        r#"{"return":"thawed"}"#
    );
    let (ok, text) = sh("systemctl", &["stop", "qeminga.service"]);
    assert!(ok, "systemctl stop: {text}");
    drop(installed);
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
    let Some(installed) = install_unit("/dev/virtio-ports/qeminga-test-no-such-port") else {
        return;
    };
    // The marker of a previous instance, in a directory provisioned as the
    // tmpfiles rule would at boot.
    std::fs::create_dir_all("/run/qeminga").unwrap();
    std::fs::write("/run/qeminga/frozen", b"").unwrap();
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

/// The installed artifact under the shipped defaults (enforced
/// hardening, real kernel): the daemon's effective capabilities,
/// no-new-privileges, seccomp mode, filesystem write confinement (#66),
/// a prohibited operation, a real freeze/thaw with pinned deduplicated
/// counts on the known loop layout (ext4, bind mount, and xfs when
/// present), post-drop read-write channel reopen, and SIGKILL crash
/// recovery all match the advertised profile, and a test-kernel request
/// is refused with the marker left alone (#43 §4). Under the
/// `seccomp-log` compatibility build the same start is refused outright,
/// which is the negative half of the same property.
#[test]
#[ignore = "needs root, a running systemd and a loop-mounted ext4 (scripts/ci/mk-loop-fs.sh)"]
fn privileged_installed_unit_matches_the_advertised_profile() {
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    let ext4 = std::env::var("QEMINGA_TEST_EXT4_MOUNT")
        .expect("QEMINGA_TEST_EXT4_MOUNT: run scripts/ci/mk-loop-fs.sh setup");
    let ext4_bind = std::env::var("QEMINGA_TEST_EXT4_BIND").ok();
    let xfs = std::env::var("QEMINGA_TEST_XFS_MOUNT").ok();
    let mut thaw_targets = vec![ext4.clone()];
    if let Some(ref x) = xfs {
        thaw_targets.push(x.clone());
    }
    // A failed assertion between the freeze and the thaw would otherwise
    // leave a loop filesystem frozen for the rest of the serial run: the
    // unit's drop SIGKILLs the daemon, watchdog included.
    let _thaw = e2e::ThawGuard::new(&thaw_targets);

    let channel_link = Path::new("/run/qeminga-test-channel");
    let _channel_guard = PathGuard(channel_link.to_path_buf());
    let mut pty1 = PtyChannel::open_for_qeminga();
    repoint_symlink(channel_link, &pty1.slave_path);
    let Some(installed) = install_unit_with(channel_link.to_str().unwrap(), true) else {
        return;
    };
    let _ = std::fs::remove_file("/run/qeminga/frozen");
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
    let refused = |what: &str| {
        // `Type=simple`: `systemctl start` returns once the process is
        // forked, so the refusal shows as the main process exiting 78 and
        // the unit's `Restart=always` loop, never as a served request.
        let (ok, text) = sh("systemctl", &["start", "--no-block", "qeminga.service"]);
        assert!(ok, "{what}: systemctl start: {text}");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let (_, status) = sh(
                "systemctl",
                &["show", "-p", "ExecMainStatus", "--value", "qeminga.service"],
            );
            if status.trim() == "78" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: no exit status 78 observed (last {status:?}):\n{}",
                journal()
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            journal().contains("refusing to serve the host"),
            "{what}: the refusal names itself:\n{}",
            journal()
        );
        assert!(
            !Path::new("/run/qeminga/frozen").exists(),
            "{what}: a refusal touches no marker"
        );
        let _ = sh("systemctl", &["stop", "qeminga.service"]);
        let _ = sh("systemctl", &["reset-failed", "qeminga.service"]);
        let (_, active) = sh("systemctl", &["is-active", "qeminga.service"]);
        assert_ne!(active.trim(), "active", "{what}: never serving");
    };
    if qeminga::daemon::seccomp_mode() != "enforce" {
        // The compatibility build cannot provide the profile: it says so
        // and serves nothing.
        refused("logging filter under enforced hardening");
        drop(installed);
        return;
    }
    let (ok, text) = sh("systemctl", &["start", "qeminga.service"]);
    assert!(ok, "systemctl start: {text}\n{}", journal());
    assert_eq!(
        pty1.request(r#"{"execute":"guest-ping"}"#),
        r#"{"return":{}}"#
    );
    let (_, pid_raw) = sh(
        "systemctl",
        &["show", "-p", "MainPID", "--value", "qeminga.service"],
    );
    let pid = pid_raw.trim().to_owned();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let field = |name: &str| -> String {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .unwrap_or_else(|| panic!("{name} missing in {status}"))
            .trim()
            .to_owned()
    };
    // CAP_DAC_READ_SEARCH (2), CAP_SYS_ADMIN (21), CAP_SYS_BOOT (22).
    const FINAL_CAPS: &str = "0000000000600004";
    assert_eq!(field("CapEff:"), FINAL_CAPS, "effective set (AC3)");
    assert_eq!(field("CapPrm:"), FINAL_CAPS, "permitted set (AC3)");
    assert_eq!(field("CapBnd:"), FINAL_CAPS, "bounding set (AC3)");
    assert_eq!(field("CapInh:"), "0000000000000000");
    assert_eq!(field("CapAmb:"), "0000000000000000");
    assert_eq!(field("NoNewPrivs:"), "1");
    assert_eq!(field("Seccomp:"), "2", "SECCOMP_MODE_FILTER");
    assert!(field("Uid:").starts_with("600\t600"), "{}", field("Uid:"));

    // #66: verify write confinement inside the running service's mount namespace.
    assert_unit_write_confinement(&pid);

    // A prohibited operation is refused; a real freeze/thaw on the known loop
    // layout (ext4 + bind alias deduplicated, plus xfs when available) works
    // under ProtectSystem=strict with exact nonzero counts.
    let reply = pty1.request(r#"{"execute":"guest-exec","arguments":{"path":"/bin/true"}}"#);
    assert!(reply.contains("CommandNotFound"), "{reply}");
    let mut requested = vec![ext4.clone()];
    if let Some(ref bind) = ext4_bind {
        requested.push(bind.clone());
    }
    if let Some(ref x) = xfs {
        requested.push(x.clone());
    }
    let expected_count: u64 = if xfs.is_some() { 2 } else { 1 };
    let freeze_req = serde_json::json!({
        "execute": "guest-fsfreeze-freeze-list",
        "arguments": { "mountpoints": requested },
    })
    .to_string();
    let expected_reply = format!(r#"{{"return":{expected_count}}}"#);

    let reply = pty1.request(&freeze_req);
    assert_eq!(
        reply, expected_reply,
        "pinned freeze count under ProtectSystem=strict for {requested:?}"
    );
    let marker = std::fs::metadata("/run/qeminga/frozen").unwrap();
    assert_eq!(marker.uid(), 600);
    assert_eq!(marker.mode() & 0o777, 0o600);
    let reply = pty1.request(r#"{"execute":"guest-fsfreeze-thaw"}"#);
    assert_eq!(
        reply, expected_reply,
        "pinned thaw count under ProtectSystem=strict"
    );
    assert!(!Path::new("/run/qeminga/frozen").exists());
    for target in &thaw_targets {
        std::fs::File::create(format!("{target}/installed-unit-probe"))
            .and_then(|mut f| f.write_all(b"ok"))
            .unwrap_or_else(|e| panic!("loop filesystem {target} must be thawed: {e}"));
    }

    // #66: read-write channel reopen after privilege drop under ProtectSystem=strict.
    let mut pty2 = PtyChannel::open_for_qeminga();
    repoint_symlink(channel_link, &pty2.slave_path);
    drop(pty1);
    assert_eq!(
        pty2.request(r#"{"execute":"guest-ping"}"#),
        r#"{"return":{}}"#,
        "dropped daemon must reopen channel O_RDWR under ProtectSystem=strict"
    );
    let (_, pid_after_reopen) = sh(
        "systemctl",
        &["show", "-p", "MainPID", "--value", "qeminga.service"],
    );
    assert_eq!(
        pid_after_reopen.trim(),
        pid,
        "channel reopen must occur in the existing dropped daemon"
    );

    // Every thread, not only the main one (§5.4): the ceiling is per
    // thread, and the freeze and thaw have put the audit writer and the
    // blocking pool to work.
    let threads = e2e::thread_statuses(pid.parse().unwrap());
    let names: Vec<&str> = threads.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"qeminga-audit"), "{names:?}");
    assert!(threads.len() >= 3, "{names:?}");
    for t in &threads {
        for set in ["CapEff:", "CapPrm:", "CapBnd:"] {
            assert_eq!(t.field(set), FINAL_CAPS, "{} {set} (AC3)", t.name);
        }
        assert_eq!(t.field("CapInh:"), "0000000000000000", "{}", t.name);
        assert_eq!(t.field("CapAmb:"), "0000000000000000", "{}", t.name);
        assert_eq!(t.field("NoNewPrivs:"), "1", "{}", t.name);
        assert_eq!(t.field("Seccomp:"), "2", "{}", t.name);
        assert!(
            t.field("Uid:").starts_with("600\t600"),
            "{}: {}",
            t.name,
            t.field("Uid:")
        );
    }

    // #66: crash recovery under the confined unit (SIGKILL while frozen ->
    // Restart=always -> marker recovery drains real ext4/xfs superblocks
    // and removes the marker under ProtectSystem=strict).
    let reply = pty2.request(&freeze_req);
    assert_eq!(reply, expected_reply, "second freeze before SIGKILL");
    assert!(Path::new("/run/qeminga/frozen").exists());
    let (ok, text) = sh(
        "systemctl",
        &["kill", "--signal=SIGKILL", "qeminga.service"],
    );
    assert!(ok, "systemctl kill: {text}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let (_, active) = sh("systemctl", &["is-active", "qeminga.service"]);
        let (_, new_pid) = sh(
            "systemctl",
            &["show", "-p", "MainPID", "--value", "qeminga.service"],
        );
        let new_pid = new_pid.trim();
        if active.trim() == "active"
            && !new_pid.is_empty()
            && new_pid != "0"
            && new_pid != pid
            && !Path::new("/run/qeminga/frozen").exists()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "restarted unit did not recover marker after SIGKILL (active={active:?}, new_pid={new_pid:?}, marker={}):\n{}",
            Path::new("/run/qeminga/frozen").exists(),
            journal()
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert_eq!(
        pty2.request(r#"{"execute":"guest-fsfreeze-status"}"#),
        r#"{"return":"thawed"}"#,
        "restarted unit must report thawed after crash recovery"
    );
    for target in &thaw_targets {
        std::fs::File::create(format!("{target}/installed-unit-recovery-probe"))
            .and_then(|mut f| f.write_all(b"recovered"))
            .unwrap_or_else(|e| {
                panic!("loop filesystem {target} must be thawed after recovery: {e}")
            });
    }

    let (ok, text) = sh("systemctl", &["stop", "qeminga.service"]);
    assert!(ok, "systemctl stop: {text}");
    // The distributed profile cannot be talked into faking the kernel.
    std::fs::write(
        Path::new(InstalledUnit::DROPIN_DIR).join("60-fake.conf"),
        "[Service]\nEnvironment=QEMINGA_TEST_FAKE_KERNEL=1\n",
    )
    .unwrap();
    let (ok, text) = sh("systemctl", &["daemon-reload"]);
    assert!(ok, "{text}");
    refused("test-kernel request under enforced hardening");
    drop(installed);
}
