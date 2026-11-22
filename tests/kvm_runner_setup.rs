//! Community KVM GitHub Actions runner setup script (`scripts/setup-kvm-runner.sh`):
//! supports both x86_64 and aarch64 (arm64) servers and is secure by default.
//!
//! Covers architecture normalization and pinned SHA-256 verification for both
//! `linux-x64` and `linux-arm64`, fail-closed input validation (refusing CLI
//! `--token`, root user, `pull_request`/`pull_request_target` events, wildcards,
//! unpinned runner versions, and cloud IMDS allow-listing), the hardened systemd
//! unit (unprivileged user, `qemu:///session`, `/dev/kvm`-only device policy,
//! cgroup egress deny for cloud IMDS and private LANs, read-only runner binaries,
//! `systemd-analyze verify`), the root-owned job-started allowlist guard and
//! post-job cleanup hook, and KVM preflight on both x86_64 and aarch64.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REPO_URL: &str = "https://github.com/vicaya/qeminga";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    root().join("scripts/setup-kvm-runner.sh")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn run_setup(args: &[&str]) -> Output {
    run_setup_env(args, &[], None)
}

fn run_setup_env(args: &[&str], env: &[(&str, &str)], bin: Option<&Path>) -> Output {
    let mut cmd = Command::new("bash");
    cmd.arg(script()).args(args);
    if let Some(bin) = bin {
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn sha256_of(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---- architecture support & runner archive verification -------------------

#[test]
fn supports_x86_64_and_arm64_unit_and_pinned_runner_digests() {
    let body = std::fs::read_to_string(script()).unwrap();
    let extract = |var: &str| {
        let prefix = format!("{var}=\"");
        body.lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("missing {var} pin in script"))
            .to_owned()
    };
    let x64_sha = extract("RUNNER_SHA256_x86_64");
    let arm64_sha = extract("RUNNER_SHA256_aarch64");
    for (label, digest) in [("x86_64", &x64_sha), ("aarch64", &arm64_sha)] {
        assert_eq!(digest.len(), 64, "{label}: {digest}");
        assert!(
            digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{label}: {digest}"
        );
    }
    assert_ne!(x64_sha, arm64_sha, "distinct digests per architecture");

    for (arg_arch, expected_arch) in [
        ("x86_64", "x86_64"),
        ("aarch64", "aarch64"),
        ("arm64", "aarch64"),
        ("amd64", "x86_64"),
        ("x64", "x86_64"),
    ] {
        let out = run_setup(&["render-unit", "--repo", REPO_URL, "--arch", arg_arch]);
        assert!(out.status.success(), "{arg_arch}: {}", text(&out));
        let unit = String::from_utf8(out.stdout).unwrap();
        assert!(
            unit.contains(&format!(
                "Description=qeminga KVM GitHub Actions runner ({expected_arch})"
            )),
            "{arg_arch}: {unit}"
        );
    }

    for bad_arch in ["riscv64", "i686", "ppc64le", "x86_64;id"] {
        let out = run_setup(&["render-unit", "--repo", REPO_URL, "--arch", bad_arch]);
        assert!(!out.status.success(), "{bad_arch}: {}", text(&out));
    }
}

#[test]
fn fetch_runner_verifies_sha256_for_both_architectures_and_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    for arch in ["x86_64", "aarch64", "arm64"] {
        let payload = format!("fake runner archive for {arch}\n");
        let sha = sha256_of(payload.as_bytes());
        let src = dir.path().join(format!("runner-{arch}.tar.gz"));
        std::fs::write(&src, &payload).unwrap();
        let url = format!("file://{}", src.display());
        let dest = dir.path().join(format!("out-{arch}.tar.gz"));

        let ok = run_setup(&[
            "fetch-runner",
            "--arch",
            arch,
            "--dest",
            dest.to_str().unwrap(),
            "--version",
            "2.338.2",
            "--sha256",
            &sha,
            "--url",
            &url,
        ]);
        assert!(ok.status.success(), "{arch}: {}", text(&ok));
        assert_eq!(std::fs::read(&dest).unwrap(), payload.as_bytes());

        // Tampered bytes must be rejected and never placed at --dest.
        let dest_bad = dir.path().join(format!("bad-{arch}.tar.gz"));
        let wrong_sha = "f".repeat(64);
        let bad = run_setup(&[
            "fetch-runner",
            "--arch",
            arch,
            "--dest",
            dest_bad.to_str().unwrap(),
            "--version",
            "2.338.2",
            "--sha256",
            &wrong_sha,
            "--url",
            &url,
        ]);
        assert!(!bad.status.success(), "{arch}: {}", text(&bad));
        assert!(
            !dest_bad.exists(),
            "{arch}: tampered download must not land"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "{arch}: partial download left behind: {leftovers:?}"
        );
    }

    // Overriding version without an explicit SHA-256 must fail closed.
    let dest_unpinned = dir.path().join("unpinned.tar.gz");
    let unpinned = run_setup(&[
        "fetch-runner",
        "--arch",
        "aarch64",
        "--dest",
        dest_unpinned.to_str().unwrap(),
        "--version",
        "2.999.0",
    ]);
    assert!(!unpinned.status.success(), "{}", text(&unpinned));
    assert!(
        text(&unpinned).contains("--sha256"),
        "names missing digest: {}",
        text(&unpinned)
    );
}

// ---- secure-by-default systemd unit ---------------------------------------

#[test]
fn rendered_unit_is_hardened_and_unprivileged_by_default() {
    let out = run_setup(&["render-unit", "--repo", REPO_URL, "--arch", "aarch64"]);
    assert!(out.status.success(), "{}", text(&out));
    let unit = String::from_utf8(out.stdout).unwrap();

    for required in [
        "User=qeminga-runner",
        "Group=qeminga-runner",
        "SupplementaryGroups=kvm",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=\n",
        "AmbientCapabilities=\n",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "ProtectProc=invisible",
        "DevicePolicy=closed",
        "DeviceAllow=/dev/kvm rw",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes",
        "ProtectControlGroups=yes",
        "ProtectClock=yes",
        "ProtectHostname=yes",
        "RestrictNamespaces=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "RestrictRealtime=yes",
        "SystemCallArchitectures=native",
        "SystemCallErrorNumber=EPERM",
        "SystemCallFilter=@system-service",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "RemoveIPC=yes",
        "UMask=0077",
        "KillMode=control-group",
        "MemoryMax=80%",
        "TasksMax=512",
        "IPAddressAllow=localhost",
        "IPAddressDeny=link-local",
        "IPAddressDeny=multicast",
        "IPAddressDeny=10.0.0.0/8",
        "IPAddressDeny=172.16.0.0/12",
        "IPAddressDeny=192.168.0.0/16",
        "IPAddressDeny=100.64.0.0/10",
        "IPAddressDeny=fc00::/7",
        "IPAddressDeny=fe80::/10",
        "IPAddressDeny=fd00:ec2::254/128",
        "ExecStart=/opt/qeminga-runner/bin/runsvc.sh",
        "Environment=XDG_RUNTIME_DIR=/run/qeminga-kvm-runner",
        "Environment=QEMINGA_E2E_CONNECT=qemu:///session",
        "Environment=LIBVIRT_DEFAULT_URI=qemu:///session",
        "Environment=QEMINGA_RUNNER_POLICY=/etc/qeminga-runner/policy.env",
        "Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/libexec/qeminga-runner/hook-job-started.sh",
        "Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/usr/local/libexec/qeminga-runner/hook-job-completed.sh",
        "ReadWritePaths=/opt/qeminga-runner/_diag",
        "StateDirectory=qeminga-runner",
        "RuntimeDirectory=qeminga-kvm-runner",
    ] {
        assert!(unit.contains(required), "missing {required:?} in:\n{unit}");
    }

    // Never root, never docker/libvirt/sudo groups, never MDWE=yes (breaks .NET/Node/QEMU JIT),
    // and never run.sh (which tries to copy run-helper.sh into the read-only install dir).
    for forbidden in [
        "User=root",
        "SupplementaryGroups=libvirt",
        "SupplementaryGroups=docker",
        "SupplementaryGroups=sudo",
        "MemoryDenyWriteExecute=yes",
        "ReadWritePaths=/opt/qeminga-runner\n",
        "ExecStart=/opt/qeminga-runner/run.sh",
    ] {
        assert!(
            !unit.contains(forbidden),
            "forbidden {forbidden:?} in:\n{unit}"
        );
    }
}

#[test]
fn rendered_units_pass_systemd_analyze_verify() {
    let has_systemd_analyze = Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !has_systemd_analyze {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let fake_install = dir.path().join("runner");
    let fake_diag = fake_install.join("_diag");
    let fake_bin = fake_install.join("bin");
    let fake_ext = fake_install.join("externals");
    let fake_state = dir.path().join("state");
    let fake_hooks = dir.path().join("hooks");
    let fake_cfg = dir.path().join("cfg");
    for d in [
        &fake_diag,
        &fake_bin,
        &fake_ext,
        &fake_state,
        &fake_hooks,
        &fake_cfg,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    for f in ["run.sh", "config.sh", "env.sh"] {
        write_exec(&fake_install.join(f), "#!/bin/sh\nexit 0\n");
    }
    std::fs::write(fake_install.join(".env"), b"").unwrap();
    write_exec(&fake_bin.join("runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_bin.join("Runner.Listener"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_hooks.join("run-jit.sh"), "#!/bin/sh\nexit 0\n");
    let jit_cfg = fake_cfg.join("jitconfig");
    std::fs::write(&jit_cfg, "dummy").unwrap();
    std::fs::set_permissions(&jit_cfg, std::fs::Permissions::from_mode(0o600)).unwrap();

    for (name, extra) in [
        ("default-x86_64.service", vec!["--arch", "x86_64"]),
        ("default-aarch64.service", vec!["--arch", "aarch64"]),
        (
            "no-lan-deny.service",
            vec!["--arch", "aarch64", "--no-lan-deny"],
        ),
        (
            "ephemeral.service",
            vec!["--arch", "aarch64", "--ephemeral"],
        ),
        (
            "jit.service",
            vec![
                "--arch",
                "aarch64",
                "--jitconfig-file",
                jit_cfg.to_str().unwrap(),
            ],
        ),
        (
            "auto-update.service",
            vec![
                "--arch",
                "x86_64",
                "--allow-auto-update",
                "--cpu-quota",
                "200%",
                "--allow-ip",
                "10.0.0.2/32",
            ],
        ),
    ] {
        let mut args = vec![
            "render-unit",
            "--repo",
            REPO_URL,
            "--install-dir",
            fake_install.to_str().unwrap(),
            "--state-dir",
            fake_state.to_str().unwrap(),
            "--hook-dir",
            fake_hooks.to_str().unwrap(),
            "--config-dir",
            fake_cfg.to_str().unwrap(),
        ];
        args.extend(extra);
        let out = run_setup(&args);
        assert!(out.status.success(), "{name}: {}", text(&out));
        let unit_path = dir.path().join(name);
        std::fs::write(&unit_path, &out.stdout).unwrap();

        let verify = Command::new("systemd-analyze")
            .args(["verify", "--man=no"])
            .arg(&unit_path)
            .output()
            .unwrap();
        let combined = text(&verify);
        assert!(
            verify.status.success(),
            "{name}: systemd-analyze verify failed:\n{combined}\nunit:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        // Reject unknown keys or syntax warnings even if verify exits 0.
        assert!(
            !combined.contains("Unknown key") && !combined.contains("Failed to parse"),
            "{name}: systemd-analyze warnings:\n{combined}"
        );
        if name == "jit.service" {
            let rendered = String::from_utf8_lossy(&out.stdout);
            assert!(rendered.contains("LoadCredential=jitconfig:"), "{rendered}");
            assert!(
                rendered.contains("ExecStopPost=+/usr/bin/rm -f "),
                "{rendered}"
            );
            assert!(rendered.contains("Restart=no"), "{rendered}");
            assert!(rendered.contains("KillSignal=SIGINT"), "{rendered}");
        }
    }
}

#[test]
fn unit_options_preserve_security_invariants() {
    // --ephemeral runs once without restarting and keeps runner binaries and .env read-only.
    let eph = run_setup(&[
        "render-unit",
        "--repo",
        REPO_URL,
        "--arch",
        "x86_64",
        "--ephemeral",
    ]);
    assert!(eph.status.success(), "{}", text(&eph));
    let unit = String::from_utf8(eph.stdout).unwrap();
    assert!(unit.contains("Restart=no"), "{unit}");
    assert!(
        unit.contains("ExecStart=/opt/qeminga-runner/bin/runsvc.sh"),
        "{unit}"
    );
    assert!(
        unit.contains("ReadOnlyPaths=/opt/qeminga-runner/bin"),
        "{unit}"
    );
    assert!(
        unit.contains("ReadOnlyPaths=/opt/qeminga-runner/externals"),
        "{unit}"
    );
    assert!(
        unit.contains("ReadOnlyPaths=/opt/qeminga-runner/.env"),
        "{unit}"
    );

    // --no-lan-deny drops RFC1918/ULA denies while STILL denying IPv4 and IPv6 cloud IMDS.
    let no_lan = run_setup(&[
        "render-unit",
        "--repo",
        REPO_URL,
        "--arch",
        "aarch64",
        "--no-lan-deny",
    ]);
    assert!(no_lan.status.success(), "{}", text(&no_lan));
    let unit = String::from_utf8(no_lan.stdout).unwrap();
    assert!(unit.contains("IPAddressDeny=link-local"), "{unit}");
    assert!(unit.contains("IPAddressDeny=fe80::/10"), "{unit}");
    assert!(unit.contains("IPAddressDeny=fd00:ec2::254/128"), "{unit}");
    assert!(unit.contains("IPAddressDeny=multicast"), "{unit}");
    assert!(!unit.contains("IPAddressDeny=10.0.0.0/8"), "{unit}");
    assert!(!unit.contains("IPAddressDeny=fc00::/7"), "{unit}");

    // --allow-ip allows a specific private resolver, never cloud IMDS, supernets, or 0.0.0.0/0.
    let ok_ip = run_setup(&[
        "render-unit",
        "--repo",
        REPO_URL,
        "--arch",
        "x86_64",
        "--allow-ip",
        "10.0.0.2/32",
    ]);
    assert!(ok_ip.status.success(), "{}", text(&ok_ip));
    assert!(
        String::from_utf8(ok_ip.stdout)
            .unwrap()
            .contains("IPAddressAllow=10.0.0.2/32")
    );

    for bad_ip in [
        "169.254.169.254",
        "169.254.169.254/32",
        "169.254.0.0/16",
        "169.254.0.0/15",
        "169.0.0.0/8",
        "128.0.0.0/1",
        "fd00:ec2::254/128",
        "fd00:0ec2::254/128",
        "::ffff:169.254.169.254/128",
        "fe90::1/128",
        "fc00::/7",
        "0.0.0.0/0",
        "::/0",
        "any",
        "10.0.0.1\nExecStart=/bin/sh",
    ] {
        let out = run_setup(&[
            "render-unit",
            "--repo",
            REPO_URL,
            "--arch",
            "x86_64",
            "--allow-ip",
            bad_ip,
        ]);
        assert!(!out.status.success(), "{bad_ip}: {}", text(&out));
    }
}

// ---- fail-closed input & credential hygiene validation --------------------

#[test]
fn refuses_cli_token_root_user_bad_repos_and_untrusted_events() {
    // Passing --token directly on the CLI must be refused to prevent ps/history leaks.
    let cli_tok = run_setup(&["install", "--repo", REPO_URL, "--token", "SECRET_TOKEN"]);
    assert!(!cli_tok.status.success());
    assert!(
        text(&cli_tok).contains("--token-file"),
        "should guide caller to safe token input: {}",
        text(&cli_tok)
    );

    // Bad repository URLs.
    for bad_repo in [
        "http://github.com/vicaya/qeminga",
        "https://evil.example/vicaya/qeminga",
        "https://github.com/vicaya",
        "https://github.com/vicaya/qeminga.git",
        "https://user:pass@github.com/vicaya/qeminga",
        "https://github.com/vicaya/qeminga;id",
        "https://github.com/../etc/passwd",
    ] {
        let out = run_setup(&["render-unit", "--repo", bad_repo, "--arch", "x86_64"]);
        assert!(!out.status.success(), "{bad_repo}: {}", text(&out));
    }

    // Never allow --user root or malformed usernames.
    for bad_user in ["root", "0", "bad user", "a;b"] {
        let out = run_setup(&[
            "render-unit",
            "--repo",
            REPO_URL,
            "--arch",
            "x86_64",
            "--user",
            bad_user,
        ]);
        assert!(!out.status.success(), "{bad_user}: {}", text(&out));
    }

    let tmp = tempfile::tempdir().unwrap();
    // Never allow untrusted PR events on community self-hosted runners.
    for bad_event in [
        "pull_request",
        "pull_request_target",
        "issue_comment",
        "discussion",
        "fork",
        "*",
    ] {
        let out = run_setup(&[
            "render-hooks",
            "--repo",
            REPO_URL,
            "--out",
            tmp.path().to_str().unwrap(),
            "--allow-event",
            bad_event,
        ]);
        assert!(!out.status.success(), "{bad_event}: {}", text(&out));
    }

    // No wildcards or traversal in refs or workflows.
    for bad_ref in [
        "main",
        "refs/heads/*",
        "refs/heads/../main",
        "refs/pull/1/head",
    ] {
        let out = run_setup(&[
            "render-hooks",
            "--repo",
            REPO_URL,
            "--out",
            tmp.path().to_str().unwrap(),
            "--allow-ref",
            bad_ref,
        ]);
        assert!(!out.status.success(), "{bad_ref}: {}", text(&out));
    }
    for bad_wf in [
        ".github/workflows/*.yml",
        ".github/workflows/../evil.yml",
        "libvirt-kvm.yml",
        "/etc/passwd",
    ] {
        let out = run_setup(&[
            "render-hooks",
            "--repo",
            REPO_URL,
            "--out",
            tmp.path().to_str().unwrap(),
            "--allow-workflow",
            bad_wf,
        ]);
        assert!(!out.status.success(), "{bad_wf}: {}", text(&out));
    }

    // Invalid resource limits and paths.
    for bad_args in [
        vec!["--memory-max", "100%"],
        vec!["--memory-max", "0%"],
        vec!["--memory-max", "unlimited"],
        vec!["--tasks-max", "0"],
        vec!["--cpu-quota", "0%"],
        vec!["--install-dir", "/"],
        vec!["--install-dir", "relative/dir"],
        vec!["--state-dir", "/var/lib/../etc"],
        vec!["--labels", "qeminga-kvm;id"],
    ] {
        let mut args = vec!["render-unit", "--repo", REPO_URL, "--arch", "x86_64"];
        args.extend(bad_args.iter().copied());
        let out = run_setup(&args);
        assert!(!out.status.success(), "{bad_args:?}: {}", text(&out));
    }
}

// ---- host-enforced job-started and job-completed hooks --------------------

const FAKE_VIRSH: &str = r#"#!/bin/sh
echo "$*" >> "${FAKE_LOG:?}"
case "$1" in --connect=*) shift ;; esac
case "$1" in
    list)
        [ "${FAKE_LIST_FAILS:-0}" = 1 ] && { echo "error: failed to connect" >&2; exit 1; }
        printf '%s\n' ${FAKE_LIST:-} ""; exit 0 ;;
    domstate)
        [ "${FAKE_STATE_FAILS:-0}" = 1 ] && { echo "error: internal error" >&2; exit 1; }
        for d in ${FAKE_LIST:-}; do
            if [ "$d" = "$2" ]; then
                echo "${FAKE_DOMSTATE:-running}"
                exit 0
            fi
        done
        echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    destroy)
        exit 0 ;;
    undefine)
        # Shift optional --nvram flag.
        if [ "$2" = "--nvram" ]; then target="$3"; else target="$2"; fi
        # Record removed domains so subsequent domstate sees absent.
        echo "$target" >> "${FAKE_REMOVED:?}"
        exit 0 ;;
    domcapabilities)
        [ "${FAKE_DOMCAPS_FAILS:-0}" = 1 ] && { echo "error: kvm unsupported" >&2; exit 1; }
        echo "<domainCapabilities><domain>kvm</domain></domainCapabilities>"; exit 0 ;;
    *) exit 0 ;;
esac
"#;

const FAKE_VIRSH_STATEFUL: &str = r#"#!/bin/sh
echo "$*" >> "${FAKE_LOG:?}"
case "$1" in --connect=*) shift ;; esac
removed() {
    [ -f "${FAKE_REMOVED:-/nonexistent}" ] && grep -qx -- "$1" "$FAKE_REMOVED"
}
destroyed() {
    [ -f "${FAKE_DESTROYED:-/nonexistent}" ] && grep -qx -- "$1" "$FAKE_DESTROYED"
}
case "$1" in
    list)
        [ "${FAKE_LIST_FAILS:-0}" = 1 ] && { echo "error: failed to connect" >&2; exit 1; }
        for d in ${FAKE_LIST:-}; do
            removed "$d" || printf '%s\n' "$d"
        done
        exit 0 ;;
    domstate)
        [ "${FAKE_STATE_FAILS:-0}" = 1 ] && { echo "error: internal error" >&2; exit 1; }
        if removed "$2"; then
            echo "error: failed to get domain '$2'" >&2; exit 1
        fi
        for d in ${FAKE_LIST:-}; do
            if [ "$d" = "$2" ]; then
                if destroyed "$2"; then echo "shut off"; else echo "${FAKE_DOMSTATE:-running}"; fi
                exit 0
            fi
        done
        echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    destroy)
        echo "$2" >> "${FAKE_DESTROYED:?}"
        exit 0 ;;
    undefine)
        if [ "$2" = "--nvram" ]; then target="$3"; else target="$2"; fi
        echo "$target" >> "${FAKE_REMOVED:?}"
        exit 0 ;;
    *) exit 0 ;;
esac
"#;

fn run_hook(hook: &Path, policy: &Path, bin: &Path, extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("bash");
    cmd.arg(hook);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    cmd.env("PATH", path)
        .env("QEMINGA_RUNNER_POLICY", policy)
        .env("QEMINGA_KVM_DEVICE", "/dev/null");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

#[test]
fn job_started_hook_allows_exact_matching_dispatch_and_refuses_everything_else() {
    let dir = tempfile::tempdir().unwrap();
    let hooks_out = dir.path().join("hooks");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(&bin.join("virsh"), FAKE_VIRSH);

    let rendered = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks_out.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--allow-actor",
        "vicaya",
    ]);
    assert!(rendered.status.success(), "{}", text(&rendered));

    let started = hooks_out.join("hook-job-started.sh");
    let policy = hooks_out.join("policy.env");
    let log = dir.path().join("virsh.log");

    let log_str = log.to_str().unwrap();
    let valid_wf_ref = "vicaya/qeminga/.github/workflows/libvirt-kvm.yml@refs/heads/main";
    fn base_env<'a>(
        log: &'a str,
        repo: &'a str,
        event: &'a str,
        git_ref: &'a str,
        wf_ref: &'a str,
        actor: &'a str,
    ) -> Vec<(&'a str, &'a str)> {
        vec![
            ("FAKE_LOG", log),
            ("GITHUB_REPOSITORY", repo),
            ("GITHUB_EVENT_NAME", event),
            ("GITHUB_REF", git_ref),
            ("GITHUB_WORKFLOW_REF", wf_ref),
            ("GITHUB_ACTOR", actor),
            ("UNRELATED_SECRET", "DO_NOT_LEAK_ME_12345"),
        ]
    }

    // Exact match passes and never leaks unrelated environment variables.
    let ok = run_hook(
        &started,
        &policy,
        &bin,
        &base_env(
            log_str,
            "vicaya/qeminga",
            "workflow_dispatch",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
    );
    assert!(ok.status.success(), "{}", text(&ok));
    assert!(
        !text(&ok).contains("DO_NOT_LEAK_ME_12345"),
        "hook must never dump env: {}",
        text(&ok)
    );
    assert!(text(&ok).contains("verdict=allow"), "{}", text(&ok));

    // Wrong repo (including prefix spoof), wrong event (PR / pull_request_target / push),
    // wrong ref, wrong workflow, wrong actor — all refused.
    for (label, repo, event, git_ref, wf_ref, actor) in [
        (
            "prefix-repo",
            "vicaya/qeminga-fork",
            "workflow_dispatch",
            "refs/heads/main",
            "vicaya/qeminga-fork/.github/workflows/libvirt-kvm.yml@refs/heads/main",
            "vicaya",
        ),
        (
            "pull_request",
            "vicaya/qeminga",
            "pull_request",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
        (
            "pull_request_target",
            "vicaya/qeminga",
            "pull_request_target",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
        (
            "unlisted-push",
            "vicaya/qeminga",
            "push",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
        (
            "wrong-branch",
            "vicaya/qeminga",
            "workflow_dispatch",
            "refs/heads/feature",
            "vicaya/qeminga/.github/workflows/libvirt-kvm.yml@refs/heads/feature",
            "vicaya",
        ),
        (
            "wrong-workflow",
            "vicaya/qeminga",
            "workflow_dispatch",
            "refs/heads/main",
            "vicaya/qeminga/.github/workflows/ci.yml@refs/heads/main",
            "vicaya",
        ),
        (
            "wrong-actor",
            "vicaya/qeminga",
            "workflow_dispatch",
            "refs/heads/main",
            valid_wf_ref,
            "random-user",
        ),
    ] {
        let out = run_hook(
            &started,
            &policy,
            &bin,
            &base_env(log_str, repo, event, git_ref, wf_ref, actor),
        );
        assert!(
            !out.status.success(),
            "{label} should be denied: {}",
            text(&out)
        );
        assert!(
            !text(&out).contains("DO_NOT_LEAK_ME_12345"),
            "{label} leaked env: {}",
            text(&out)
        );
    }

    // Missing policy fails closed.
    let missing_policy = run_hook(
        &started,
        &dir.path().join("nonexistent.env"),
        &bin,
        &base_env(
            log_str,
            "vicaya/qeminga",
            "workflow_dispatch",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
    );
    assert!(!missing_policy.status.success());

    // Missing /dev/kvm fails closed.
    let mut no_kvm_env = base_env(
        log_str,
        "vicaya/qeminga",
        "workflow_dispatch",
        "refs/heads/main",
        valid_wf_ref,
        "vicaya",
    );
    no_kvm_env.push(("QEMINGA_KVM_DEVICE", "/nonexistent/kvm"));
    let no_kvm = run_hook(&started, &policy, &bin, &no_kvm_env);
    assert!(!no_kvm.status.success(), "{}", text(&no_kvm));

    // Stale qeminga-e2e-* domain or failing virsh listing fails closed.
    let mut stale_env = base_env(
        log_str,
        "vicaya/qeminga",
        "workflow_dispatch",
        "refs/heads/main",
        valid_wf_ref,
        "vicaya",
    );
    stale_env.push(("FAKE_LIST", "qeminga-e2e-99-1-aarch64"));
    let stale = run_hook(&started, &policy, &bin, &stale_env);
    assert!(!stale.status.success(), "{}", text(&stale));

    let mut list_fail_env = base_env(
        log_str,
        "vicaya/qeminga",
        "workflow_dispatch",
        "refs/heads/main",
        valid_wf_ref,
        "vicaya",
    );
    list_fail_env.push(("FAKE_LIST_FAILS", "1"));
    let list_fail = run_hook(&started, &policy, &bin, &list_fail_env);
    assert!(!list_fail.status.success(), "{}", text(&list_fail));
}

#[test]
fn job_completed_hook_scrubs_work_dir_and_stray_qeminga_domains_only() {
    let dir = tempfile::tempdir().unwrap();
    let hooks_out = dir.path().join("hooks");
    let state_dir = dir.path().join("state");
    let work_dir = state_dir.join("work");
    let images_dir = state_dir.join("images");
    let cache_dir = state_dir.join("image-cache");
    let stray_run = images_dir.join("qeminga-e2e-77-1-aarch64");
    let donor_dir = images_dir.join("donor-vm");
    for d in [&work_dir, &stray_run, &donor_dir, &cache_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(work_dir.join("checkout.txt"), b"leftover").unwrap();
    std::fs::write(work_dir.join(".hidden-token"), b"leftover").unwrap();
    std::fs::write(stray_run.join("root.qcow2"), b"stray").unwrap();
    std::fs::write(donor_dir.join("important.qcow2"), b"keep").unwrap();
    std::fs::write(cache_dir.join("cached-img"), b"keep-cache").unwrap();

    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(&bin.join("virsh"), FAKE_VIRSH_STATEFUL);

    let rendered = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks_out.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    assert!(rendered.status.success(), "{}", text(&rendered));

    let completed = hooks_out.join("hook-job-completed.sh");
    let policy = hooks_out.join("policy.env");
    let log = dir.path().join("virsh.log");
    let removed = dir.path().join("removed");
    let destroyed = dir.path().join("destroyed");

    let out = run_hook(
        &completed,
        &policy,
        &bin,
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("FAKE_REMOVED", removed.to_str().unwrap()),
            ("FAKE_DESTROYED", destroyed.to_str().unwrap()),
            ("FAKE_LIST", "donor-vm qeminga-e2e-77-1-aarch64"),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));

    // Stray qeminga domain & its disks are removed; donor's domain & disks stay untouched.
    let v_log = std::fs::read_to_string(&log).unwrap();
    assert!(
        v_log.contains("destroy qeminga-e2e-77-1-aarch64"),
        "{v_log}"
    );
    assert!(
        v_log.contains("undefine --nvram qeminga-e2e-77-1-aarch64"),
        "{v_log}"
    );
    assert!(!v_log.contains("destroy donor-vm"), "{v_log}");
    assert!(
        !v_log.contains("undefine") || !v_log.contains("donor-vm"),
        "{v_log}"
    );
    assert!(!stray_run.exists(), "stray qeminga run dir removed");
    assert!(
        donor_dir.join("important.qcow2").exists(),
        "donor dir untouched"
    );

    // Work dir is scrubbed (including dotfiles), while work_dir itself and image-cache stay.
    assert!(work_dir.is_dir());
    assert_eq!(std::fs::read_dir(&work_dir).unwrap().count(), 0);
    assert!(cache_dir.join("cached-img").exists());

    // When libvirt state cannot be established, orphan disks are conservatively kept.
    let unknown_run = images_dir.join("qeminga-e2e-88-1-x86_64");
    std::fs::create_dir_all(&unknown_run).unwrap();
    std::fs::write(unknown_run.join("root.qcow2"), b"keep-unknown").unwrap();
    let out_unknown = run_hook(
        &completed,
        &policy,
        &bin,
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("FAKE_STATE_FAILS", "1"),
            ("FAKE_LIST", "qeminga-e2e-88-1-x86_64"),
        ],
    );
    assert!(
        unknown_run.join("root.qcow2").exists(),
        "must not delete disks when domain state is unknown: {}",
        text(&out_unknown)
    );
}

// ---- preflight on both x86_64 and aarch64 ---------------------------------

#[test]
fn preflight_supports_x86_64_and_aarch64_and_detects_missing_kvm_or_firmware() {
    for arch in ["x86_64", "aarch64"] {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_exec(
            &bin.join("uname"),
            &format!("#!/bin/sh\nif [ \"$1\" = -m ]; then echo {arch}; else echo Linux; fi\n"),
        );
        write_exec(&bin.join("virsh"), FAKE_VIRSH);
        for tool in [
            "libvirtd",
            "qemu-img",
            "genisoimage",
            "jq",
            "curl",
            "sha256sum",
            "tar",
            "systemctl",
            &format!("qemu-system-{arch}"),
        ] {
            write_exec(&bin.join(tool), "#!/bin/sh\nexit 0\n");
        }

        let fw_code = dir.path().join("AAVMF_CODE.no-secboot.fd");
        let fw_vars = dir.path().join("AAVMF_VARS.fd");
        std::fs::write(&fw_code, b"code").unwrap();
        std::fs::write(&fw_vars, b"vars").unwrap();
        let resolv = dir.path().join("resolv.conf");
        std::fs::write(&resolv, "nameserver 127.0.0.53\n").unwrap();
        let log = dir.path().join("virsh.log");

        let ok = run_setup_env(
            &["preflight", "--state-dir", dir.path().to_str().unwrap()],
            &[
                ("FAKE_LOG", log.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", fw_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", fw_vars.to_str().unwrap()),
                ("QEMINGA_RESOLV_CONF", resolv.to_str().unwrap()),
                ("QEMINGA_MIN_DISK_GIB", "0"),
                ("QEMINGA_MIN_RAM_MIB", "0"),
            ],
            Some(&bin),
        );
        assert!(ok.status.success(), "{arch}: {}", text(&ok));

        // Missing /dev/kvm fails preflight on both arches.
        let no_kvm = run_setup_env(
            &["preflight", "--state-dir", dir.path().to_str().unwrap()],
            &[
                ("FAKE_LOG", log.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/nonexistent/kvm"),
                ("QEMINGA_AAVMF_CODE", fw_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", fw_vars.to_str().unwrap()),
                ("QEMINGA_RESOLV_CONF", resolv.to_str().unwrap()),
                ("QEMINGA_MIN_DISK_GIB", "0"),
                ("QEMINGA_MIN_RAM_MIB", "0"),
            ],
            Some(&bin),
        );
        assert!(!no_kvm.status.success(), "{arch}: {}", text(&no_kvm));

        // Private non-loopback nameserver triggers a helpful --allow-ip hint.
        let priv_resolv = dir.path().join("resolv-private.conf");
        std::fs::write(&priv_resolv, "nameserver 10.0.0.2\n").unwrap();
        let hinted = run_setup_env(
            &["preflight", "--state-dir", dir.path().to_str().unwrap()],
            &[
                ("FAKE_LOG", log.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", fw_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", fw_vars.to_str().unwrap()),
                ("QEMINGA_RESOLV_CONF", priv_resolv.to_str().unwrap()),
                ("QEMINGA_MIN_DISK_GIB", "0"),
                ("QEMINGA_MIN_RAM_MIB", "0"),
            ],
            Some(&bin),
        );
        assert!(hinted.status.success(), "{arch}: {}", text(&hinted));
        assert!(
            text(&hinted).contains("--allow-ip 10.0.0.2/32"),
            "{arch}: expected --allow-ip hint: {}",
            text(&hinted)
        );

        // On aarch64, missing UEFI firmware fails preflight.
        if arch == "aarch64" {
            let no_fw = run_setup_env(
                &["preflight", "--state-dir", dir.path().to_str().unwrap()],
                &[
                    ("FAKE_LOG", log.to_str().unwrap()),
                    ("QEMINGA_KVM_DEVICE", "/dev/null"),
                    ("QEMINGA_AAVMF_CODE", "/nonexistent/AAVMF_CODE.fd"),
                    ("QEMINGA_AAVMF_VARS", "/nonexistent/AAVMF_VARS.fd"),
                    ("QEMINGA_RESOLV_CONF", resolv.to_str().unwrap()),
                    ("QEMINGA_MIN_DISK_GIB", "0"),
                    ("QEMINGA_MIN_RAM_MIB", "0"),
                ],
                Some(&bin),
            );
            assert!(!no_fw.status.success(), "aarch64 without AAVMF must fail");
        }
    }
}

// ---- symlink safety, token-argv hygiene, and read-only launcher -----------

const FAKE_CHOWN: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_CHOWN_LOG:?}"
exit 0
"#;

const FAKE_INSTALL: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_INSTALL_LOG:?}"
is_dir=0
mode=""
while [ $# -gt 0 ]; do
    case "$1" in
        -d) is_dir=1; shift ;;
        -m) mode="$2"; shift 2 ;;
        -o|-g) shift 2 ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
if [ "$is_dir" -eq 1 ]; then
    for d in "$@"; do
        mkdir -p "$d"
        [ -n "$mode" ] && chmod "$mode" "$d"
    done
else
    src="$1"; dst="$2"
    cp "$src" "$dst"
    [ -n "$mode" ] && chmod "$mode" "$dst"
fi
"#;

#[test]
fn lock_runner_permissions_refuses_symlinks_and_non_regular_files() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(&bin.join("chown"), FAKE_CHOWN);
    write_exec(&bin.join("install"), FAKE_INSTALL);

    let run_lock = |install_dir: &Path, chown_log: &Path, install_log: &Path| -> Output {
        let path_env = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new("bash")
            .args([
                "-c",
                r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_USER="qeminga-runner"; OPT_ALLOW_AUTO_UPDATE=0; OPT_EPHEMERAL=0; lock_runner_permissions"#,
                "_",
                script().to_str().unwrap(),
                install_dir.to_str().unwrap(),
            ])
            .env("PATH", path_env)
            .env("FAKE_CHOWN_LOG", chown_log)
            .env("FAKE_INSTALL_LOG", install_log)
            .output()
            .unwrap()
    };

    // Planted symlinks for any config file, .env, or _diag must fail closed without touching targets.
    for entry in [
        ".runner",
        ".credentials",
        ".credentials_rsaparams",
        ".path",
        ".env",
    ] {
        let case_dir = dir
            .path()
            .join(format!("sym-{}", entry.trim_start_matches('.')));
        let install_dir = case_dir.join("runner");
        std::fs::create_dir_all(&install_dir).unwrap();
        let victim = case_dir.join("victim");
        std::fs::write(&victim, b"root-secret").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&victim, install_dir.join(entry)).unwrap();

        let chown_log = case_dir.join("chown.log");
        let install_log = case_dir.join("install.log");
        let out = run_lock(&install_dir, &chown_log, &install_log);
        assert!(
            !out.status.success(),
            "symlinked {entry} must be refused: {}",
            text(&out)
        );
        let victim_mode = std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            victim_mode, 0o644,
            "victim mode must stay untouched for symlinked {entry}"
        );
    }

    // Symlinked _diag directory must be refused.
    let diag_case = dir.path().join("sym-diag");
    let diag_install = diag_case.join("runner");
    let victim_dir = diag_case.join("victim-dir");
    std::fs::create_dir_all(&diag_install).unwrap();
    std::fs::create_dir_all(&victim_dir).unwrap();
    std::fs::set_permissions(&victim_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&victim_dir, diag_install.join("_diag")).unwrap();
    let out = run_lock(
        &diag_install,
        &diag_case.join("chown.log"),
        &diag_case.join("install.log"),
    );
    assert!(
        !out.status.success(),
        "symlinked _diag must be refused: {}",
        text(&out)
    );
    assert_eq!(
        std::fs::metadata(&victim_dir).unwrap().permissions().mode() & 0o777,
        0o755
    );

    // Symlinked OPT_INSTALL_DIR and symlinked bin/runsvc.sh must be refused.
    let top_case = dir.path().join("sym-top");
    let real_top = top_case.join("real");
    let link_top = top_case.join("link");
    std::fs::create_dir_all(&real_top).unwrap();
    symlink(&real_top, &link_top).unwrap();
    let out = run_lock(
        &link_top,
        &top_case.join("chown.log"),
        &top_case.join("install.log"),
    );
    assert!(
        !out.status.success(),
        "symlinked OPT_INSTALL_DIR must be refused: {}",
        text(&out)
    );

    let svc_case = dir.path().join("sym-runsvc");
    let svc_install = svc_case.join("runner");
    std::fs::create_dir_all(svc_install.join("bin")).unwrap();
    let svc_victim = svc_case.join("victim");
    std::fs::write(&svc_victim, b"x").unwrap();
    symlink(&svc_victim, svc_install.join("bin/runsvc.sh")).unwrap();
    let out = run_lock(
        &svc_install,
        &svc_case.join("chown.log"),
        &svc_case.join("install.log"),
    );
    assert!(
        !out.status.success(),
        "symlinked bin/runsvc.sh must be refused: {}",
        text(&out)
    );

    // Non-regular entries (directories) at .runner or .env must be refused.
    for entry in [".runner", ".env"] {
        let case_dir = dir
            .path()
            .join(format!("dir-{}", entry.trim_start_matches('.')));
        let install_dir = case_dir.join("runner");
        std::fs::create_dir_all(install_dir.join(entry)).unwrap();
        let out = run_lock(
            &install_dir,
            &case_dir.join("chown.log"),
            &case_dir.join("install.log"),
        );
        assert!(
            !out.status.success(),
            "non-regular {entry} must be refused: {}",
            text(&out)
        );
    }

    // Clean install directory succeeds, uses chown -h everywhere, and creates .env via install.
    let clean_case = dir.path().join("clean");
    let clean_install = clean_case.join("runner");
    std::fs::create_dir_all(clean_install.join("bin")).unwrap();
    std::fs::write(clean_install.join(".runner"), b"{}").unwrap();
    std::fs::write(clean_install.join(".credentials"), b"{}").unwrap();
    std::fs::write(clean_install.join("bin/runsvc.sh"), b"#!/bin/sh\n").unwrap();
    let chown_log = clean_case.join("chown.log");
    let install_log = clean_case.join("install.log");
    let out = run_lock(&clean_install, &chown_log, &install_log);
    assert!(out.status.success(), "clean lock failed: {}", text(&out));
    assert!(clean_install.join(".env").is_file(), ".env created");
    let chowns = std::fs::read_to_string(&chown_log).unwrap();
    for line in chowns.lines() {
        assert!(
            line.starts_with("-h "),
            "every chown in lock_runner_permissions must pass -h: {line}"
        );
    }
    let installs = std::fs::read_to_string(&install_log).unwrap();
    assert!(
        installs.contains("/dev/null") && installs.contains(".env"),
        "missing .env must be created via install: {installs}"
    );
}

#[test]
fn registration_and_uninstall_pass_tokens_only_via_inherited_env_never_argv() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();

    // Fake id reports root (uid 0) and existing service user; fake systemctl/chown are no-ops.
    write_exec(
        &bin.join("id"),
        "#!/bin/sh\nif [ \"$1\" = -u ]; then echo 0; fi\nexit 0\n",
    );
    write_exec(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("runuser"),
        r#"#!/bin/sh
printf '%s\n' "$*" > "${FAKE_RUNUSER_ARGV:?}"
printf '%s' "${ACTIONS_RUNNER_INPUT_TOKEN:-}" > "${FAKE_RUNUSER_ENV:?}"
exit 0
"#,
    );

    let install_dir = dir.path().join("runner");
    let state_dir = dir.path().join("state");
    let hook_dir = dir.path().join("hooks");
    let cfg_dir = dir.path().join("cfg");
    for d in [&install_dir, &state_dir, &hook_dir, &cfg_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    write_exec(&install_dir.join("config.sh"), "#!/bin/sh\nexit 0\n");

    // 1. Direct test of registration helper run_runner_config_with_token.
    let reg_argv_log = dir.path().join("runuser-reg.argv");
    let reg_env_log = dir.path().join("runuser-reg.env");
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let reg = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_USER="qeminga-runner"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; run_runner_config_with_token "SECRET_REG_TOKEN_12345" --unattended --replace --url "https://github.com/vicaya/qeminga""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_RUNUSER_ARGV", &reg_argv_log)
        .env("FAKE_RUNUSER_ENV", &reg_env_log)
        .output()
        .unwrap();
    assert!(
        reg.status.success(),
        "registration helper failed: {}",
        text(&reg)
    );
    let reg_argv = std::fs::read_to_string(&reg_argv_log).unwrap();
    let reg_env = std::fs::read_to_string(&reg_env_log).unwrap();
    assert!(
        !reg_argv.contains("SECRET_REG_TOKEN_12345"),
        "registration token must NEVER appear in runuser argv: {reg_argv}"
    );
    assert!(
        reg_argv.contains("-w ACTIONS_RUNNER_INPUT_TOKEN"),
        "runuser must explicitly whitelist ACTIONS_RUNNER_INPUT_TOKEN: {reg_argv}"
    );
    assert_eq!(
        reg_env, "SECRET_REG_TOKEN_12345",
        "registration token must be delivered via inherited environment"
    );

    // 2. End-to-end uninstall deregistration test.
    let token_file = dir.path().join("rm-token");
    std::fs::write(&token_file, "SECRET_RM_TOKEN_98765\n").unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let argv_log = dir.path().join("runuser-uninstall.argv");
    let env_log = dir.path().join("runuser-uninstall.env");
    let out = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-test-nonexistent-unit",
            "--install-dir",
            install_dir.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--hook-dir",
            hook_dir.to_str().unwrap(),
            "--config-dir",
            cfg_dir.to_str().unwrap(),
            "--token-file",
            token_file.to_str().unwrap(),
        ],
        &[
            ("FAKE_RUNUSER_ARGV", argv_log.to_str().unwrap()),
            ("FAKE_RUNUSER_ENV", env_log.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(out.status.success(), "uninstall failed: {}", text(&out));
    let argv = std::fs::read_to_string(&argv_log).unwrap();
    let env_token = std::fs::read_to_string(&env_log).unwrap();
    assert!(
        !argv.contains("SECRET_RM_TOKEN_98765"),
        "removal token must NEVER appear in runuser argv: {argv}"
    );
    assert!(
        argv.contains("-w ACTIONS_RUNNER_INPUT_TOKEN"),
        "runuser must explicitly whitelist ACTIONS_RUNNER_INPUT_TOKEN: {argv}"
    );
    assert_eq!(
        env_token, "SECRET_RM_TOKEN_98765",
        "removal token must be delivered via inherited environment"
    );

    // Registration/deregistration script must never expand ACTIONS_RUNNER_INPUT_TOKEN into command argv.
    let body = std::fs::read_to_string(script()).unwrap();
    for line in body.lines() {
        let trimmed = line.trim();
        assert!(
            !(trimmed.contains("ACTIONS_RUNNER_INPUT_TOKEN=$") && !trimmed.starts_with("export ")),
            "token must never be expanded into command argv: {trimmed}"
        );
    }
}

#[test]
fn jit_launcher_execs_runner_listener_directly_without_writing_install_dir() {
    let dir = tempfile::tempdir().unwrap();
    let install_dir = dir.path().join("runner");
    let bin_dir = install_dir.join("bin");
    let cred_dir = dir.path().join("creds");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&cred_dir).unwrap();

    let listener_args = dir.path().join("listener.args");
    let listener_jit = dir.path().join("listener.jit");
    write_exec(
        &bin_dir.join("Runner.Listener"),
        r#"#!/bin/sh
printf '%s' "$*" > "${FAKE_LISTENER_ARGS:?}"
printf '%s' "${ACTIONS_RUNNER_INPUT_JITCONFIG:-}" > "${FAKE_LISTENER_JIT:?}"
exit 0
"#,
    );
    write_exec(
        &install_dir.join("run.sh"),
        "#!/bin/sh\necho 'run.sh must not be invoked' >&2\nexit 99\n",
    );
    std::fs::write(cred_dir.join("jitconfig"), "JIT_SECRET_VALUE\n").unwrap();

    let launcher = dir.path().join("run-jit.sh");
    let generated = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; write_jit_launcher "$3""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            launcher.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(generated.status.success(), "{}", text(&generated));

    // Make install_dir read-only to prove the launcher never writes run-helper.sh.
    std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let run = Command::new(&launcher)
        .env("CREDENTIALS_DIRECTORY", &cred_dir)
        .env("FAKE_LISTENER_ARGS", &listener_args)
        .env("FAKE_LISTENER_JIT", &listener_jit)
        .output()
        .unwrap();
    std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(run.status.success(), "run-jit.sh failed: {}", text(&run));
    assert_eq!(
        std::fs::read_to_string(&listener_args).unwrap(),
        "run --startuptype service"
    );
    assert_eq!(
        std::fs::read_to_string(&listener_jit).unwrap(),
        "JIT_SECRET_VALUE"
    );
}
