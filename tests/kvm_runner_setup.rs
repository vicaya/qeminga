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

const REPO_URL: &str = "https://github.com/vicaya/qeminga-kvm-controller";
const PUBLIC_REPO_URL: &str = "https://github.com/vicaya/qeminga";

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
        "ExecStartPre=/usr/local/libexec/qeminga-runner/check-egress-firewall.sh",
        "ExecStart=/opt/qeminga-runner/bin/runsvc.sh",
        "RestartPreventExitStatus=78",
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
    write_exec(
        &fake_hooks.join("check-egress-firewall.sh"),
        "#!/bin/sh\nexit 0\n",
    );
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
        if !verify.status.success()
            && std::env::var_os("CI").is_none()
            && combined.contains("Failed to create /run/systemd")
        {
            eprintln!("skipped systemd-analyze verify in unprivileged container: {combined}");
            return;
        }
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
    let ctrl_repo = "vicaya/qeminga-kvm-controller";
    let valid_wf_ref =
        "vicaya/qeminga-kvm-controller/.github/workflows/libvirt-kvm.yml@refs/heads/main";
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
            ctrl_repo,
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
            "vicaya/qeminga-kvm-controller-fork",
            "workflow_dispatch",
            "refs/heads/main",
            "vicaya/qeminga-kvm-controller-fork/.github/workflows/libvirt-kvm.yml@refs/heads/main",
            "vicaya",
        ),
        (
            "pull_request",
            ctrl_repo,
            "pull_request",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
        (
            "pull_request_target",
            ctrl_repo,
            "pull_request_target",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
        (
            "unlisted-push",
            ctrl_repo,
            "push",
            "refs/heads/main",
            valid_wf_ref,
            "vicaya",
        ),
        (
            "wrong-branch",
            ctrl_repo,
            "workflow_dispatch",
            "refs/heads/feature",
            "vicaya/qeminga-kvm-controller/.github/workflows/libvirt-kvm.yml@refs/heads/feature",
            "vicaya",
        ),
        (
            "wrong-workflow",
            ctrl_repo,
            "workflow_dispatch",
            "refs/heads/main",
            "vicaya/qeminga-kvm-controller/.github/workflows/ci.yml@refs/heads/main",
            "vicaya",
        ),
        (
            "wrong-actor",
            ctrl_repo,
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
            ctrl_repo,
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
        ctrl_repo,
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
        ctrl_repo,
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
        ctrl_repo,
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
            "python3",
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
        let cgroup_ctrls = dir.path().join("cgroup.controllers");
        std::fs::write(&cgroup_ctrls, "cpu memory pids\n").unwrap();
        let log = dir.path().join("virsh.log");

        let ok = run_setup_env(
            &["preflight", "--state-dir", dir.path().to_str().unwrap()],
            &[
                ("FAKE_LOG", log.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", fw_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", fw_vars.to_str().unwrap()),
                ("QEMINGA_RESOLV_CONF", resolv.to_str().unwrap()),
                ("QEMINGA_CGROUP_CONTROLLERS", cgroup_ctrls.to_str().unwrap()),
                ("QEMINGA_MIN_DISK_GIB", "0"),
                ("QEMINGA_MIN_RAM_MIB", "0"),
            ],
            Some(&bin),
        );
        assert!(ok.status.success(), "{arch}: {}", text(&ok));

        // Missing cgroup v2 fails preflight (systemd IPAddressDeny BPF firewall requires cgroup v2).
        let no_cg2 = run_setup_env(
            &["preflight", "--state-dir", dir.path().to_str().unwrap()],
            &[
                ("FAKE_LOG", log.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", fw_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", fw_vars.to_str().unwrap()),
                ("QEMINGA_RESOLV_CONF", resolv.to_str().unwrap()),
                (
                    "QEMINGA_CGROUP_CONTROLLERS",
                    "/nonexistent/cgroup.controllers",
                ),
                ("QEMINGA_MIN_DISK_GIB", "0"),
                ("QEMINGA_MIN_RAM_MIB", "0"),
            ],
            Some(&bin),
        );
        assert!(
            !no_cg2.status.success(),
            "{arch}: missing cgroup v2 must fail preflight: {}",
            text(&no_cg2)
        );

        // Missing /dev/kvm fails preflight on both arches.
        let no_kvm = run_setup_env(
            &["preflight", "--state-dir", dir.path().to_str().unwrap()],
            &[
                ("FAKE_LOG", log.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/nonexistent/kvm"),
                ("QEMINGA_AAVMF_CODE", fw_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", fw_vars.to_str().unwrap()),
                ("QEMINGA_RESOLV_CONF", resolv.to_str().unwrap()),
                ("QEMINGA_CGROUP_CONTROLLERS", cgroup_ctrls.to_str().unwrap()),
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
                ("QEMINGA_CGROUP_CONTROLLERS", cgroup_ctrls.to_str().unwrap()),
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
                    ("QEMINGA_CGROUP_CONTROLLERS", cgroup_ctrls.to_str().unwrap()),
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
        &bin.join("stat"),
        r#"#!/bin/sh
# Report uid 0 for ownership checks while delegating mode checks to real stat.
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then
    echo 0
    exit 0
fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then
    mode="$(/usr/bin/stat -c '%a' "$3")"
    echo "0:${mode}"
    exit 0
fi
exec /usr/bin/stat "$@"
"#,
    );
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
    std::fs::write(
        cfg_dir.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nSERVICE=qeminga-test-nonexistent-unit\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test-runner\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\n",
            install_dir.display(),
            state_dir.display(),
            hook_dir.display(),
            cfg_dir.display(),
            state_dir.display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(
        cfg_dir.join("install.env"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

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
            r#"source "$1"; OPT_USER="qeminga-runner"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; run_runner_config_with_token "SECRET_REG_TOKEN_12345" --unattended --replace --url "https://github.com/vicaya/qeminga-kvm-controller""#,
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

// ---- Round 2 security & lifecycle hardening tests -------------------------

fn b64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn make_jit_config(github_url: &str, work_folder: &str) -> String {
    let runner_json = format!(
        "\u{feff}{{\"agentId\":1,\"agentName\":\"jit-test\",\"gitHubUrl\":\"{github_url}\",\"workFolder\":\"{work_folder}\"}}"
    );
    let outer = format!("{{\".runner\":\"{}\"}}", b64(runner_json.as_bytes()));
    b64(outer.as_bytes())
}

#[test]
fn refuses_direct_public_repo_registration_and_requires_controller_or_runner_group() {
    let tmp = tempfile::tempdir().unwrap();

    // Direct registration against public vicaya/qeminga must be refused everywhere.
    for args in [
        vec!["render-unit", "--repo", PUBLIC_REPO_URL, "--arch", "x86_64"],
        vec![
            "render-hooks",
            "--repo",
            PUBLIC_REPO_URL,
            "--out",
            tmp.path().to_str().unwrap(),
        ],
    ] {
        let out = run_setup(&args);
        assert!(
            !out.status.success(),
            "public repo must be refused for {args:?}: {}",
            text(&out)
        );
        let msg = text(&out).to_ascii_lowercase();
        assert!(
            msg.contains("private") || msg.contains("controller") || msg.contains("runner-group"),
            "error should guide operator to private controller or runner group: {msg}"
        );
    }

    // verify_private_repo fails closed when GitHub reports a public repository (HTTP 200, private=false)
    // and succeeds when GitHub returns 404 (unauthenticated private repository).
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
if [ "${FAKE_REPO_PUBLIC:-0}" = 1 ]; then
    printf '{"private":false}\n200'
else
    printf '{"message":"Not Found"}\n404'
fi
"#,
    );
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let pub_check = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; verify_private_repo "someone/public-repo""#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_REPO_PUBLIC", "1")
        .output()
        .unwrap();
    assert!(
        !pub_check.status.success(),
        "public repository must fail verify_private_repo: {}",
        text(&pub_check)
    );
    let priv_check = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; verify_private_repo "vicaya/qeminga-kvm-controller""#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_REPO_PUBLIC", "0")
        .output()
        .unwrap();
    assert!(
        priv_check.status.success(),
        "private repository (HTTP 404 unauth) should pass verify_private_repo: {}",
        text(&priv_check)
    );

    // Organization runner-group mode requires BOTH a non-Default --runner-group AND --allow-repo.
    for bad_org_args in [
        vec![
            "render-unit",
            "--org",
            "https://github.com/myorg",
            "--arch",
            "x86_64",
        ],
        vec![
            "render-unit",
            "--org",
            "https://github.com/myorg",
            "--runner-group",
            "Default",
            "--allow-repo",
            "vicaya/qeminga",
            "--arch",
            "x86_64",
        ],
        vec![
            "render-unit",
            "--org",
            "https://github.com/myorg",
            "--runner-group",
            "qeminga-kvm-restricted",
            "--arch",
            "x86_64",
        ],
        vec![
            "render-unit",
            "--repo",
            REPO_URL,
            "--org",
            "https://github.com/myorg",
            "--runner-group",
            "qeminga-kvm-restricted",
            "--allow-repo",
            "vicaya/qeminga",
            "--arch",
            "x86_64",
        ],
    ] {
        let out = run_setup(&bad_org_args);
        assert!(
            !out.status.success(),
            "unsafe org args must fail {bad_org_args:?}: {}",
            text(&out)
        );
    }

    let hooks_org = tmp.path().join("org-hooks");
    let ok_org = run_setup(&[
        "render-hooks",
        "--org",
        "https://github.com/myorg",
        "--runner-group",
        "qeminga-kvm-restricted",
        "--allow-repo",
        "vicaya/qeminga",
        "--out",
        hooks_org.to_str().unwrap(),
    ]);
    assert!(ok_org.status.success(), "{}", text(&ok_org));
    let policy = std::fs::read_to_string(hooks_org.join("policy.env")).unwrap();
    assert!(
        policy.contains("ALLOWED_REPOSITORY=vicaya/qeminga\n"),
        "{policy}"
    );

    // Documentation must default to the private controller repo, never direct public vicaya/qeminga.
    let testing_doc = std::fs::read_to_string(root().join("docs/testing.md")).unwrap();
    assert!(
        !testing_doc.contains("install \\\n  --repo https://github.com/vicaya/qeminga\n"),
        "docs/testing.md must not instruct registering directly on public vicaya/qeminga"
    );
}

#[test]
fn provision_state_dirs_uses_runner_uid_and_stops_service_before_mutating() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(&bin.join("install"), FAKE_INSTALL);
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then
    echo "0:755"
    exit 0
fi
exec /usr/bin/stat "$@"
"#,
    );
    write_exec(
        &bin.join("runuser"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_RUNUSER_LOG:?}"
while [ $# -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        *) shift ;;
    esac
done
exec "$@"
"#,
    );

    let state_dir = dir.path().join("state");
    let install_log = dir.path().join("install.log");
    let runuser_log = dir.path().join("runuser.log");
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let ok = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_STATE_DIR="$2"; OPT_USER="qeminga-runner"; provision_state_dirs"#,
            "_",
            script().to_str().unwrap(),
            state_dir.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_INSTALL_LOG", &install_log)
        .env("FAKE_RUNUSER_LOG", &runuser_log)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "provision_state_dirs failed: {}",
        text(&ok)
    );

    // Root install -d must touch ONLY the top-level state directory, never any descendant.
    let root_installs = std::fs::read_to_string(&install_log).unwrap();
    assert!(
        !root_installs.contains("/work")
            && !root_installs.contains("/images")
            && !root_installs.contains("/.local"),
        "root install must not create state descendants: {root_installs}"
    );
    let user_calls = std::fs::read_to_string(&runuser_log).unwrap();
    assert!(
        user_calls.contains("-u qeminga-runner"),
        "state descendants must be created as service user: {user_calls}"
    );
    for sub in [
        "work",
        "images",
        "image-cache",
        ".config",
        ".cache",
        ".local/share",
    ] {
        assert!(state_dir.join(sub).is_dir(), "missing state subdir {sub}");
    }

    // Symlinked top-level state dir must be refused.
    let real_target = dir.path().join("real-target");
    std::fs::create_dir_all(&real_target).unwrap();
    let sym_state = dir.path().join("sym-state");
    symlink(&real_target, &sym_state).unwrap();
    let bad = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_STATE_DIR="$2"; OPT_USER="qeminga-runner"; provision_state_dirs"#,
            "_",
            script().to_str().unwrap(),
            sym_state.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_INSTALL_LOG", &install_log)
        .env("FAKE_RUNUSER_LOG", &runuser_log)
        .output()
        .unwrap();
    assert!(!bad.status.success(), "symlinked state dir must be refused");

    // In cmd_install, systemctl stop must happen before provision_state_dirs.
    let body = std::fs::read_to_string(script()).unwrap();
    let install_fn = &body[body.find("cmd_install()").unwrap()..];
    let stop_pos = install_fn.find("systemctl stop").unwrap();
    let prov_pos = install_fn.find("provision_state_dirs").unwrap();
    assert!(
        stop_pos < prov_pos,
        "cmd_install must stop the existing service before mutating state directories"
    );
}

#[test]
fn egress_firewall_check_gates_unit_startup_and_fails_closed_when_unfiltered() {
    let dir = tempfile::tempdir().unwrap();
    let hooks_out = dir.path().join("hooks");
    let rendered = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks_out.to_str().unwrap(),
    ]);
    assert!(rendered.status.success(), "{}", text(&rendered));

    let check = hooks_out.join("check-egress-firewall.sh");
    assert!(
        check.is_file(),
        "render-hooks must write check-egress-firewall.sh"
    );

    // Controlled local check on an unfiltered cgroup (no IPAddressDeny BPF active):
    // must fail closed with EX_CONFIG (78) before the listener ever starts.
    let unfiltered = Command::new("bash")
        .arg(&check)
        .env("QEMINGA_RUNNER_POLICY", hooks_out.join("policy.env"))
        .output()
        .unwrap();
    assert_eq!(
        unfiltered.status.code(),
        Some(78),
        "unfiltered cgroup must exit 78 (EX_CONFIG): {}",
        text(&unfiltered)
    );
    assert!(
        text(&unfiltered).contains("169.254.169.254") || text(&unfiltered).contains("BPF"),
        "diagnostic should explain failed egress block: {}",
        text(&unfiltered)
    );

    // Controlled simulated outcomes via sitecustomize hook on PYTHONPATH:
    let site_dir = dir.path().join("site");
    std::fs::create_dir_all(&site_dir).unwrap();
    std::fs::write(
        site_dir.join("sitecustomize.py"),
        r#"import errno, os, socket
mode = os.environ.get("FAKE_SOCKET_MODE")
if mode:
    _orig = socket.socket.sendto
    def _patched(self, data, addr):
        host = addr[0]
        if mode == "v4_eperm_v6_unreach":
            if host == "169.254.169.254":
                raise OSError(errno.EPERM, "Operation not permitted")
            raise OSError(errno.ENETUNREACH, "Network is unreachable")
        if mode == "v4_unreach_v6_eperm":
            if host == "fd00:ec2::254":
                raise OSError(errno.EPERM, "Operation not permitted")
            raise OSError(errno.ENETUNREACH, "Network is unreachable")
        if mode == "all_unreach":
            raise OSError(errno.ENETUNREACH, "Network is unreachable")
        if mode == "v4_eperm_v6_sent":
            if host == "169.254.169.254":
                raise OSError(errno.EPERM, "Operation not permitted")
            return len(data)
        return _orig(self, data, addr)
    socket.socket.sendto = _patched
"#,
    )
    .unwrap();

    for (mode, want_code) in [
        ("v4_eperm_v6_unreach", 0),
        ("v4_unreach_v6_eperm", 0),
        ("all_unreach", 78),
        ("v4_eperm_v6_sent", 78),
    ] {
        let out = Command::new("bash")
            .arg(&check)
            .env("PYTHONPATH", &site_dir)
            .env("FAKE_SOCKET_MODE", mode)
            .env("QEMINGA_RUNNER_POLICY", hooks_out.join("policy.env"))
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(want_code),
            "mode={mode}: {}",
            text(&out)
        );
    }
}

#[test]
fn install_record_scopes_uninstall_refuses_unmanaged_dirs_and_preserves_images_on_cleanup_failure()
{
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(
        &bin.join("id"),
        "#!/bin/sh\nif [ \"$1\" = -u ]; then echo 0; fi\nexit 0\n",
    );
    write_exec(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:755"; exit 0; fi
exec /usr/bin/stat "$@"
"#,
    );
    write_exec(
        &bin.join("runuser"),
        r#"#!/bin/sh
while [ $# -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        *) shift ;;
    esac
done
exec "$@"
"#,
    );

    // 1. Uninstall WITHOUT a valid install.env must refuse and leave unrelated directories intact.
    let shared_install = dir.path().join("shared-install");
    let shared_state = dir.path().join("shared-state");
    let shared_hooks = dir.path().join("shared-hooks");
    let shared_cfg = dir.path().join("shared-cfg");
    for d in [&shared_install, &shared_state, &shared_hooks, &shared_cfg] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(shared_install.join("precious.txt"), b"do-not-delete").unwrap();

    let no_rec = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-test-unmanaged",
            "--install-dir",
            shared_install.to_str().unwrap(),
            "--state-dir",
            shared_state.to_str().unwrap(),
            "--hook-dir",
            shared_hooks.to_str().unwrap(),
            "--config-dir",
            shared_cfg.to_str().unwrap(),
        ],
        &[],
        Some(&bin),
    );
    assert!(
        !no_rec.status.success(),
        "uninstall without install.env must fail closed: {}",
        text(&no_rec)
    );
    assert!(
        shared_install.join("precious.txt").exists(),
        "unrelated files must NEVER be deleted without install.env"
    );

    // 2. check_dedicated_managed_dirs rejects overlapping paths and pre-existing unmanaged dirs on fresh install.
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let overlap = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$2/sub"; OPT_HOOK_DIR="$3"; OPT_CONFIG_DIR="$4"; check_dedicated_managed_dirs 0"#,
            "_",
            script().to_str().unwrap(),
            dir.path().join("ov-a").to_str().unwrap(),
            dir.path().join("ov-b").to_str().unwrap(),
            dir.path().join("ov-c").to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .output()
        .unwrap();
    assert!(
        !overlap.status.success(),
        "overlapping dirs must be refused"
    );

    let unmanaged = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_HOOK_DIR="$4"; OPT_CONFIG_DIR="$5"; check_dedicated_managed_dirs 0"#,
            "_",
            script().to_str().unwrap(),
            shared_install.to_str().unwrap(),
            dir.path().join("fresh-state").to_str().unwrap(),
            dir.path().join("fresh-hooks").to_str().unwrap(),
            dir.path().join("fresh-cfg").to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .output()
        .unwrap();
    assert!(
        !unmanaged.status.success(),
        "fresh install must refuse to adopt pre-existing unmanaged directory: {}",
        text(&unmanaged)
    );

    // 3. Uninstall preserves state/images when hook-job-completed.sh reports failure (unknown domain state).
    let case3 = dir.path().join("preserve-images");
    let inst3 = case3.join("runner");
    let state3 = case3.join("state");
    let hooks3 = case3.join("hooks");
    let cfg3 = case3.join("cfg");
    let vm_disk = state3.join("images/qeminga-e2e-55-1-x86_64/root.qcow2");
    std::fs::create_dir_all(vm_disk.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&inst3).unwrap();
    std::fs::create_dir_all(&hooks3).unwrap();
    std::fs::create_dir_all(&cfg3).unwrap();
    std::fs::write(&vm_disk, b"active-vm-disk").unwrap();
    std::fs::write(
        cfg3.join("policy.env"),
        "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\n",
    )
    .unwrap();
    write_exec(
        &hooks3.join("hook-job-completed.sh"),
        "#!/bin/sh\necho 'cannot establish domain state' >&2\nexit 1\n",
    );
    std::fs::write(
        cfg3.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nSERVICE=qeminga-test-preserve\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\n",
            inst3.display(),
            state3.display(),
            hooks3.display(),
            cfg3.display(),
            state3.display(),
        ),
    )
    .unwrap();

    let rt_root = dir.path().join("run");
    std::fs::create_dir_all(&rt_root).unwrap();
    let fail_uninst = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-test-preserve",
            "--install-dir",
            inst3.to_str().unwrap(),
            "--state-dir",
            state3.to_str().unwrap(),
            "--hook-dir",
            hooks3.to_str().unwrap(),
            "--config-dir",
            cfg3.to_str().unwrap(),
        ],
        &[("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap())],
        Some(&bin),
    );
    assert!(
        !fail_uninst.status.success(),
        "uninstall must fail non-zero when cleanup hook cannot confirm domains absent: {}",
        text(&fail_uninst)
    );
    assert!(
        vm_disk.exists(),
        "VM disk under images/ MUST be preserved when cleanup hook fails"
    );
}

#[test]
fn ensure_service_user_refuses_unrelated_account_and_extra_groups() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
case "$1" in
    -u) echo "${FAKE_UID:-995}" ;;
    -g) echo "${FAKE_GID:-995}" ;;
    -gn) echo "${FAKE_PGROUP:-qeminga-runner}" ;;
    -nG) echo "${FAKE_GROUPS:-qeminga-runner kvm}" ;;
    *) exit 0 ;;
esac
"#,
    );
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // 1. Fresh install (HAS_INSTALL_RECORD=0) must refuse an already-existing unrelated account.
    let fresh = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_USER="qeminga-runner"; HAS_INSTALL_RECORD=0; ensure_service_user"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .output()
        .unwrap();
    assert!(
        !fresh.status.success(),
        "fresh install must refuse existing unrelated user: {}",
        text(&fresh)
    );

    // 2. Reinstall with matching UID, GID, and exact allowlisted groups {qeminga-runner, kvm} succeeds.
    let ok_reuse = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_USER="qeminga-runner"; HAS_INSTALL_RECORD=1; REC_USER_UID=995; REC_USER_GID=995; REC_USER_CREATED=1; ensure_service_user"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_UID", "995")
        .env("FAKE_GID", "995")
        .env("FAKE_GROUPS", "qeminga-runner kvm")
        .output()
        .unwrap();
    assert!(
        ok_reuse.status.success(),
        "matching managed account should reuse cleanly: {}",
        text(&ok_reuse)
    );

    // 3. Extra site-specific group (outside {qeminga-runner, kvm}) must be refused.
    let extra_group = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_USER="qeminga-runner"; HAS_INSTALL_RECORD=1; REC_USER_UID=995; REC_USER_GID=995; REC_USER_CREATED=1; ensure_service_user"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_GROUPS", "qeminga-runner kvm site-backups")
        .output()
        .unwrap();
    assert!(
        !extra_group.status.success(),
        "unexpected site-specific group must be refused: {}",
        text(&extra_group)
    );

    // 4. UID drift from recorded UID must be refused.
    let uid_drift = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_USER="qeminga-runner"; HAS_INSTALL_RECORD=1; REC_USER_UID=995; REC_USER_GID=995; REC_USER_CREATED=1; ensure_service_user"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_UID", "1050")
        .output()
        .unwrap();
    assert!(
        !uid_drift.status.success(),
        "mismatched UID must be refused: {}",
        text(&uid_drift)
    );
}

#[test]
fn existing_registration_check_and_rollback_on_failed_reconfig() {
    let dir = tempfile::tempdir().unwrap();
    let install_dir = dir.path().join("runner");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();

    // Write a UTF-8-BOM .runner file like actions/runner produces.
    let runner_json = format!(
        "\u{feff}{{\"agentId\":1,\"agentName\":\"qeminga-kvm-x86_64-box\",\"gitHubUrl\":\"{REPO_URL}\",\"workFolder\":\"{}/work\"}}",
        state_dir.display()
    );
    std::fs::write(install_dir.join(".runner"), &runner_json).unwrap();

    // 1. Matching existing registration returns "reuse".
    let reuse = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; check_existing_registration "$4" "qeminga-kvm-x86_64-box""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            REPO_URL,
        ])
        .output()
        .unwrap();
    assert!(reuse.status.success(), "{}", text(&reuse));
    assert_eq!(String::from_utf8_lossy(&reuse.stdout).trim(), "reuse");

    // 2. Incompatible target URL or runner name must fail immediately before mutating anything.
    let mismatch = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; check_existing_registration "https://github.com/other/controller" "qeminga-kvm-x86_64-box""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            REPO_URL,
        ])
        .output()
        .unwrap();
    assert!(
        !mismatch.status.success(),
        "incompatible existing registration must be refused: {}",
        text(&mismatch)
    );

    // 3. Failed config.sh restores locked permissions and restarts previously-active service.
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let sc_log = dir.path().join("systemctl.log");
    let chown_log = dir.path().join("chown.log");
    let install_log = dir.path().join("install.log");
    write_exec(
        &bin.join("systemctl"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_SC_LOG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("chown"), FAKE_CHOWN);
    write_exec(&bin.join("install"), FAKE_INSTALL);
    write_exec(&bin.join("runuser"), "#!/bin/sh\nexit 1\n");
    std::fs::create_dir_all(install_dir.join("bin")).unwrap();
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let rb = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_USER="qeminga-runner"; OPT_SERVICE="qeminga-kvm-runner"; OPT_ALLOW_AUTO_UPDATE=0; OPT_EPHEMERAL=0; register_runner_with_rollback 1 "TOK" --unattended"#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_SC_LOG", &sc_log)
        .env("FAKE_CHOWN_LOG", &chown_log)
        .env("FAKE_INSTALL_LOG", &install_log)
        .output()
        .unwrap();
    assert!(
        !rb.status.success(),
        "failed config.sh must still exit non-zero"
    );
    let sc = std::fs::read_to_string(&sc_log).unwrap();
    assert!(
        sc.contains("start qeminga-kvm-runner.service"),
        "rollback must restart previously active service: {sc}"
    );
    let ch = std::fs::read_to_string(&chown_log).unwrap();
    assert!(
        ch.contains("-h -R -P root:root"),
        "rollback must restore locked runner permissions: {ch}"
    );
}

#[test]
fn jit_workspace_validation_and_post_job_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let install_dir = dir.path().join("runner");
    let state_dir = dir.path().join("state");
    let hooks_out = dir.path().join("hooks");
    let bin = dir.path().join("bin");
    for d in [
        install_dir.join("bin"),
        install_dir.join("_work"),
        state_dir.join("work"),
        state_dir.join("images"),
        state_dir.join("image-cache"),
        bin.clone(),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    write_exec(&bin.join("virsh"), FAKE_VIRSH_STATEFUL);

    // 1. Default GitHub JIT API workFolder ("_work" under install_dir) is validated and scrubbed.
    let jit_default_file = dir.path().join("jit-default");
    std::fs::write(&jit_default_file, make_jit_config(REPO_URL, "_work")).unwrap();
    std::fs::set_permissions(&jit_default_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let rendered = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--install-dir",
        install_dir.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--jitconfig-file",
        jit_default_file.to_str().unwrap(),
        "--out",
        hooks_out.to_str().unwrap(),
    ]);
    assert!(rendered.status.success(), "{}", text(&rendered));
    let policy_path = hooks_out.join("policy.env");
    let policy = std::fs::read_to_string(&policy_path).unwrap();
    assert!(
        policy.contains(&format!("WORK_DIR={}/_work\n", install_dir.display())),
        "default JIT _work must be recorded in policy.env:\n{policy}"
    );

    // Populate _work with files + dotfiles and verify hook-job-completed.sh scrubs _work cleanly.
    std::fs::write(install_dir.join("_work/secret.txt"), b"leftover").unwrap();
    std::fs::write(install_dir.join("_work/.dotfile"), b"leftover").unwrap();
    std::fs::write(install_dir.join("bin/keep"), b"runner-bin").unwrap();
    std::fs::write(state_dir.join("image-cache/img"), b"cache").unwrap();
    let log = dir.path().join("virsh.log");
    let cleanup = run_hook(
        &hooks_out.join("hook-job-completed.sh"),
        &policy_path,
        &bin,
        &[("FAKE_LOG", log.to_str().unwrap())],
    );
    assert!(cleanup.status.success(), "{}", text(&cleanup));
    assert_eq!(
        std::fs::read_dir(install_dir.join("_work"))
            .unwrap()
            .count(),
        0,
        "JIT _work directory must be scrubbed completely"
    );
    assert!(
        install_dir.join("bin/keep").exists(),
        "bin/ must stay untouched"
    );
    assert!(
        state_dir.join("image-cache/img").exists(),
        "image-cache must stay untouched"
    );

    // 2. Malicious/escaped JIT workFolder or mismatched gitHubUrl must fail closed.
    for (label, url, wf) in [
        ("traversal", REPO_URL, "../../etc"),
        ("outside-abs", REPO_URL, "/tmp/outside"),
        ("bin-dir", REPO_URL, "bin"),
        ("dot-dir", REPO_URL, "."),
        ("wrong-repo", "https://github.com/evil/repo", "_work"),
    ] {
        let bad_jit = dir.path().join(format!("jit-{label}"));
        std::fs::write(&bad_jit, make_jit_config(url, wf)).unwrap();
        std::fs::set_permissions(&bad_jit, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out_dir = dir.path().join(format!("hooks-{label}"));
        let out = run_setup(&[
            "render-hooks",
            "--repo",
            REPO_URL,
            "--install-dir",
            install_dir.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--jitconfig-file",
            bad_jit.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ]);
        assert!(
            !out.status.success(),
            "bad JIT config ({label}) must be refused: {}",
            text(&out)
        );
    }
}

#[test]
fn uninstall_provides_private_runtime_dir_for_cleanup_after_stopping_service() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let rt_root = dir.path().join("run");
    let service_rt = rt_root.join("qeminga-test-rt");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [&bin, &rt_root, &service_rt, &inst, &state, &hooks, &cfg] {
        std::fs::create_dir_all(d).unwrap();
    }

    let userdel_log = dir.path().join("userdel.log");
    let rt_seen_log = dir.path().join("rt_seen.log");
    let daemon_pids_log = dir.path().join("daemon.pids");

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    // Simulate systemd removing RuntimeDirectory= when the service stops.
    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "stop" ] && [ "${FAKE_KEEP_SERVICE_RT:-0}" != "1" ]; then
    rm -rf "${FAKE_SERVICE_RT:?}"
fi
exit 0
"#,
    );
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    // Fail userdel if any simulated libvirt daemon PID is still alive, matching
    // real userdel ("user is currently used by process").
    write_exec(
        &bin.join("userdel"),
        r#"#!/bin/sh
if [ -f "${FAKE_DAEMON_PIDS_LOG:-}" ]; then
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if kill -0 "$p" 2>/dev/null; then
            echo "userdel: user $1 is currently used by process $p" >&2
            exit 8
        fi
    done <"${FAKE_DAEMON_PIDS_LOG}"
fi
printf '%s\n' "$*" >> "${FAKE_USERDEL_LOG:?}"
exit 0
"#,
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then
    if [ -n "${FAKE_LIVE_RT_PATH:-}" ] && [ "$3" = "$FAKE_LIVE_RT_PATH" ]; then
        echo "${FAKE_LIVE_RT_STAT:-995:700}"
        exit 0
    fi
    echo "0:755"
    exit 0
fi
exec /usr/bin/stat "$@"
"#,
    );
    write_exec(
        &bin.join("runuser"),
        r#"#!/bin/sh
while [ $# -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        *) shift ;;
    esac
done
exec "$@"
"#,
    );

    let write_install_env = |cfg_dir: &Path,
                             service: &str,
                             inst_dir: &Path,
                             state_dir: &Path,
                             hook_dir: &Path| {
        std::fs::write(
            cfg_dir.join("policy.env"),
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\n",
        )
        .unwrap();
        std::fs::write(
            cfg_dir.join("install.env"),
            format!(
                "RECORD_SCHEMA=1\nSERVICE={service}\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\n",
                inst_dir.display(),
                state_dir.display(),
                hook_dir.display(),
                cfg_dir.display(),
                state_dir.display(),
            ),
        )
        .unwrap();
    };

    // 1. Ordinary uninstall after systemctl stop removes RuntimeDirectory=:
    //    must provision a private mode-0700 XDG_RUNTIME_DIR, isolate XDG env
    //    vars from the invoking root shell, terminate both monolithic and
    //    auxiliary session libvirt daemons before userdel, and remove the temp dir.
    write_exec(
        &hooks.join("hook-job-completed.sh"),
        r#"#!/bin/sh
set -eu
[ -n "${XDG_RUNTIME_DIR:-}" ] || { echo "missing XDG_RUNTIME_DIR" >&2; exit 1; }
[ -d "$XDG_RUNTIME_DIR" ] || { echo "XDG_RUNTIME_DIR does not exist: $XDG_RUNTIME_DIR" >&2; exit 1; }
mode="$(/usr/bin/stat -c '%a' "$XDG_RUNTIME_DIR")"
[ "$mode" = "700" ] || { echo "XDG_RUNTIME_DIR mode $mode != 700" >&2; exit 1; }
[ "${XDG_CONFIG_HOME:-}" = "${HOME}/.config" ] || { echo "unexpected XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-}" >&2; exit 1; }
[ "${XDG_CACHE_HOME:-}" = "${HOME}/.cache" ] || { echo "unexpected XDG_CACHE_HOME=${XDG_CACHE_HOME:-}" >&2; exit 1; }
[ "${XDG_DATA_HOME:-}" = "${HOME}/.local/share" ] || { echo "unexpected XDG_DATA_HOME=${XDG_DATA_HOME:-}" >&2; exit 1; }
[ "${LIBVIRT_DEFAULT_URI:-}" = "qemu:///session" ] || { echo "unexpected LIBVIRT_DEFAULT_URI=${LIBVIRT_DEFAULT_URI:-}" >&2; exit 1; }
[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] || { echo "caller DBUS_SESSION_BUS_ADDRESS leaked" >&2; exit 1; }
mkdir -p "$XDG_RUNTIME_DIR/libvirt"
printf '%s\n' "$XDG_RUNTIME_DIR" > "${FAKE_RT_SEEN_LOG:?}"
: > "${FAKE_DAEMON_PIDS_LOG:?}"
sleep 30 </dev/null >/dev/null 2>&1 &
pid1=$!
sleep 30 </dev/null >/dev/null 2>&1 &
pid2=$!
printf '%s\n' "$pid1" > "$XDG_RUNTIME_DIR/libvirt/libvirtd.pid"
printf '%s\n' "$pid2" > "$XDG_RUNTIME_DIR/libvirt/virtlogd.pid"
printf '%s\n%s\n' "$pid1" "$pid2" > "${FAKE_DAEMON_PIDS_LOG:?}"
exit 0
"#,
    );
    write_install_env(&cfg, "qeminga-test-rt", &inst, &state, &hooks);

    let out = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-test-rt",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("FAKE_SERVICE_RT", service_rt.to_str().unwrap()),
            ("FAKE_USERDEL_LOG", userdel_log.to_str().unwrap()),
            ("FAKE_RT_SEEN_LOG", rt_seen_log.to_str().unwrap()),
            ("FAKE_DAEMON_PIDS_LOG", daemon_pids_log.to_str().unwrap()),
            ("XDG_CONFIG_HOME", "/root/.config"),
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/0/bus"),
        ],
        Some(&bin),
    );
    assert!(
        out.status.success(),
        "ordinary uninstall after systemctl stop removed RuntimeDirectory= must succeed: {}",
        text(&out)
    );

    let seen_rt = std::fs::read_to_string(&rt_seen_log).unwrap();
    let seen_rt = seen_rt.trim();
    assert!(
        seen_rt.starts_with(rt_root.to_str().unwrap()) && seen_rt != service_rt.to_str().unwrap(),
        "cleanup XDG_RUNTIME_DIR should be a fresh temp dir under runtime root: {seen_rt}"
    );
    assert!(
        !Path::new(seen_rt).exists(),
        "temporary cleanup runtime directory must be removed after uninstall: {seen_rt}"
    );
    assert!(
        !inst.exists() && !state.exists() && !hooks.exists() && !cfg.exists(),
        "managed directories must be removed on clean uninstall"
    );
    let ud = std::fs::read_to_string(&userdel_log).unwrap();
    assert!(
        ud.contains("qeminga-runner"),
        "--purge-user must complete cleanly and remove qeminga-runner: {ud}"
    );

    // 2. When /run/<service> is still present with owner=REC_USER_UID and mode=0700,
    //    uninstall reuses it (to talk to any still-running session daemon), stops its
    //    modular virtqemud daemon after clean domain cleanup, and succeeds with --purge-user.
    let case2 = dir.path().join("reuse-live-rt");
    let inst2 = case2.join("runner");
    let state2 = case2.join("state");
    let hooks2 = case2.join("hooks");
    let cfg2 = case2.join("cfg");
    let live_rt = rt_root.join("qeminga-live-rt");
    for d in [&inst2, &state2, &hooks2, &cfg2, &live_rt] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::set_permissions(&live_rt, std::fs::Permissions::from_mode(0o700)).unwrap();
    write_install_env(&cfg2, "qeminga-live-rt", &inst2, &state2, &hooks2);
    let rt_seen2 = case2.join("rt_seen.log");
    let pids2 = case2.join("daemon.pids");
    let userdel2 = case2.join("userdel.log");
    write_exec(
        &hooks2.join("hook-job-completed.sh"),
        r#"#!/bin/sh
set -eu
mkdir -p "$XDG_RUNTIME_DIR/libvirt"
printf '%s\n' "$XDG_RUNTIME_DIR" > "${FAKE_RT_SEEN_LOG:?}"
sleep 30 </dev/null >/dev/null 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$XDG_RUNTIME_DIR/libvirt/virtqemud.pid"
printf '%s\n' "$pid" > "${FAKE_DAEMON_PIDS_LOG:?}"
exit 0
"#,
    );
    let out2 = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-live-rt",
            "--install-dir",
            inst2.to_str().unwrap(),
            "--state-dir",
            state2.to_str().unwrap(),
            "--hook-dir",
            hooks2.to_str().unwrap(),
            "--config-dir",
            cfg2.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("FAKE_KEEP_SERVICE_RT", "1"),
            ("FAKE_LIVE_RT_PATH", live_rt.to_str().unwrap()),
            ("FAKE_LIVE_RT_STAT", "995:700"),
            ("FAKE_USERDEL_LOG", userdel2.to_str().unwrap()),
            ("FAKE_RT_SEEN_LOG", rt_seen2.to_str().unwrap()),
            ("FAKE_DAEMON_PIDS_LOG", pids2.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        out2.status.success(),
        "uninstall reusing live private RuntimeDirectory must succeed: {}",
        text(&out2)
    );
    assert_eq!(
        std::fs::read_to_string(&rt_seen2).unwrap().trim(),
        live_rt.to_str().unwrap(),
        "must reuse live private RuntimeDirectory owned by recorded UID"
    );
    assert!(
        std::fs::read_to_string(&userdel2)
            .unwrap()
            .contains("qeminga-runner"),
        "userdel must succeed after stopping virtqemud in live RuntimeDirectory"
    );

    // 3. Untrusted /run/<service> (wrong mode 0755) must NOT be reused; uninstall
    //    must create a fresh private mode-0700 temp runtime dir instead.
    let case3 = dir.path().join("bad-mode-rt");
    let inst3 = case3.join("runner");
    let state3 = case3.join("state");
    let hooks3 = case3.join("hooks");
    let cfg3 = case3.join("cfg");
    let bad_rt = rt_root.join("qeminga-bad-rt");
    for d in [&inst3, &state3, &hooks3, &cfg3, &bad_rt] {
        std::fs::create_dir_all(d).unwrap();
    }
    write_install_env(&cfg3, "qeminga-bad-rt", &inst3, &state3, &hooks3);
    let rt_seen3 = case3.join("rt_seen.log");
    write_exec(
        &hooks3.join("hook-job-completed.sh"),
        r#"#!/bin/sh
set -eu
mode="$(/usr/bin/stat -c '%a' "$XDG_RUNTIME_DIR")"
[ "$mode" = "700" ] || { echo "expected mode 700, got $mode" >&2; exit 1; }
printf '%s\n' "$XDG_RUNTIME_DIR" > "${FAKE_RT_SEEN_LOG:?}"
exit 0
"#,
    );
    let out3 = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-bad-rt",
            "--install-dir",
            inst3.to_str().unwrap(),
            "--state-dir",
            state3.to_str().unwrap(),
            "--hook-dir",
            hooks3.to_str().unwrap(),
            "--config-dir",
            cfg3.to_str().unwrap(),
        ],
        &[
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("FAKE_KEEP_SERVICE_RT", "1"),
            ("FAKE_LIVE_RT_PATH", bad_rt.to_str().unwrap()),
            ("FAKE_LIVE_RT_STAT", "995:755"),
            ("FAKE_RT_SEEN_LOG", rt_seen3.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        out3.status.success(),
        "uninstall with untrusted /run/<service> mode must fall back to fresh temp dir: {}",
        text(&out3)
    );
    let seen_rt3 = std::fs::read_to_string(&rt_seen3).unwrap();
    let seen_rt3 = seen_rt3.trim();
    assert_ne!(
        seen_rt3,
        bad_rt.to_str().unwrap(),
        "must not reuse /run/<service> with non-0700 mode"
    );
    assert!(
        !Path::new(seen_rt3).exists(),
        "fallback temp runtime dir must be removed after uninstall"
    );

    // 4. On partial uninstall (cleanup hook fails after starting a temp libvirtd),
    //    temp runtime dir and temp daemon must still be cleaned up while images/ and
    //    config/ remain preserved.
    let case4 = dir.path().join("partial-cleanup-rt");
    let inst4 = case4.join("runner");
    let state4 = case4.join("state");
    let hooks4 = case4.join("hooks");
    let cfg4 = case4.join("cfg");
    let vm_disk4 = state4.join("images/qeminga-e2e-77-1-x86_64/root.qcow2");
    std::fs::create_dir_all(vm_disk4.parent().unwrap()).unwrap();
    for d in [&inst4, &hooks4, &cfg4] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(&vm_disk4, b"active-disk").unwrap();
    write_install_env(&cfg4, "qeminga-partial-rt", &inst4, &state4, &hooks4);
    let rt_seen4 = case4.join("rt_seen.log");
    let pids4 = case4.join("daemon.pids");
    write_exec(
        &hooks4.join("hook-job-completed.sh"),
        r#"#!/bin/sh
set -eu
mkdir -p "$XDG_RUNTIME_DIR/libvirt"
printf '%s\n' "$XDG_RUNTIME_DIR" > "${FAKE_RT_SEEN_LOG:?}"
sleep 30 </dev/null >/dev/null 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$XDG_RUNTIME_DIR/libvirt/libvirtd.pid"
printf '%s\n' "$pid" > "${FAKE_DAEMON_PIDS_LOG:?}"
exit 1
"#,
    );
    let out4 = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-partial-rt",
            "--install-dir",
            inst4.to_str().unwrap(),
            "--state-dir",
            state4.to_str().unwrap(),
            "--hook-dir",
            hooks4.to_str().unwrap(),
            "--config-dir",
            cfg4.to_str().unwrap(),
        ],
        &[
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            (
                "FAKE_SERVICE_RT",
                rt_root.join("qeminga-partial-rt").to_str().unwrap(),
            ),
            ("FAKE_RT_SEEN_LOG", rt_seen4.to_str().unwrap()),
            ("FAKE_DAEMON_PIDS_LOG", pids4.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !out4.status.success(),
        "partial uninstall must fail non-zero when hook fails: {}",
        text(&out4)
    );
    let seen_rt4 = std::fs::read_to_string(&rt_seen4).unwrap();
    let seen_rt4 = seen_rt4.trim();
    assert!(
        !Path::new(seen_rt4).exists(),
        "temp runtime dir must still be removed on partial uninstall: {seen_rt4}"
    );
    let pid4: i32 = std::fs::read_to_string(&pids4)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let alive4 = Command::new("kill")
        .args(["-0", &pid4.to_string()])
        .output()
        .unwrap()
        .status
        .success();
    assert!(
        !alive4,
        "temp session libvirtd (pid {pid4}) must still be terminated on partial uninstall"
    );
    assert!(
        vm_disk4.exists() && cfg4.join("install.env").exists(),
        "VM disk and install.env must remain preserved on partial uninstall"
    );
}
