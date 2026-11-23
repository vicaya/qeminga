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
        "Type=notify",
        "NotifyAccess=main",
        "TimeoutStartSec=60s",
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
        "IPAddressAllow=127.0.0.0/9",
        "IPAddressAllow=::1/128",
        "IPAddressDeny=127.255.255.254/32",
        "IPAddressDeny=link-local",
        "IPAddressDeny=multicast",
        "IPAddressDeny=10.0.0.0/8",
        "IPAddressDeny=172.16.0.0/12",
        "IPAddressDeny=192.168.0.0/16",
        "IPAddressDeny=100.64.0.0/10",
        "IPAddressDeny=fc00::/7",
        "IPAddressDeny=fe80::/10",
        "IPAddressDeny=fd00:ec2::254/128",
        "ExecStart=/usr/local/libexec/qeminga-runner/run-runner.sh",
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
    // never Type=simple (systemctl start must wait for the firewall gate via Type=notify),
    // never ExecStartPre= for the firewall gate (RestartPreventExitStatus=78 applies only to the
    // main service process), and never run.sh.
    for forbidden in [
        "Type=simple",
        "User=root",
        "SupplementaryGroups=libvirt",
        "SupplementaryGroups=docker",
        "SupplementaryGroups=sudo",
        "MemoryDenyWriteExecute=yes",
        "ReadWritePaths=/opt/qeminga-runner\n",
        "ExecStart=/opt/qeminga-runner/run.sh",
        "ExecStartPre=",
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
    write_exec(&fake_hooks.join("run-runner.sh"), "#!/bin/sh\nexit 0\n");
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
        let unprivileged_run_systemd_err = combined.contains("Failed to create /run/systemd")
            || combined.contains("Failed to create directory '/run/systemd");
        if !verify.status.success()
            && std::env::var_os("CI").is_none()
            && unprivileged_run_systemd_err
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
        unit.contains("ExecStart=/usr/local/libexec/qeminga-runner/run-runner.sh"),
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
    assert!(unit.contains("IPAddressDeny=127.255.255.254/32"), "{unit}");
    assert!(unit.contains("IPAddressDeny=link-local"), "{unit}");
    assert!(unit.contains("IPAddressDeny=fe80::/10"), "{unit}");
    assert!(unit.contains("IPAddressDeny=fd00:ec2::254/128"), "{unit}");
    assert!(unit.contains("IPAddressDeny=multicast"), "{unit}");
    assert!(!unit.contains("IPAddressDeny=10.0.0.0/8"), "{unit}");
    assert!(!unit.contains("IPAddressDeny=fc00::/7"), "{unit}");

    // --allow-ip allows a specific private resolver, never cloud IMDS, the loopback sentinel, supernets, or 0.0.0.0/0.
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
        "127.255.255.254",
        "127.255.255.254/32",
        "127.0.0.0/8",
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
            "git",
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

    // Fake id reports root (uid 0) and existing service user (995:995); fake systemctl/chown are no-ops.
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
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
    echo "0:755"
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
    use std::os::unix::net::UnixDatagram;

    let dir = tempfile::tempdir().unwrap();
    let install_dir = dir.path().join("runner");
    let bin_dir = install_dir.join("bin");
    let hook_dir = dir.path().join("hooks");
    let cred_dir = dir.path().join("creds");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&hook_dir).unwrap();
    std::fs::create_dir_all(&cred_dir).unwrap();

    let notify_sock_path = dir.path().join("notify.sock");
    let notify_sock = UnixDatagram::bind(&notify_sock_path).unwrap();
    notify_sock.set_nonblocking(true).unwrap();

    let listener_args = dir.path().join("listener.args");
    let listener_jit = dir.path().join("listener.jit");
    let listener_notify = dir.path().join("listener.notify");
    write_exec(
        &bin_dir.join("Runner.Listener"),
        r#"#!/bin/sh
printf '%s' "$*" > "${FAKE_LISTENER_ARGS:?}"
printf '%s' "${ACTIONS_RUNNER_INPUT_JITCONFIG:-}" > "${FAKE_LISTENER_JIT:?}"
printf '%s' "${NOTIFY_SOCKET:-}" > "${FAKE_LISTENER_NOTIFY:?}"
exit 0
"#,
    );
    write_exec(
        &install_dir.join("run.sh"),
        "#!/bin/sh\necho 'run.sh must not be invoked' >&2\nexit 99\n",
    );
    write_exec(
        &hook_dir.join("check-egress-firewall.sh"),
        "#!/bin/sh\nexit \"${FAKE_FW_RC:-0}\"\n",
    );
    std::fs::write(cred_dir.join("jitconfig"), "JIT_SECRET_VALUE\n").unwrap();

    let launcher = hook_dir.join("run-jit.sh");
    let generated = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_HOOK_DIR="$3"; write_jit_launcher "$4""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            hook_dir.to_str().unwrap(),
            launcher.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(generated.status.success(), "{}", text(&generated));

    // When the firewall check fails, the main process wrapper MUST exit 78
    // directly (matching RestartPreventExitStatus=78) without sending READY=1
    // or starting Runner.Listener.
    let blocked = Command::new(&launcher)
        .env("CREDENTIALS_DIRECTORY", &cred_dir)
        .env("NOTIFY_SOCKET", &notify_sock_path)
        .env("FAKE_FW_RC", "78")
        .env("FAKE_LISTENER_ARGS", &listener_args)
        .env("FAKE_LISTENER_JIT", &listener_jit)
        .env("FAKE_LISTENER_NOTIFY", &listener_notify)
        .output()
        .unwrap();
    assert_eq!(
        blocked.status.code(),
        Some(78),
        "run-jit.sh must exit 78 from main process when firewall check fails: {}",
        text(&blocked)
    );
    assert!(
        !listener_args.exists(),
        "Runner.Listener must NOT be started when firewall check fails"
    );
    let mut buf = [0u8; 64];
    assert_eq!(
        notify_sock.recv(&mut buf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "run-jit.sh must NOT signal READY=1 when firewall check fails"
    );

    // Make install_dir read-only to prove the launcher never writes run-helper.sh.
    std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let run = Command::new(&launcher)
        .env("CREDENTIALS_DIRECTORY", &cred_dir)
        .env("NOTIFY_SOCKET", &notify_sock_path)
        .env("FAKE_FW_RC", "0")
        .env("FAKE_LISTENER_ARGS", &listener_args)
        .env("FAKE_LISTENER_JIT", &listener_jit)
        .env("FAKE_LISTENER_NOTIFY", &listener_notify)
        .output()
        .unwrap();
    std::fs::set_permissions(&install_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(run.status.success(), "run-jit.sh failed: {}", text(&run));
    let n = notify_sock
        .recv(&mut buf)
        .expect("run-jit.sh must send READY=1 to NOTIFY_SOCKET after firewall gate passes");
    assert_eq!(
        std::str::from_utf8(&buf[..n]).unwrap().trim(),
        "READY=1",
        "unexpected sd_notify payload from run-jit.sh"
    );
    assert_eq!(
        std::fs::read_to_string(&listener_notify).unwrap(),
        "",
        "NOTIFY_SOCKET must be stripped before exec'ing Runner.Listener"
    );
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

fn make_jit_config_json(runner_json: &str) -> String {
    let outer = format!("{{\".runner\":\"{}\"}}", b64(runner_json.as_bytes()));
    b64(outer.as_bytes())
}

fn make_jit_config(github_url: &str, work_folder: &str) -> String {
    let runner_json = format!(
        "\u{feff}{{\"agentId\":1,\"agentName\":\"jit-test\",\"gitHubUrl\":\"{github_url}\",\"workFolder\":\"{work_folder}\"}}"
    );
    make_jit_config_json(&runner_json)
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
    let fake_install = dir.path().join("runner");
    let fake_bin = fake_install.join("bin");
    let hooks_out = dir.path().join("hooks");
    std::fs::create_dir_all(&fake_bin).unwrap();

    let rendered = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--install-dir",
        fake_install.to_str().unwrap(),
        "--hook-dir",
        hooks_out.to_str().unwrap(),
        "--out",
        hooks_out.to_str().unwrap(),
    ]);
    assert!(rendered.status.success(), "{}", text(&rendered));

    let check = hooks_out.join("check-egress-firewall.sh");
    let run_runner = hooks_out.join("run-runner.sh");
    assert!(
        check.is_file(),
        "render-hooks must write check-egress-firewall.sh"
    );
    assert!(
        run_runner.is_file(),
        "render-hooks must write root-owned main-process run-runner.sh"
    );

    // 1. Controlled local check on an unfiltered cgroup (no IPAddressDeny BPF active)
    //    WITH runner-writable Python user-site configuration poisoned in HOME,
    //    PYTHONPATH, PYTHONUSERBASE, and PYTHONSTARTUP trying to forge EPERM:
    //    check-egress-firewall.sh MUST run system python3 in isolated mode (-I -S)
    //    with a sanitized environment and STILL fail closed with EX_CONFIG (78).
    let py_ver_out = Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ])
        .output()
        .unwrap();
    assert!(py_ver_out.status.success());
    let py_ver = String::from_utf8(py_ver_out.stdout).unwrap();
    let py_ver = py_ver.trim();

    let poison_home = dir.path().join("poison-home");
    let user_site = poison_home.join(format!(".local/lib/python{py_ver}/site-packages"));
    std::fs::create_dir_all(&user_site).unwrap();
    let forge_eperm_py = r#"import errno, socket
def _forge(self, data, addr):
    if addr[0] == "127.0.0.1":
        return len(data)
    raise OSError(errno.EPERM, "forged by runner-writable python config")
socket.socket.sendto = _forge
"#;
    std::fs::write(user_site.join("usercustomize.py"), forge_eperm_py).unwrap();
    std::fs::write(user_site.join("sitecustomize.py"), forge_eperm_py).unwrap();
    std::fs::write(user_site.join("poison.pth"), "import sys; sys.exit(0)\n").unwrap();
    std::fs::write(user_site.join("socket.py"), "import sys; sys.exit(0)\n").unwrap();
    let startup_py = poison_home.join("startup.py");
    std::fs::write(&startup_py, "import sys; sys.exit(0)\n").unwrap();

    // Also plant a fake `python3` earlier in PATH to prove check-egress-firewall.sh
    // invokes the trusted system /usr/bin/python3 rather than PATH lookup.
    let fake_path_bin = dir.path().join("fake-path-bin");
    std::fs::create_dir_all(&fake_path_bin).unwrap();
    write_exec(&fake_path_bin.join("python3"), "#!/bin/sh\nexit 0\n");
    let poisoned_path = format!(
        "{}:{}",
        fake_path_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let poisoned = Command::new("bash")
        .arg(&check)
        .env("HOME", &poison_home)
        .env("PATH", &poisoned_path)
        .env("PYTHONPATH", &user_site)
        .env("PYTHONUSERBASE", poison_home.join(".local"))
        .env("PYTHONSTARTUP", &startup_py)
        .env("QEMINGA_RUNNER_POLICY", hooks_out.join("policy.env"))
        .output()
        .unwrap();
    assert_eq!(
        poisoned.status.code(),
        Some(78),
        "poisoned user Python config and PATH must NOT bypass firewall check (must exit 78): {}",
        text(&poisoned)
    );
    let check_body = std::fs::read_to_string(&check).unwrap();
    assert!(
        check_body.contains("-I -S") && check_body.contains("env -i"),
        "check-egress-firewall.sh must run isolated Python (-I -S) under env -i:\n{check_body}"
    );

    // 2. Main-process run-runner.sh exits 78 directly (matching RestartPreventExitStatus=78)
    //    without sending READY=1 or starting bin/runsvc.sh when the firewall check fails,
    //    and signals READY=1 (stripping NOTIFY_SOCKET) before exec'ing bin/runsvc.sh when it passes.
    let notify_sock_path = dir.path().join("runner-notify.sock");
    let notify_sock = std::os::unix::net::UnixDatagram::bind(&notify_sock_path).unwrap();
    notify_sock.set_nonblocking(true).unwrap();

    let runsvc_marker = dir.path().join("runsvc.started");
    let runsvc_notify = dir.path().join("runsvc.notify");
    write_exec(
        &fake_bin.join("runsvc.sh"),
        "#!/bin/sh\necho started > \"${FAKE_RUNSVC_MARKER:?}\"\nprintf '%s' \"${NOTIFY_SOCKET:-}\" > \"${FAKE_RUNSVC_NOTIFY:?}\"\nexit 0\n",
    );
    let blocked_main = Command::new(&run_runner)
        .env("HOME", &poison_home)
        .env("NOTIFY_SOCKET", &notify_sock_path)
        .env("FAKE_RUNSVC_MARKER", &runsvc_marker)
        .env("FAKE_RUNSVC_NOTIFY", &runsvc_notify)
        .output()
        .unwrap();
    assert_eq!(
        blocked_main.status.code(),
        Some(78),
        "main-process run-runner.sh must exit 78 when firewall check fails: {}",
        text(&blocked_main)
    );
    assert!(
        !runsvc_marker.exists(),
        "bin/runsvc.sh must NOT start when firewall check fails"
    );
    let mut nbuf = [0u8; 64];
    assert_eq!(
        notify_sock.recv(&mut nbuf).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "run-runner.sh must NOT send READY=1 when firewall check fails"
    );

    // Replace check-egress-firewall.sh with a passing stub to confirm run-runner.sh
    // sends READY=1, strips NOTIFY_SOCKET, and execs bin/runsvc.sh.
    let saved_check = std::fs::read_to_string(&check).unwrap();
    write_exec(&check, "#!/bin/sh\nexit 0\n");
    let ok_main = Command::new(&run_runner)
        .env("NOTIFY_SOCKET", &notify_sock_path)
        .env("FAKE_RUNSVC_MARKER", &runsvc_marker)
        .env("FAKE_RUNSVC_NOTIFY", &runsvc_notify)
        .output()
        .unwrap();
    assert!(ok_main.status.success(), "{}", text(&ok_main));
    let n = notify_sock
        .recv(&mut nbuf)
        .expect("run-runner.sh must send READY=1 to NOTIFY_SOCKET after firewall gate passes");
    assert_eq!(
        std::str::from_utf8(&nbuf[..n]).unwrap().trim(),
        "READY=1",
        "unexpected sd_notify payload from run-runner.sh"
    );
    assert_eq!(
        std::fs::read_to_string(&runsvc_notify).unwrap(),
        "",
        "NOTIFY_SOCKET must be stripped before exec'ing bin/runsvc.sh"
    );
    assert!(
        runsvc_marker.exists(),
        "run-runner.sh must exec bin/runsvc.sh when firewall check passes"
    );

    // 3. Exercise the embedded Python probe logic directly against controlled kernel
    //    sendto() verdicts (host-wide IMDS-only block vs real unit cgroup BPF,
    //    loopback allow sanity, private-LAN deny, --no-lan-deny, --allow-ip).
    let extract_py = |script_text: &str| -> String {
        let start = script_text
            .find("<<'PY'\n")
            .expect("missing PY heredoc start")
            + "<<'PY'\n".len();
        let end = script_text[start..]
            .find("\nPY\n")
            .expect("missing PY heredoc end");
        script_text[start..start + end].to_string()
    };
    let default_py = extract_py(&saved_check);

    let run_probe_sim = |py_code: &str, mode: &str| -> Output {
        let harness = format!(
            r#"import errno, socket
_MODE = {mode:?}
class _SimSocket:
    def __init__(self, family, stype):
        self.family = family
    def sendto(self, data, addr):
        host = addr[0]
        if _MODE == "host_imds_only":
            # Host firewall blocks IMDS, but unit cgroup BPF is missing (sentinel & LAN succeed!)
            if host in ("169.254.169.254", "fd00:ec2::254"):
                raise OSError(errno.EPERM, "Operation not permitted")
            return len(data)
        if _MODE == "unit_bpf_full":
            if host == "127.0.0.1":
                return len(data)
            if host == "fd00:ec2::254":
                raise OSError(errno.ENETUNREACH, "Network is unreachable")
            raise OSError(errno.EPERM, "Operation not permitted")
        if _MODE == "unit_bpf_lan_leaked":
            if host == "127.0.0.1":
                return len(data)
            if host == "10.255.255.254":
                return len(data)
            raise OSError(errno.EPERM, "Operation not permitted")
        if _MODE == "loopback_blocked":
            raise OSError(errno.EPERM, "Operation not permitted")
        if _MODE == "no_lan_deny_ok":
            if host in ("127.255.255.254", "169.254.169.254"):
                raise OSError(errno.EPERM, "Operation not permitted")
            if host == "fd00:ec2::254":
                raise OSError(errno.ENETUNREACH, "Network is unreachable")
            return len(data)
        raise AssertionError(f"unknown mode {{_MODE}}")
    def close(self):
        pass
socket.socket = _SimSocket
{py_code}
"#
        );
        Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", &harness])
            .output()
            .unwrap()
    };

    for (mode, want_code) in [
        ("host_imds_only", 78),
        ("unit_bpf_full", 0),
        ("unit_bpf_lan_leaked", 78),
        ("loopback_blocked", 78),
    ] {
        let out = run_probe_sim(&default_py, mode);
        assert_eq!(
            out.status.code(),
            Some(want_code),
            "default policy mode={mode}: {}",
            text(&out)
        );
    }

    // With --no-lan-deny, LAN probes are skipped while unit sentinel + IMDS still require EPERM.
    let hooks_nolan = dir.path().join("hooks-nolan");
    let r_nolan = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--no-lan-deny",
        "--out",
        hooks_nolan.to_str().unwrap(),
    ]);
    assert!(r_nolan.status.success(), "{}", text(&r_nolan));
    let nolan_py =
        extract_py(&std::fs::read_to_string(hooks_nolan.join("check-egress-firewall.sh")).unwrap());
    assert_eq!(
        run_probe_sim(&nolan_py, "no_lan_deny_ok").status.code(),
        Some(0)
    );
    assert_eq!(
        run_probe_sim(&nolan_py, "host_imds_only").status.code(),
        Some(78)
    );

    // With --allow-ip 10.0.0.0/8, 10.255.255.254 is exempted while other LAN ranges remain probed.
    let hooks_allow10 = dir.path().join("hooks-allow10");
    let r_allow10 = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--allow-ip",
        "10.0.0.0/8",
        "--out",
        hooks_allow10.to_str().unwrap(),
    ]);
    assert!(r_allow10.status.success(), "{}", text(&r_allow10));
    let allow10_py = extract_py(
        &std::fs::read_to_string(hooks_allow10.join("check-egress-firewall.sh")).unwrap(),
    );
    assert_eq!(
        run_probe_sim(&allow10_py, "unit_bpf_lan_leaked")
            .status
            .code(),
        Some(0),
        "10.255.255.254 should be skipped when --allow-ip 10.0.0.0/8 is configured"
    );
}

#[test]
fn install_record_scopes_uninstall_refuses_unmanaged_dirs_and_preserves_images_on_cleanup_failure()
{
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
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

    // Write a UTF-8-BOM .runner file like actions/runner produces for the default
    // (--disableupdate) configuration.
    let runner_json_disabled_update = format!(
        "\u{feff}{{\"agentId\":1,\"agentName\":\"qeminga-kvm-x86_64-box\",\"gitHubUrl\":\"{REPO_URL}\",\"workFolder\":\"{}/work\",\"disableUpdate\":true}}",
        state_dir.display()
    );
    std::fs::write(install_dir.join(".runner"), &runner_json_disabled_update).unwrap();

    // 1. Matching existing registration returns "reuse".
    let reuse = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_ALLOW_AUTO_UPDATE=0; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; REC_ALLOW_AUTO_UPDATE=0; check_existing_registration "$4" "qeminga-kvm-x86_64-box""#,
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

    // 2. Incompatible target URL must fail immediately before mutating anything.
    let mismatch = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_ALLOW_AUTO_UPDATE=0; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; REC_ALLOW_AUTO_UPDATE=0; check_existing_registration "https://github.com/other/controller" "qeminga-kvm-x86_64-box""#,
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

    // 2a. Switching from default (--disableupdate) to --allow-auto-update must NOT
    //     silently reuse the existing disabled-update registration.
    let enable_auto = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_ALLOW_AUTO_UPDATE=1; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; REC_ALLOW_AUTO_UPDATE=0; check_existing_registration "$4" "qeminga-kvm-x86_64-box""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            REPO_URL,
        ])
        .output()
        .unwrap();
    assert!(
        !enable_auto.status.success(),
        "switching default registration to --allow-auto-update must be refused: {}",
        text(&enable_auto)
    );

    // 2b. Even if install.env says ALLOW_AUTO_UPDATE=1, a .runner still carrying
    //     "disableUpdate":true must be refused.
    let runner_drift = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_ALLOW_AUTO_UPDATE=1; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; REC_ALLOW_AUTO_UPDATE=1; check_existing_registration "$4" "qeminga-kvm-x86_64-box""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            REPO_URL,
        ])
        .output()
        .unwrap();
    assert!(
        !runner_drift.status.success(),
        ".runner disableUpdate=true must be refused when --allow-auto-update is requested: {}",
        text(&runner_drift)
    );

    // 2c. An auto-update registration (disableUpdate omitted/false) matches
    //     --allow-auto-update=1 and refuses switching back to default (0).
    let runner_json_auto_update = format!(
        "\u{feff}{{\"agentId\":1,\"agentName\":\"qeminga-kvm-x86_64-box\",\"gitHubUrl\":\"{REPO_URL}\",\"workFolder\":\"{}/work\"}}",
        state_dir.display()
    );
    std::fs::write(install_dir.join(".runner"), &runner_json_auto_update).unwrap();
    let reuse_auto = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_ALLOW_AUTO_UPDATE=1; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; REC_ALLOW_AUTO_UPDATE=1; check_existing_registration "$4" "qeminga-kvm-x86_64-box""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            REPO_URL,
        ])
        .output()
        .unwrap();
    assert!(reuse_auto.status.success(), "{}", text(&reuse_auto));
    assert_eq!(String::from_utf8_lossy(&reuse_auto.stdout).trim(), "reuse");

    let disable_auto = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_ALLOW_AUTO_UPDATE=0; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; REC_ALLOW_AUTO_UPDATE=1; check_existing_registration "$4" "qeminga-kvm-x86_64-box""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            REPO_URL,
        ])
        .output()
        .unwrap();
    assert!(
        !disable_auto.status.success(),
        "switching --allow-auto-update registration back to default must be refused: {}",
        text(&disable_auto)
    );

    // 2d. Ephemeral flag mismatch in .runner must also be refused.
    let runner_json_ephemeral = format!(
        "\u{feff}{{\"agentId\":1,\"agentName\":\"qeminga-kvm-x86_64-box\",\"gitHubUrl\":\"{REPO_URL}\",\"workFolder\":\"{}/work\",\"disableUpdate\":true,\"ephemeral\":true}}",
        state_dir.display()
    );
    std::fs::write(install_dir.join(".runner"), &runner_json_ephemeral).unwrap();
    let eph_mismatch = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_EPHEMERAL=0; OPT_ALLOW_AUTO_UPDATE=0; OPT_LABELS="qeminga-kvm"; OPT_RUNNER_GROUP=""; OPT_JITCONFIG_FILE=""; HAS_INSTALL_RECORD=1; REC_TARGET_URL="$4"; REC_RUNNER_NAME="qeminga-kvm-x86_64-box"; REC_LABELS="qeminga-kvm"; REC_RUNNER_GROUP=""; REC_EPHEMERAL=0; REC_ALLOW_AUTO_UPDATE=0; check_existing_registration "$4" "qeminga-kvm-x86_64-box""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            REPO_URL,
        ])
        .output()
        .unwrap();
    assert!(
        !eph_mismatch.status.success(),
        ".runner ephemeral=true must be refused when persistent mode is requested: {}",
        text(&eph_mismatch)
    );
    std::fs::write(install_dir.join(".runner"), &runner_json_disabled_update).unwrap();

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

    // 2. Unbound JIT configs with gitHubUrl omitted or empty MUST fail closed even when
    //    serverUrlV2 points to a shared hosted GitHub Actions endpoint (shared endpoints do
    //    not identify which repository owns the enrollment); donors are directed to token
    //    registration (--token-file). An explicit matching gitHubUrl with exact STATE_DIR/work
    //    is accepted.
    for (label, json) in [
        (
            "omitted-url",
            format!(
                "\u{feff}{{\"agentId\":7,\"agentName\":\"jit-nourl\",\"serverUrlV2\":\"https://broker.actions.githubusercontent.com/test\",\"workFolder\":\"{}\"}}",
                state_dir.join("work").display()
            ),
        ),
        (
            "empty-url",
            "\u{feff}{\"agentId\":8,\"agentName\":\"jit-emptyurl\",\"gitHubUrl\":\"\",\"serverUrl\":\"https://pipelines.actions.githubusercontent.com/test\",\"workFolder\":\"_work\"}".to_string(),
        ),
    ] {
        let jit_unbound = dir.path().join(format!("jit-{label}"));
        std::fs::write(&jit_unbound, make_jit_config_json(&json)).unwrap();
        std::fs::set_permissions(&jit_unbound, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out_dir = dir.path().join(format!("hooks-{label}"));
        let rejected = run_setup(&[
            "render-hooks",
            "--repo",
            REPO_URL,
            "--install-dir",
            install_dir.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--jitconfig-file",
            jit_unbound.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ]);
        assert!(
            !rejected.status.success(),
            "unbound JIT blob ({label}) must be refused: {}",
            text(&rejected)
        );
        let msg = text(&rejected);
        assert!(
            msg.contains("gitHubUrl") && msg.contains("--token-file"),
            "refusal for unbound JIT blob ({label}) should explain missing gitHubUrl and direct donors to --token-file: {msg}"
        );
    }

    let jit_exact_work = dir.path().join("jit-exact-work");
    let exact_work = state_dir.join("work");
    std::fs::write(
        &jit_exact_work,
        make_jit_config(REPO_URL, exact_work.to_str().unwrap()),
    )
    .unwrap();
    std::fs::set_permissions(&jit_exact_work, std::fs::Permissions::from_mode(0o600)).unwrap();
    let hooks_exact_work = dir.path().join("hooks-exact-work");
    let ok_exact = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--install-dir",
        install_dir.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--jitconfig-file",
        jit_exact_work.to_str().unwrap(),
        "--out",
        hooks_exact_work.to_str().unwrap(),
    ]);
    assert!(
        ok_exact.status.success(),
        "bound JIT blob with exact STATE_DIR/work must succeed: {}",
        text(&ok_exact)
    );
    assert!(
        std::fs::read_to_string(hooks_exact_work.join("policy.env"))
            .unwrap()
            .contains(&format!("WORK_DIR={}\n", exact_work.display()))
    );

    // 3. Organization JIT provisioning (--org + --jitconfig-file) MUST be refused
    //    because JIT blobs do not cryptographically bind the org runner group, and
    //    direct resolve_jit_work_dir rejects poolName mismatch against OPT_RUNNER_GROUP.
    let org_jit = dir.path().join("jit-org");
    std::fs::write(
        &org_jit,
        make_jit_config_json(
            "\u{feff}{\"agentId\":9,\"agentName\":\"org-jit\",\"gitHubUrl\":\"https://github.com/myorg\",\"poolName\":\"wrong-group\",\"workFolder\":\"_work\"}",
        ),
    )
    .unwrap();
    std::fs::set_permissions(&org_jit, std::fs::Permissions::from_mode(0o600)).unwrap();
    for subcmd in ["render-unit", "render-hooks"] {
        let mut args = vec![
            subcmd,
            "--org",
            "https://github.com/myorg",
            "--runner-group",
            "qeminga-kvm-restricted",
            "--allow-repo",
            "vicaya/qeminga",
            "--jitconfig-file",
            org_jit.to_str().unwrap(),
        ];
        let tmp_out = dir.path().join(format!("org-jit-{subcmd}"));
        if subcmd == "render-hooks" {
            args.extend(["--out", tmp_out.to_str().unwrap()]);
        } else {
            args.extend(["--arch", "x86_64"]);
        }
        let res = run_setup(&args);
        assert!(
            !res.status.success(),
            "--org with --jitconfig-file ({subcmd}) must be refused: {}",
            text(&res)
        );
        let msg = text(&res);
        assert!(
            msg.contains("--jitconfig-file") && msg.contains("--org"),
            "refusal should explain --org + --jitconfig-file restriction ({subcmd}): {msg}"
        );
    }
    let grp_mismatch = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_RUNNER_GROUP="qeminga-kvm-restricted"; resolve_jit_work_dir "$(cat "$4")" "https://github.com/myorg""#,
            "_",
            script().to_str().unwrap(),
            install_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            org_jit.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !grp_mismatch.status.success(),
        "JIT poolName mismatch against OPT_RUNNER_GROUP must be refused: {}",
        text(&grp_mismatch)
    );

    // 4. Malicious/escaped JIT workFolder, nested work/sub (which would allow runner-writable
    //    intermediate symlink swaps), overlapping VM/state subtrees (images, image-cache,
    //    .config, work2), or mismatched gitHubUrl must fail closed.
    let bad_work_sub = state_dir
        .join("work/job-sub")
        .to_string_lossy()
        .into_owned();
    let bad_images = state_dir.join("images").to_string_lossy().into_owned();
    let bad_images_sub = state_dir.join("images/sub").to_string_lossy().into_owned();
    let bad_cache = state_dir.join("image-cache").to_string_lossy().into_owned();
    let bad_cfg = state_dir.join(".config").to_string_lossy().into_owned();
    let bad_work2 = state_dir.join("work2").to_string_lossy().into_owned();
    for (label, url, wf) in [
        ("traversal", REPO_URL, "../../etc"),
        ("outside-abs", REPO_URL, "/tmp/outside"),
        ("bin-dir", REPO_URL, "bin"),
        ("dot-dir", REPO_URL, "."),
        ("wrong-repo", "https://github.com/evil/repo", "_work"),
        ("nested-work-sub", REPO_URL, bad_work_sub.as_str()),
        ("state-images", REPO_URL, bad_images.as_str()),
        ("state-images-sub", REPO_URL, bad_images_sub.as_str()),
        ("state-image-cache", REPO_URL, bad_cache.as_str()),
        ("state-dot-config", REPO_URL, bad_cfg.as_str()),
        ("state-work2", REPO_URL, bad_work2.as_str()),
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

    // 5. Defense in depth: hook-job-completed.sh MUST refuse a policy whose WORK_DIR
    //    overlaps IMAGES_DIR, uses a nested path through an intermediate runner-writable
    //    symlink into IMAGES_DIR, or points WORK_DIR itself via a symlink into IMAGES_DIR,
    //    preserving VM disks intact even when libvirt cannot confirm domains absent.
    let kept_disk = state_dir.join("images/qeminga-e2e-88-1-x86_64/root.qcow2");
    std::fs::create_dir_all(kept_disk.parent().unwrap()).unwrap();
    std::fs::write(&kept_disk, b"keep-me").unwrap();

    // 5a. Direct overlap WORK_DIR=$STATE_DIR/images.
    let bad_policy = dir.path().join("bad-overlap-policy.env");
    std::fs::write(
        &bad_policy,
        format!(
            "INSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/images\nIMAGES_DIR={}/images\nLIBVIRT_CONNECT=qemu:///session\n",
            install_dir.display(),
            state_dir.display(),
            state_dir.display(),
            state_dir.display(),
        ),
    )
    .unwrap();
    let bad_hook = run_hook(
        &hooks_out.join("hook-job-completed.sh"),
        &bad_policy,
        &bin,
        &[("FAKE_LOG", log.to_str().unwrap())],
    );
    assert!(
        !bad_hook.status.success(),
        "hook-job-completed.sh must refuse WORK_DIR overlapping IMAGES_DIR: {}",
        text(&bad_hook)
    );
    assert!(
        kept_disk.exists(),
        "VM disk under images/ must remain intact when WORK_DIR overlaps images/"
    );

    // 5b. Intermediate symlink inside a nested WORK_DIR ($STATE_DIR/work/link/qeminga-e2e-88-1-x86_64
    //     where $STATE_DIR/work/link -> $STATE_DIR/images): must be refused without deleting kept_disk!
    let inter_link = state_dir.join("work/link");
    std::os::unix::fs::symlink(state_dir.join("images"), &inter_link).unwrap();
    let nested_symlink_policy = dir.path().join("nested-symlink-policy.env");
    std::fs::write(
        &nested_symlink_policy,
        format!(
            "INSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work/link/qeminga-e2e-88-1-x86_64\nIMAGES_DIR={}/images\nLIBVIRT_CONNECT=qemu:///session\n",
            install_dir.display(),
            state_dir.display(),
            state_dir.display(),
            state_dir.display(),
        ),
    )
    .unwrap();
    let bad_nested = run_hook(
        &hooks_out.join("hook-job-completed.sh"),
        &nested_symlink_policy,
        &bin,
        &[("FAKE_LOG", log.to_str().unwrap()), ("FAKE_LIST_FAIL", "1")],
    );
    assert!(
        !bad_nested.status.success(),
        "hook-job-completed.sh must refuse nested WORK_DIR traversing intermediate symlink: {}",
        text(&bad_nested)
    );
    assert!(
        kept_disk.exists(),
        "VM disk under images/ must survive intermediate symlink in nested WORK_DIR"
    );

    // 5c. Direct symlink replacing $STATE_DIR/work -> $STATE_DIR/images: must refuse to scrub!
    std::fs::remove_dir_all(state_dir.join("work")).unwrap();
    std::os::unix::fs::symlink(state_dir.join("images"), state_dir.join("work")).unwrap();
    let direct_sym_policy = dir.path().join("direct-sym-policy.env");
    std::fs::write(
        &direct_sym_policy,
        format!(
            "INSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work\nIMAGES_DIR={}/images\nLIBVIRT_CONNECT=qemu:///session\n",
            install_dir.display(),
            state_dir.display(),
            state_dir.display(),
            state_dir.display(),
        ),
    )
    .unwrap();
    let bad_direct = run_hook(
        &hooks_out.join("hook-job-completed.sh"),
        &direct_sym_policy,
        &bin,
        &[("FAKE_LOG", log.to_str().unwrap()), ("FAKE_LIST_FAIL", "1")],
    );
    assert!(
        !bad_direct.status.success(),
        "hook-job-completed.sh must refuse symlinked WORK_DIR -> images: {}",
        text(&bad_direct)
    );
    assert!(
        kept_disk.exists(),
        "VM disk under images/ must survive symlinked WORK_DIR"
    );
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
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
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

#[test]
fn preflight_and_install_packages_require_git_and_support_modular_virtqemud() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Controlled PATH containing all basic utilities and virtualization tools
    //    EXCEPT git: preflight MUST fail reporting missing 'git'.
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for util in ["awk", "df", "dirname", "grep", "sed", "tr", "cut", "head"] {
        let out = Command::new("which").arg(util).output().unwrap();
        assert!(out.status.success(), "host lacks {util}");
        let real = String::from_utf8(out.stdout).unwrap();
        std::os::unix::fs::symlink(real.trim(), bin.join(util)).unwrap();
    }
    write_exec(
        &bin.join("uname"),
        "#!/bin/sh\nif [ \"$1\" = -m ]; then echo x86_64; else echo Linux; fi\n",
    );
    write_exec(&bin.join("virsh"), FAKE_VIRSH);
    for tool in [
        "virtqemud",
        "qemu-system-x86_64",
        "qemu-img",
        "genisoimage",
        "jq",
        "curl",
        "sha256sum",
        "tar",
        "systemctl",
        "python3",
    ] {
        write_exec(&bin.join(tool), "#!/bin/sh\nexit 0\n");
    }

    let resolv = dir.path().join("resolv.conf");
    std::fs::write(&resolv, "nameserver 127.0.0.53\n").unwrap();
    let cgroup_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cgroup_ctrls, "cpu memory pids\n").unwrap();
    let log = dir.path().join("virsh.log");

    let run_preflight_isolated = || {
        Command::new("/bin/bash")
            .arg(script())
            .args(["preflight", "--state-dir", dir.path().to_str().unwrap()])
            .env("PATH", &bin)
            .env("FAKE_LOG", &log)
            .env("QEMINGA_KVM_DEVICE", "/dev/null")
            .env("QEMINGA_RESOLV_CONF", &resolv)
            .env("QEMINGA_CGROUP_CONTROLLERS", &cgroup_ctrls)
            .env("QEMINGA_MIN_DISK_GIB", "0")
            .env("QEMINGA_MIN_RAM_MIB", "0")
            .output()
            .unwrap()
    };

    let no_git = run_preflight_isolated();
    assert!(
        !no_git.status.success(),
        "preflight must fail when git is missing: {}",
        text(&no_git)
    );
    assert!(
        text(&no_git).contains("missing tool 'git'"),
        "preflight output must name missing git: {}",
        text(&no_git)
    );

    // Adding git makes preflight pass (also proving modular virtqemud is accepted
    // when monolithic libvirtd is absent, as on Fedora).
    write_exec(&bin.join("git"), "#!/bin/sh\nexit 0\n");
    let with_git = run_preflight_isolated();
    assert!(
        with_git.status.success(),
        "preflight with git and virtqemud must succeed: {}",
        text(&with_git)
    );

    // 2. install_packages includes git in both apt-get and dnf branches for both arches.
    for (pm, arch) in [
        ("apt-get", "x86_64"),
        ("apt-get", "aarch64"),
        ("dnf", "x86_64"),
        ("dnf", "aarch64"),
    ] {
        let pm_bin = dir.path().join(format!("pm-{pm}-{arch}"));
        std::fs::create_dir_all(&pm_bin).unwrap();
        let pm_log = dir.path().join(format!("pm-{pm}-{arch}.log"));
        write_exec(
            &pm_bin.join(pm),
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_PM_LOG:?}\"\nexit 0\n",
        );
        let out = Command::new("/bin/bash")
            .args([
                "-c",
                r#"source "$1"; install_packages "$2""#,
                "_",
                script().to_str().unwrap(),
                arch,
            ])
            .env("PATH", &pm_bin)
            .env("FAKE_PM_LOG", &pm_log)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "install_packages ({pm}, {arch}) failed: {}",
            text(&out)
        );
        let logged = std::fs::read_to_string(&pm_log).unwrap();
        let has_git_token = logged
            .lines()
            .any(|line| line.split_whitespace().any(|tok| tok == "git"));
        assert!(
            has_git_token,
            "install_packages ({pm}, {arch}) must install git package: {logged}"
        );
    }
}

#[test]
fn ancestor_path_validation_rejects_unsafe_ancestor_under_safe_parent() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();

    // Fake stat returns 0:755 by default, unless FAKE_BAD_PATH matches $3.
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then
    if [ -n "${FAKE_BAD_PATH:-}" ] && [ "$3" = "$FAKE_BAD_PATH" ]; then
        echo "${FAKE_BAD_STAT:?}"
        exit 0
    fi
    echo "0:755"
    exit 0
fi
exec /usr/bin/stat "$@"
"#,
    );
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // 1. Safe-looking immediate parent beneath a symlinked ancestor MUST fail.
    let real_base = dir.path().join("real-base");
    let safe_parent = real_base.join("safe-parent");
    std::fs::create_dir_all(&safe_parent).unwrap();
    let sym_anc = dir.path().join("sym-anc");
    std::os::unix::fs::symlink(&real_base, &sym_anc).unwrap();
    let sym_target = sym_anc.join("safe-parent/runner");

    let out_sym = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; check_trusted_parent_dir "$2""#,
            "_",
            script().to_str().unwrap(),
            sym_target.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .output()
        .unwrap();
    assert!(
        !out_sym.status.success(),
        "symlinked ancestor beneath safe-looking parent must be refused: {}",
        text(&out_sym)
    );

    // 2. Safe-looking root-owned 0755 immediate parent beneath a world-writable
    //    (0:777) or non-root (1000:755) ancestor MUST fail.
    let unsafe_anc = dir.path().join("unsafe-anc");
    let nested_safe = unsafe_anc.join("safe-parent");
    std::fs::create_dir_all(&nested_safe).unwrap();
    let nested_target = nested_safe.join("runner");
    for (label, bad_stat) in [("world-writable", "0:777"), ("non-root-owner", "1000:755")] {
        let out = Command::new("bash")
            .args([
                "-c",
                r#"source "$1"; check_trusted_parent_dir "$2""#,
                "_",
                script().to_str().unwrap(),
                nested_target.to_str().unwrap(),
            ])
            .env("PATH", &path_env)
            .env("FAKE_BAD_PATH", &unsafe_anc)
            .env("FAKE_BAD_STAT", bad_stat)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{label} ancestor under safe-looking immediate parent must be refused: {}",
            text(&out)
        );
    }

    // 3. When all ancestors from / down are root-owned 0755 non-symlinks, check passes.
    let ok = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; check_trusted_parent_dir "$2""#,
            "_",
            script().to_str().unwrap(),
            nested_target.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "clean ancestor chain must pass: {}",
        text(&ok)
    );
}

#[test]
fn update_requires_valid_install_record_and_rejects_mismatched_flags() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
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

    let inst = dir.path().join("runner");
    let other_inst = dir.path().join("other-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [
        inst.join("bin"),
        other_inst.join("bin"),
        state.clone(),
        hooks.clone(),
        cfg.clone(),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(inst.join("bin/keep"), b"orig").unwrap();
    std::fs::write(other_inst.join("bin/precious"), b"unrelated").unwrap();

    // 1. update WITHOUT install.env must fail closed before modifying anything.
    let no_rec = run_setup_env(
        &[
            "update",
            "--install-dir",
            inst.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
        ],
        &[],
        Some(&bin),
    );
    assert!(
        !no_rec.status.success(),
        "update without install.env must fail closed: {}",
        text(&no_rec)
    );
    assert!(inst.join("bin/keep").exists());

    // 2. With a valid install.env, passing a mismatched --install-dir or --service MUST fail
    //    and leave both directories untouched.
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-kvm-runner\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    let bad_dir = run_setup_env(
        &[
            "update",
            "--install-dir",
            other_inst.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
        ],
        &[],
        Some(&bin),
    );
    assert!(
        !bad_dir.status.success(),
        "update with mismatched --install-dir must be refused: {}",
        text(&bad_dir)
    );
    assert!(other_inst.join("bin/precious").exists());

    let bad_svc = run_setup_env(
        &[
            "update",
            "--service",
            "unrelated-donor-svc",
            "--config-dir",
            cfg.to_str().unwrap(),
        ],
        &[],
        Some(&bin),
    );
    assert!(
        !bad_svc.status.success(),
        "update with mismatched --service must be refused: {}",
        text(&bad_svc)
    );

    // 3. update on a user-only record (post-uninstall) must also be refused.
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=user-only\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nCONFIG_DIR={}\n",
            cfg.display(),
        ),
    )
    .unwrap();
    let on_user_only = run_setup_env(
        &["update", "--config-dir", cfg.to_str().unwrap()],
        &[],
        Some(&bin),
    );
    assert!(
        !on_user_only.status.success(),
        "update on user-only record must be refused: {}",
        text(&on_user_only)
    );
}

#[test]
fn fresh_install_refuses_existing_systemd_unit_without_install_record() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let vendor_units = dir.path().join("usr-lib-systemd");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(&vendor_units).unwrap();

    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then
    echo "${FAKE_LOAD_STATE:-not-found}"
    exit 0
fi
if [ "$1" = "list-unit-files" ]; then
    printf '%s\n' "${FAKE_UNIT_FILES:-}"
    exit 0
fi
if [ "$1" = "is-active" ]; then
    exit "${FAKE_IS_ACTIVE_RC:-3}"
fi
exit 0
"#,
    );
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let unit_dirs = format!("{}:{}", etc_units.display(), vendor_units.display());

    // 1. Clean unit name passes check_unit_not_occupied.
    let ok = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_SERVICE="qeminga-fresh-svc"; check_unit_not_occupied"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "unoccupied unit name should pass: {}",
        text(&ok)
    );

    // 2. Vendor unit file under /usr/lib/systemd/system collides and MUST fail.
    std::fs::write(vendor_units.join("donor-vendor.service"), "[Unit]\n").unwrap();
    let vendor_hit = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_SERVICE="donor-vendor"; check_unit_not_occupied"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs)
        .output()
        .unwrap();
    assert!(
        !vendor_hit.status.success(),
        "fresh install must refuse colliding vendor unit file: {}",
        text(&vendor_hit)
    );

    // 3. Systemd-known unit via LoadState=loaded or list-unit-files MUST fail even when
    //    not present in the scanned unit directories.
    let loaded_hit = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_SERVICE="donor-loaded"; check_unit_not_occupied"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs)
        .env("FAKE_LOAD_STATE", "loaded")
        .output()
        .unwrap();
    assert!(
        !loaded_hit.status.success(),
        "fresh install must refuse systemd-loaded unit without install.env: {}",
        text(&loaded_hit)
    );

    let listed_hit = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_SERVICE="donor-listed"; check_unit_not_occupied"#,
            "_",
            script().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs)
        .env("FAKE_UNIT_FILES", "donor-listed.service disabled")
        .output()
        .unwrap();
    assert!(
        !listed_hit.status.success(),
        "fresh install must refuse unit reported by systemctl list-unit-files: {}",
        text(&listed_hit)
    );
}

#[test]
fn ownership_record_survives_failed_download_and_normal_uninstall_for_reinstall() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let rt_root = dir.path().join("run");
    let etc_units = dir.path().join("etc-systemd");
    let fake_tar_src = dir.path().join("tar-src");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("bin")).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("externals")).unwrap();

    // Build a valid fake runner tarball and compute its SHA-256.
    write_exec(
        &fake_tar_src.join("config.sh"),
        r#"#!/bin/sh
# Write a realistic .runner file with disableUpdate:true.
work=""
url=""
name=""
while [ $# -gt 0 ]; do
    case "$1" in
        --url) url="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --work) work="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '{"agentId":1,"agentName":"%s","gitHubUrl":"%s","workFolder":"%s","disableUpdate":true}\n' "$name" "$url" "$work" > "$(dirname "$0")/.runner"
exit 0
"#,
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let good_tarball = dir.path().join("runner-good.tar.gz");
    let tar_out = Command::new("tar")
        .args([
            "-czf",
            good_tarball.to_str().unwrap(),
            "-C",
            fake_tar_src.to_str().unwrap(),
            ".",
        ])
        .output()
        .unwrap();
    assert!(tar_out.status.success(), "{}", text(&tar_out));
    let good_sha = sha256_of(&std::fs::read(&good_tarball).unwrap());

    // Stateful fake account database so useradd/id/userdel reflect real lifecycle transitions.
    let user_flag = dir.path().join("user_exists");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let tok_file = dir.path().join("token");
    std::fs::write(&tok_file, "FAKE_REG_TOKEN\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
case "$1" in
    -u) echo 995 ;;
    -g) echo 995 ;;
    -gn) echo qeminga-runner ;;
    -nG) echo "qeminga-runner kvm" ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(
        &bin.join("useradd"),
        "#!/bin/sh\n: > \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("install"),
        r#"#!/bin/sh
# Strip -o / -g ownership flags so unprivileged tests can create real files/dirs.
args=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) args="$args $(printf '%s' "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/")"; shift ;;
    esac
done
eval "exec /usr/bin/install $args"
"#,
    );
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
    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then exit 3; fi
exit 0
"#,
    );
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
    // Fake curl: verify_private_repo gets 404 (private!), while tarball download fails or copies.
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
# Check if this is verify_private_repo (-w %{http_code})
for a in "$@"; do
    case "$a" in
        *api.github.com/repos/*)
            printf '404'
            exit 0
            ;;
    esac
done
if [ "${FAKE_DOWNLOAD_FAIL:-0}" = "1" ]; then
    exit 22
fi
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
cp "${FAKE_GOOD_TARBALL:?}" "$out"
exit 0
"#,
    );
    write_exec(&bin.join("virsh"), FAKE_VIRSH);

    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"fw-code").unwrap();
    std::fs::write(&aavmf_vars, b"fw-vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = etc_units.to_str().unwrap();
    let virsh_log = dir.path().join("virsh.log");
    let common_env = [
        ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
        ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
        ("FAKE_LOG", virsh_log.to_str().unwrap()),
        ("QEMINGA_KVM_DEVICE", "/dev/null"),
        ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
        ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
        ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
        ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
        ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
    ];
    let install_args = [
        "install",
        "--repo",
        REPO_URL,
        "--name",
        "recovery-box",
        "--service",
        "qeminga-recovery-svc",
        "--install-dir",
        inst.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
        "--hook-dir",
        hooks.to_str().unwrap(),
        "--config-dir",
        cfg.to_str().unwrap(),
        "--token-file",
        tok_file.to_str().unwrap(),
        "--runner-sha256",
        good_sha.as_str(),
        "--skip-packages",
        "--no-start",
    ];

    // 1. First install fails mid-flight during runner download (after user & state creation).
    let mut env_fail = common_env.to_vec();
    env_fail.push(("FAKE_DOWNLOAD_FAIL", "1"));
    let fail1 = run_setup_env(&install_args, &env_fail, Some(&bin));
    assert!(
        !fail1.status.success(),
        "interrupted download must fail install: {}",
        text(&fail1)
    );
    assert!(
        user_flag.exists(),
        "service user was created before download failed: {}",
        text(&fail1)
    );
    let rec_after_fail = std::fs::read_to_string(cfg.join("install.env")).unwrap_or_else(|e| {
        panic!(
            "ownership record install.env MUST be written before download so retry/uninstall works: {e}"
        )
    });
    assert!(
        rec_after_fail.contains("RECORD_STATE=installing\n"),
        "interrupted install must leave RECORD_STATE=installing:\n{rec_after_fail}"
    );

    // 2. Retrying the exact same install command succeeds once the network recovers.
    let mut env_ok = common_env.to_vec();
    env_ok.push(("FAKE_DOWNLOAD_FAIL", "0"));
    let retry_ok = run_setup_env(&install_args, &env_ok, Some(&bin));
    assert!(
        retry_ok.status.success(),
        "retrying install after interrupted download must succeed: {}",
        text(&retry_ok)
    );
    let rec_installed = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_installed.contains("RECORD_STATE=installed\n"),
        "completed install must mark RECORD_STATE=installed:\n{rec_installed}"
    );

    // 3. Ordinary uninstall WITHOUT --purge-user removes runner/state/hooks/policy while
    //    retaining the minimal user-only ownership record so the surviving account is tracked.
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--service",
            "qeminga-recovery-svc",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
        ],
        &env_ok,
        Some(&bin),
    );
    assert!(
        uninst.status.success(),
        "ordinary uninstall without --purge-user must succeed: {}",
        text(&uninst)
    );
    assert!(
        !inst.exists() && !state.exists() && !hooks.exists() && !cfg.join("policy.env").exists(),
        "ordinary uninstall must remove install, state, hooks, and policy"
    );
    assert!(
        user_flag.exists(),
        "ordinary uninstall without --purge-user keeps the service user"
    );
    let rec_user_only = std::fs::read_to_string(cfg.join("install.env")).unwrap_or_else(|e| {
        panic!("ordinary uninstall without --purge-user must retain minimal UID/GID record: {e}")
    });
    assert!(
        rec_user_only.contains("RECORD_STATE=user-only\n")
            && rec_user_only.contains("USER=qeminga-runner\n")
            && rec_user_only.contains("USER_UID=995\n"),
        "retained record must be user-only with UID/GID metadata:\n{rec_user_only}"
    );

    // 4. A subsequent default install MUST recognize and reuse its own surviving account!
    let reinstall = run_setup_env(&install_args, &env_ok, Some(&bin));
    assert!(
        reinstall.status.success(),
        "reinstall after ordinary uninstall without --purge-user must succeed: {}",
        text(&reinstall)
    );
    assert!(
        std::fs::read_to_string(cfg.join("install.env"))
            .unwrap()
            .contains("RECORD_STATE=installed\n")
    );

    // 5. Uninstall without --purge-user followed by a later uninstall --purge-user cleans
    //    up both the surviving account and the retained config directory completely.
    let uninst2 = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &env_ok,
        Some(&bin),
    );
    assert!(uninst2.status.success(), "{}", text(&uninst2));
    let purge_later = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &env_ok,
        Some(&bin),
    );
    assert!(
        purge_later.status.success(),
        "later uninstall --purge-user on user-only record must succeed: {}",
        text(&purge_later)
    );
    assert!(
        !user_flag.exists() && !cfg.exists(),
        "later --purge-user must delete surviving user and remove retained config dir"
    );
}

#[test]
fn uninstall_verifies_recorded_uid_and_gid_before_credentials_or_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let rt_root = dir.path().join("run");
    let etc_units = dir.path().join("etc-systemd");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [&bin, &rt_root, &etc_units, &inst, &state, &hooks, &cfg] {
        std::fs::create_dir_all(d).unwrap();
    }

    let runuser_log = dir.path().join("runuser.log");
    let chown_log = dir.path().join("chown.log");
    let systemctl_log = dir.path().join("systemctl.log");
    let unit_file = etc_units.join("qeminga-uid-guard.service");
    std::fs::write(&unit_file, "[Unit]\n").unwrap();
    std::fs::write(inst.join(".credentials"), b"secret-runner-creds").unwrap();
    write_exec(&inst.join("config.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&hooks.join("hook-job-completed.sh"), "#!/bin/sh\nexit 0\n");
    std::fs::write(
        cfg.join("policy.env"),
        "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\n",
    )
    .unwrap();
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-uid-guard\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();
    let tok = dir.path().join("rm-token");
    std::fs::write(&tok, "REMOVE_TOKEN_SECRET\n").unwrap();
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o600)).unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo "${FAKE_LIVE_UID:?}"; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo "${FAKE_LIVE_GID:?}"; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("runuser"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_RUNUSER_LOG:?}\"\nexit 0\n",
    );
    write_exec(
        &bin.join("chown"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_CHOWN_LOG:?}\"\nexit 0\n",
    );
    write_exec(
        &bin.join("systemctl"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_SC_LOG:?}\"\nexit 0\n",
    );
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:755"; exit 0; fi
exec /usr/bin/stat "$@"
"#,
    );

    for (label, live_uid, live_gid) in [
        ("uid-reassigned", "996", "995"),
        ("gid-reassigned", "995", "996"),
        ("uid-zero", "0", "995"),
    ] {
        let out = run_setup_env(
            &[
                "uninstall",
                "--config-dir",
                cfg.to_str().unwrap(),
                "--token-file",
                tok.to_str().unwrap(),
            ],
            &[
                ("FAKE_LIVE_UID", live_uid),
                ("FAKE_LIVE_GID", live_gid),
                ("FAKE_RUNUSER_LOG", runuser_log.to_str().unwrap()),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
                ("FAKE_SC_LOG", systemctl_log.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", etc_units.to_str().unwrap()),
            ],
            Some(&bin),
        );
        assert!(
            !out.status.success(),
            "uninstall with {label} ({live_uid}:{live_gid}) MUST fail closed: {}",
            text(&out)
        );
        assert!(
            !runuser_log.exists(),
            "{label}: uninstall must NEVER invoke runuser before verifying UID/GID"
        );
        assert!(
            !chown_log.exists(),
            "{label}: uninstall must NEVER chown runner credentials before verifying UID/GID"
        );
        assert!(
            !systemctl_log.exists(),
            "{label}: uninstall must NEVER stop/disable service before verifying UID/GID"
        );
        assert!(
            cfg.join("install.env").exists()
                && inst.join(".credentials").exists()
                && unit_file.exists(),
            "{label}: mismatch must leave install.env, credentials, and unit intact for recovery"
        );
    }
}

#[test]
fn install_fails_without_marking_installed_when_service_start_rejects_firewall() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let fake_tar_src = dir.path().join("tar-src");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("bin")).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("externals")).unwrap();

    write_exec(
        &fake_tar_src.join("config.sh"),
        r#"#!/bin/sh
work="" url="" name=""
while [ $# -gt 0 ]; do
    case "$1" in
        --url) url="$2"; shift 2 ;;
        --name) name="$2"; shift 2 ;;
        --work) work="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '{"agentId":1,"agentName":"%s","gitHubUrl":"%s","workFolder":"%s","disableUpdate":true}\n' "$name" "$url" "$work" > "$(dirname "$0")/.runner"
exit 0
"#,
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let good_tarball = dir.path().join("runner.tar.gz");
    let tar_out = Command::new("tar")
        .args([
            "-czf",
            good_tarball.to_str().unwrap(),
            "-C",
            fake_tar_src.to_str().unwrap(),
            ".",
        ])
        .output()
        .unwrap();
    assert!(tar_out.status.success(), "{}", text(&tar_out));
    let good_sha = sha256_of(&std::fs::read(&good_tarball).unwrap());

    let user_flag = dir.path().join("user_exists");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let tok_file = dir.path().join("token");
    std::fs::write(&tok_file, "FAKE_REG_TOKEN\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
case "$1" in
    -u) echo 995 ;;
    -g) echo 995 ;;
    -gn) echo qeminga-runner ;;
    -nG) echo "qeminga-runner kvm" ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(
        &bin.join("useradd"),
        "#!/bin/sh\n: > \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("install"),
        r#"#!/bin/sh
args=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) args="$args $(printf '%s' "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/")"; shift ;;
    esac
done
eval "exec /usr/bin/install $args"
"#,
    );
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
    // Simulate systemd Type=notify rejecting startup when run-runner.sh exits 78 without READY=1.
    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then exit 3; fi
if [ "$1" = "enable" ] || [ "$1" = "start" ]; then
    echo "Job for qeminga-notify-svc.service failed because the control process exited with error code 78." >&2
    exit 1
fi
exit 0
"#,
    );
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in *api.github.com/repos/*) printf '404'; exit 0 ;; esac
done
out=""
while [ $# -gt 0 ]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
cp "${FAKE_GOOD_TARBALL:?}" "$out"
exit 0
"#,
    );

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = etc_units.to_str().unwrap();
    let failed_start = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "notify-box",
            "--service",
            "qeminga-notify-svc",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !failed_start.status.success(),
        "install MUST fail when Type=notify service start fails firewall gate: {}",
        text(&failed_start)
    );
    assert!(
        !text(&failed_start).contains("qeminga KVM runner installed:"),
        "failed startup must NOT report the runner installed/started: {}",
        text(&failed_start)
    );
    let rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec.contains("RECORD_STATE=installing\n") && rec.contains("OWNED_UNIT=1\n"),
        "failed start must keep RECORD_STATE=installing with OWNED_UNIT=1:\n{rec}"
    );
    let installed_unit =
        std::fs::read_to_string(etc_units.join("qeminga-notify-svc.service")).unwrap();
    assert!(
        installed_unit.contains("Type=notify\n") && installed_unit.contains("NotifyAccess=main\n"),
        "installed unit must use Type=notify so systemctl start waits for firewall gate:\n{installed_unit}"
    );
}

#[test]
fn interrupted_install_tracks_per_resource_ownership_against_later_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let rt_root = dir.path().join("run");
    let etc_units = dir.path().join("etc-systemd");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();

    let user_flag = dir.path().join("user_exists");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let tok_file = dir.path().join("token");
    std::fs::write(&tok_file, "FAKE_REG_TOKEN\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let sc_log = dir.path().join("systemctl.log");

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
case "$1" in
    -u) echo 995 ;;
    -g) echo 995 ;;
    -gn) echo qeminga-runner ;;
    -nG) echo "qeminga-runner kvm" ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(
        &bin.join("useradd"),
        "#!/bin/sh\n: > \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("install"),
        r#"#!/bin/sh
args=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) args="$args $(printf '%s' "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/")"; shift ;;
    esac
done
eval "exec /usr/bin/install $args"
"#,
    );
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
    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then exit 3; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in *api.github.com/repos/*) printf '404'; exit 0 ;; esac
done
exit 22
"#,
    );

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = etc_units.to_str().unwrap();
    let common_env = [
        ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
        ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
        ("QEMINGA_KVM_DEVICE", "/dev/null"),
        ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
        ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
        ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
        ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
        ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
    ];

    // 1. First install fails during runner download (after creating user + state dir,
    //    BEFORE creating install_dir, hook_dir, or systemd unit).
    let fail1 = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "collide-box",
            "--service",
            "qeminga-collide-svc",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--skip-packages",
            "--no-start",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(!fail1.status.success(), "{}", text(&fail1));
    let rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    for expected in [
        "RECORD_STATE=installing\n",
        "OWNED_CONFIG_DIR=1\n",
        "OWNED_STATE_DIR=1\n",
        "OWNED_INSTALL_DIR=0\n",
        "OWNED_HOOK_DIR=0\n",
        "OWNED_UNIT=0\n",
    ] {
        assert!(
            rec.contains(expected),
            "interrupted install record missing {expected:?}:\n{rec}"
        );
    }

    // 2. An independent service now claims the same service name and install_dir path!
    let foreign_unit = etc_units.join("qeminga-collide-svc.service");
    std::fs::write(
        &foreign_unit,
        "[Unit]\nDescription=unrelated donor service\n",
    )
    .unwrap();
    std::fs::create_dir_all(&inst).unwrap();
    std::fs::write(inst.join("foreign.txt"), b"do-not-touch").unwrap();

    // 3. Retrying install MUST refuse because OWNED_UNIT=0 / OWNED_INSTALL_DIR=0!
    let retry_collide = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "collide-box",
            "--service",
            "qeminga-collide-svc",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--skip-packages",
            "--no-start",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(
        !retry_collide.status.success(),
        "retry must refuse colliding unowned unit/dir after interrupted install: {}",
        text(&retry_collide)
    );
    assert!(
        foreign_unit.exists() && inst.join("foreign.txt").exists(),
        "colliding foreign service and dir must stay untouched on failed retry"
    );

    // 4. Uninstall --purge-user MUST clean up ONLY our owned resources (state dir, user,
    //    config dir) and MUST NOT stop, disable, or delete the foreign service or foreign dir!
    let _ = std::fs::remove_file(&sc_log);
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(
        uninst.status.success(),
        "uninstall of interrupted install should succeed without touching foreign resources: {}",
        text(&uninst)
    );
    assert!(
        foreign_unit.exists(),
        "uninstall must NEVER delete a same-named service that had OWNED_UNIT=0"
    );
    assert!(
        inst.join("foreign.txt").exists(),
        "uninstall must NEVER delete a directory that had OWNED_INSTALL_DIR=0"
    );
    let sc_calls = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        !sc_calls.contains("stop qeminga-collide-svc.service")
            && !sc_calls.contains("disable qeminga-collide-svc.service"),
        "uninstall must NEVER stop/disable a service that had OWNED_UNIT=0: {sc_calls}"
    );
    assert!(
        !state.exists() && !user_flag.exists() && !cfg.exists(),
        "owned state dir, managed user, and config dir must be cleaned up"
    );
}

#[test]
fn jit_install_bootstraps_jq_via_install_packages_before_decoding_blob() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let fake_tar_src = dir.path().join("tar-src");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("bin")).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("externals")).unwrap();

    // Symlink essential POSIX utilities into isolated bin WITHOUT jq initially.
    for util in [
        "awk",
        "base64",
        "cat",
        "chmod",
        "cp",
        "cut",
        "dirname",
        "env",
        "find",
        "grep",
        "gzip",
        "head",
        "hostname",
        "ln",
        "mkdir",
        "mktemp",
        "mv",
        "rm",
        "sed",
        "sha256sum",
        "tar",
        "tr",
        "uname",
    ] {
        let out = Command::new("which").arg(util).output().unwrap();
        assert!(out.status.success(), "host lacks {util}");
        let real = String::from_utf8(out.stdout).unwrap();
        std::os::unix::fs::symlink(real.trim(), bin.join(util)).unwrap();
    }
    let real_jq_out = Command::new("which").arg("jq").output().unwrap();
    assert!(real_jq_out.status.success(), "host lacks jq");
    let real_jq = String::from_utf8(real_jq_out.stdout).unwrap();
    let real_jq = real_jq.trim();

    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("config.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let good_tarball = dir.path().join("runner-jit.tar.gz");
    let tar_out = Command::new("tar")
        .args([
            "-czf",
            good_tarball.to_str().unwrap(),
            "-C",
            fake_tar_src.to_str().unwrap(),
            ".",
        ])
        .output()
        .unwrap();
    assert!(tar_out.status.success(), "{}", text(&tar_out));
    let good_sha = sha256_of(&std::fs::read(&good_tarball).unwrap());

    let user_flag = dir.path().join("user_exists");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    // Fake apt-get installs jq into our isolated bin when install_packages runs!
    write_exec(
        &bin.join("apt-get"),
        r#"#!/bin/sh
if [ "$1" = "install" ]; then
    ln -sf "${REAL_JQ_BIN:?}" "${ISOLATED_BIN:?}/jq"
fi
exit 0
"#,
    );
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
case "$1" in
    -u) echo 995 ;;
    -g) echo 995 ;;
    -gn) echo qeminga-runner ;;
    -nG) echo "qeminga-runner kvm" ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(
        &bin.join("useradd"),
        "#!/bin/sh\n: > \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("install"),
        r#"#!/bin/sh
args=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|-g) shift 2 ;;
        *) args="$args $(printf '%s' "$1" | sed "s/'/'\\\\''/g; s/^/'/; s/\$/'/")"; shift ;;
    esac
done
eval "exec /usr/bin/install $args"
"#,
    );
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
    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then exit 3; fi
exit 0
"#,
    );
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in *api.github.com/repos/*) printf '404'; exit 0 ;; esac
done
out=""
while [ $# -gt 0 ]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
cp "${FAKE_GOOD_TARBALL:?}" "$out"
exit 0
"#,
    );

    let jit_file = dir.path().join("jitconfig");
    std::fs::write(&jit_file, make_jit_config(REPO_URL, "_work")).unwrap();
    std::fs::set_permissions(&jit_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = etc_units.to_str().unwrap();

    // 1. With --skip-packages and no jq on PATH, install MUST fail with clear missing-jq
    //    error BEFORE creating any service user or managed directories.
    let no_jq_skip = Command::new("/bin/bash")
        .arg(script())
        .args([
            "install",
            "--repo",
            REPO_URL,
            "--service",
            "qeminga-jit-bootstrap",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--jitconfig-file",
            jit_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ])
        .env("PATH", &bin)
        .env("FAKE_USER_FLAG", &user_flag)
        .env("FAKE_GOOD_TARBALL", &good_tarball)
        .env("REAL_JQ_BIN", real_jq)
        .env("ISOLATED_BIN", &bin)
        .env("QEMINGA_KVM_DEVICE", "/dev/null")
        .env("QEMINGA_CGROUP_CONTROLLERS", &cg_ctrls)
        .env("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir)
        .env("QEMINGA_AAVMF_CODE", &aavmf_code)
        .env("QEMINGA_AAVMF_VARS", &aavmf_vars)
        .output()
        .unwrap();
    assert!(
        !no_jq_skip.status.success(),
        "--skip-packages without jq must fail: {}",
        text(&no_jq_skip)
    );
    assert!(
        text(&no_jq_skip).contains("jq is required"),
        "missing-jq error should be clear: {}",
        text(&no_jq_skip)
    );
    assert!(
        !user_flag.exists() && !cfg.exists() && !state.exists(),
        "--skip-packages failure must occur before creating user or directories"
    );

    // 2. Normal one-command JIT install (no --skip-packages) on a fresh host without jq
    //    installs jq via install_packages first, then decodes/validates the JIT blob and succeeds!
    let bootstrap_ok = Command::new("/bin/bash")
        .arg(script())
        .args([
            "install",
            "--repo",
            REPO_URL,
            "--service",
            "qeminga-jit-bootstrap",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--jitconfig-file",
            jit_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--no-start",
        ])
        .env("PATH", &bin)
        .env("FAKE_USER_FLAG", &user_flag)
        .env("FAKE_GOOD_TARBALL", &good_tarball)
        .env("REAL_JQ_BIN", real_jq)
        .env("ISOLATED_BIN", &bin)
        .env("QEMINGA_KVM_DEVICE", "/dev/null")
        .env("QEMINGA_CGROUP_CONTROLLERS", &cg_ctrls)
        .env("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir)
        .env("QEMINGA_AAVMF_CODE", &aavmf_code)
        .env("QEMINGA_AAVMF_VARS", &aavmf_vars)
        .output()
        .unwrap();
    assert!(
        bootstrap_ok.status.success(),
        "one-command JIT install must bootstrap jq via install_packages before decoding JIT blob: {}",
        text(&bootstrap_ok)
    );
    assert!(
        hooks.join("run-jit.sh").exists()
            && cfg.join("jitconfig").exists()
            && std::fs::read_to_string(cfg.join("install.env"))
                .unwrap()
                .contains("RECORD_STATE=installed\n"),
        "JIT bootstrap install must complete cleanly"
    );
}
