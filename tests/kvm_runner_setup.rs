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

/// Create a private mode-0700 temporary directory at creation time so executable
/// test stubs placed under `<dir>/bin` and prepended to `PATH` can never be
/// modified by other local users on a shared host even under permissive umasks.
fn private_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

/// Write a mock `systemctl` stub that answers live
/// `systemctl show -p LoadState -p FragmentPath <unit>` (and
/// `systemctl show -p LoadState --value <unit>`) queries consistently with
/// `QEMINGA_SYSTEMD_UNIT_DIR`, then runs `body` for all other verbs.
fn write_mock_systemctl(path: &Path, body: &str) {
    let rest = body.strip_prefix("#!/bin/sh\n").unwrap_or(body);
    let full = format!(
        "#!/bin/sh\n\
if [ \"$1\" = \"show\" ]; then\n\
    val_only=0; unit=\"\"\n\
    for a in \"$@\"; do [ \"$a\" = \"--value\" ] && val_only=1; unit=\"$a\"; done\n\
    if [ \"$val_only\" -eq 1 ]; then echo \"not-found\"; exit 0; fi\n\
    udir=\"${{QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}}\"\n\
    if [ -f \"${{udir%/}}/${{unit}}\" ]; then echo \"LoadState=loaded\"; echo \"FragmentPath=${{udir%/}}/${{unit}}\"; else echo \"LoadState=not-found\"; echo \"FragmentPath=\"; fi\n\
    exit 0\n\
fi\n\
{rest}"
    );
    write_exec(path, &full);
}

fn live_volume_id(path: &Path) -> String {
    let out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn build_fake_runner_tarball(root: &Path) -> (PathBuf, String) {
    let fake_tar_src = root.join("tar-src");
    std::fs::create_dir_all(fake_tar_src.join("bin")).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("externals")).unwrap();
    write_exec(
        &fake_tar_src.join("config.sh"),
        r#"#!/bin/sh
work=""; url=""; name=""
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
    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let tarball = root.join("runner-fixture.tar.gz");
    let tar_out = Command::new("tar")
        .args([
            "-czf",
            tarball.to_str().unwrap(),
            "-C",
            fake_tar_src.to_str().unwrap(),
            ".",
        ])
        .output()
        .unwrap();
    assert!(tar_out.status.success(), "{}", text(&tar_out));
    let sha = sha256_of(&std::fs::read(&tarball).unwrap());
    (tarball, sha)
}

fn install_standard_mock_bin(bin: &Path) {
    std::fs::create_dir_all(bin).unwrap();
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
    write_exec(&bin.join("useradd"), FAKE_USERADD_GECOS);
    write_exec(&bin.join("getent"), FAKE_GETENT_GECOS);
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("usermod"),
        r#"#!/bin/sh
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--comment)
            if [ -n "${FAKE_USER_FLAG:-}" ]; then
                printf '%s\n' "$2" > "$FAKE_USER_FLAG"
            fi
            shift 2
            ;;
        *) shift ;;
    esac
done
exit 0
"#,
    );
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
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
if [ -n "${FAKE_SC_LOG:-}" ]; then
    printf '%s\n' "$*" >> "$FAKE_SC_LOG"
fi
if [ "$1" = "show" ]; then
    val_only=0
    unit=""
    for a in "$@"; do
        if [ "$a" = "--value" ]; then val_only=1; fi
        unit="$a"
    done
    if [ "$val_only" -eq 1 ]; then
        echo "not-found"
        exit 0
    fi
    udir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    if [ -f "${udir%/}/${unit}" ]; then
        echo "LoadState=loaded"
        echo "FragmentPath=${udir%/}/${unit}"
    else
        echo "LoadState=not-found"
        echo "FragmentPath="
    fi
    exit 0
fi
if [ "$1" = "is-active" ]; then rc="${FAKE_IS_ACTIVE_RC:-3}"; if [ "$rc" -eq 0 ]; then echo active; else echo inactive; fi; exit "$rc"; fi
exit 0
"#,
    );
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in
        *api.github.com/repos/*) printf '404'; exit 0 ;;
    esac
done
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
    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );
}

fn runner_registration_config_script(agent_name: &str) -> String {
    format!(
        r#"#!/bin/sh
dir="$(dirname "$0")"
printf '{{"gitHubUrl":"{REPO_URL}","agentName":"{agent_name}","workFolder":"%s","disableUpdate":true,"ephemeral":false}}\n' "${{HOME}}/work" > "$dir/.runner"
exit 0
"#
    )
}

fn build_versioned_runner_pkg(
    out_dir: &Path,
    src: &Path,
    tag: &str,
    archive_name: &str,
    config_script: &str,
) -> (PathBuf, String) {
    std::fs::create_dir_all(src.join("bin")).unwrap();
    std::fs::create_dir_all(src.join("externals")).unwrap();
    write_exec(&src.join("bin/Runner.Listener"), "#!/bin/sh\nexit 0\n");
    write_exec(&src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&src.join("run.sh"), &format!("#!/bin/sh\necho {tag}\n"));
    write_exec(&src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&src.join("config.sh"), config_script);
    std::fs::write(src.join(format!("bin/{tag}-marker")), tag.as_bytes()).unwrap();
    std::fs::write(src.join(format!("externals/{tag}-ext")), tag.as_bytes()).unwrap();
    let tb = out_dir.join(archive_name);
    assert!(
        Command::new("tar")
            .args(["-czf", tb.to_str().unwrap(), "-C"])
            .arg(src)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let sha = sha256_of(&std::fs::read(&tb).unwrap());
    (tb, sha)
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
    let dir = private_tempdir();
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

    let dir = private_tempdir();
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

    let tmp = private_tempdir();
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
    let dir = private_tempdir();
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
    let dir = private_tempdir();
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
        let dir = private_tempdir();
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

const FAKE_USERADD_GECOS: &str = r#"#!/bin/sh
comment=""
while [ $# -gt 0 ]; do
    case "$1" in
        --comment|-c) comment="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '%s\n' "$comment" > "${FAKE_USER_FLAG:?}"
exit 0
"#;

const FAKE_GETENT_GECOS: &str = r#"#!/bin/sh
if [ "$1" = "passwd" ] && [ -f "${FAKE_USER_FLAG:?}" ]; then
    comment="$(cat "${FAKE_USER_FLAG:?}")"
    printf '%s:x:995:995:%s:/var/lib/qeminga-runner:/usr/sbin/nologin\n' "$2" "$comment"
    exit 0
fi
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

    let dir = private_tempdir();
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
                r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_USER="qeminga-runner"; MANAGED_USER_UID=995; MANAGED_USER_GID=995; OPT_ALLOW_AUTO_UPDATE=0; OPT_EPHEMERAL=0; lock_runner_permissions"#,
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
    let dir = private_tempdir();
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then echo inactive; exit 3; fi\nexit 0\n",
    );
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
    let rt_root = dir.path().join("run");
    let units_dir = dir.path().join("etc-systemd");
    std::fs::create_dir_all(&rt_root).unwrap();
    std::fs::create_dir_all(&units_dir).unwrap();
    std::fs::write(
        units_dir.join("qeminga-test-nonexistent-unit.service"),
        "[Unit]\n",
    )
    .unwrap();
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
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", units_dir.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", units_dir.to_str().unwrap()),
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

    let dir = private_tempdir();
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
    let tmp = private_tempdir();

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

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    write_exec(&bin.join("chown"), FAKE_CHOWN);
    write_exec(&bin.join("install"), FAKE_INSTALL);
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
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

    let cfg_dir = dir.path().join("cfg");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    let state_dir = dir.path().join("state");
    let chown_log = dir.path().join("chown.log");
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
            r#"source "$1"
OPT_CONFIG_DIR="$2"
OPT_STATE_DIR="$3"
OPT_INSTALL_DIR="$4/runner"
OPT_HOOK_DIR="$4/hooks"
OPT_USER="qeminga-runner"
OPT_SERVICE="qeminga-test"
TARGET_URL="https://github.com/vicaya/qeminga-kvm-controller"
RESOLVED_WORK_DIR="$OPT_STATE_DIR/work"
MANAGED_USER_UID=995
MANAGED_USER_GID=995
MANAGED_USER_CREATED=1
OWNED_CONFIG_DIR=1
OWNED_STATE_DIR=0
claim_managed_dir state OWNED_STATE_DIR "$OPT_STATE_DIR" 0700 "$OPT_USER" "$OPT_USER" test-runner
grep -qx 'OWNED_STATE_DIR=1' "$OPT_CONFIG_DIR/install.env"
init_state_subdirs"#,
            "_",
            script().to_str().unwrap(),
            cfg_dir.to_str().unwrap(),
            state_dir.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_CHOWN_LOG", &chown_log)
        .env("FAKE_INSTALL_LOG", &install_log)
        .env("FAKE_RUNUSER_LOG", &runuser_log)
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "claim_managed_dir + init_state_subdirs failed: {}",
        text(&ok)
    );

    // Root chown/install must touch ONLY the top-level state directory, never any descendant.
    let root_chowns = std::fs::read_to_string(&chown_log).unwrap();
    assert!(
        !root_chowns.contains("/work")
            && !root_chowns.contains("/images")
            && !root_chowns.contains("/.local"),
        "root chown must not touch state descendants: {root_chowns}"
    );
    let root_installs = std::fs::read_to_string(&install_log).unwrap_or_default();
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

    // Symlinked top-level state dir must be refused by both claim_managed_dir and init_state_subdirs.
    let real_target = dir.path().join("real-target");
    std::fs::create_dir_all(&real_target).unwrap();
    let sym_state = dir.path().join("sym-state");
    symlink(&real_target, &sym_state).unwrap();
    let bad_claim = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_CONFIG_DIR="$2"; OPT_STATE_DIR="$3"; OPT_USER="qeminga-runner"; claim_managed_dir state OWNED_STATE_DIR "$OPT_STATE_DIR" 0700 "$OPT_USER" "$OPT_USER" test-runner"#,
            "_",
            script().to_str().unwrap(),
            cfg_dir.to_str().unwrap(),
            sym_state.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_CHOWN_LOG", &chown_log)
        .env("FAKE_INSTALL_LOG", &install_log)
        .env("FAKE_RUNUSER_LOG", &runuser_log)
        .output()
        .unwrap();
    assert!(
        !bad_claim.status.success(),
        "claim_managed_dir must refuse symlinked state dir"
    );
    let bad_init = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_STATE_DIR="$2"; OPT_USER="qeminga-runner"; init_state_subdirs"#,
            "_",
            script().to_str().unwrap(),
            sym_state.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_CHOWN_LOG", &chown_log)
        .env("FAKE_INSTALL_LOG", &install_log)
        .env("FAKE_RUNUSER_LOG", &runuser_log)
        .output()
        .unwrap();
    assert!(
        !bad_init.status.success(),
        "init_state_subdirs must refuse symlinked state dir"
    );

    // In cmd_install, stopping any owned service must happen before claiming or initializing state dirs.
    let body = std::fs::read_to_string(script()).unwrap();
    let install_fn = &body[body.find("cmd_install()").unwrap()..];
    let stop_pos = install_fn
        .find("ensure_owned_service_stopped install")
        .unwrap();
    let claim_pos = install_fn.find("claim_managed_dir state").unwrap();
    let prov_pos = install_fn.find("init_state_subdirs").unwrap();
    assert!(
        stop_pos < claim_pos && claim_pos < prov_pos,
        "cmd_install must stop the existing service before claiming and initializing state directories"
    );
}

#[test]
fn egress_firewall_check_gates_unit_startup_and_fails_closed_when_unfiltered() {
    let dir = private_tempdir();
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
    let dir = private_tempdir();
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then echo inactive; exit 3; fi\nexit 0\n",
    );
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
    let rt_root1 = dir.path().join("run1");
    let shared_install = dir.path().join("shared-install");
    let shared_state = dir.path().join("shared-state");
    let shared_hooks = dir.path().join("shared-hooks");
    let shared_cfg = dir.path().join("shared-cfg");
    for d in [
        &rt_root1,
        &shared_install,
        &shared_state,
        &shared_hooks,
        &shared_cfg,
    ] {
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
        &[("QEMINGA_RUNTIME_ROOT", rt_root1.to_str().unwrap())],
        Some(&bin),
    );
    assert!(
        !no_rec.status.success() && text(&no_rec).contains("missing installation record"),
        "uninstall without install.env must fail closed with missing-record error: {}",
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

    // 3. Uninstall preserves state/images when the real generated hook-job-completed.sh reports
    //    unknown domain state, releases ownership of the removed unit & runner dir via
    //    RECORD_STATE=partial-uninstall, blocks update/install while partial-uninstall is pending,
    //    and on retry (with --token-file) runs the generated hook in domain-only mode over a
    //    private temporary runtime dir so neither a replacement JIT workspace (writable or
    //    symlinked) nor a replacement service's /run/$SERVICE runtime dir is touched.
    let case3 = dir.path().join("preserve-images");
    let inst3 = case3.join("runner");
    let state3 = case3.join("state");
    let hooks3 = case3.join("hooks");
    let cfg3 = case3.join("cfg");
    let units3 = case3.join("etc-systemd");
    let sc_log3 = case3.join("systemctl.log");
    let chown_log3 = case3.join("chown.log");
    let virsh_rt_log3 = case3.join("virsh-rt.log");
    let virsh_fail_flag3 = case3.join("virsh-fail");
    let cg_ctrls3 = case3.join("cgroup.controllers");
    let aavmf_code3 = case3.join("AAVMF_CODE.fd");
    let aavmf_vars3 = case3.join("AAVMF_VARS.fd");
    let vm_disk = state3.join("images/qeminga-e2e-55-1-x86_64/root.qcow2");
    std::fs::create_dir_all(vm_disk.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&inst3).unwrap();
    std::fs::create_dir_all(&hooks3).unwrap();
    std::fs::create_dir_all(&cfg3).unwrap();
    std::fs::create_dir_all(&units3).unwrap();
    std::fs::write(&cg_ctrls3, "cpu memory pids\n").unwrap();
    std::fs::write(&aavmf_code3, b"code").unwrap();
    std::fs::write(&aavmf_vars3, b"vars").unwrap();
    std::fs::write(&vm_disk, b"active-vm-disk").unwrap();
    std::fs::write(&virsh_fail_flag3, b"1").unwrap();
    let unit3 = units3.join("qeminga-test-preserve.service");
    std::fs::write(&unit3, "[Unit]\nDescription=original qeminga runner\n").unwrap();

    // Generate the real hook-job-completed.sh (not a stub) and pair it with a JIT policy.env
    // whose WORK_DIR lives under $INSTALL_DIR/_work.
    let render3 = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks3.to_str().unwrap(),
    ]);
    assert!(render3.status.success(), "{}", text(&render3));
    let state3_vol = live_volume_id(&state3);
    let inst3_vol = live_volume_id(&inst3);
    let hooks3_vol = live_volume_id(&hooks3);
    let unit3_vol = live_volume_id(&unit3);
    std::fs::write(
        cfg3.join("policy.env"),
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/_work\nIMAGES_DIR={}/images\nSTATE_VOL={state3_vol}\nINSTALL_VOL={inst3_vol}\nLIBVIRT_CONNECT=qemu:///session\n",
            inst3.display(),
            state3.display(),
            inst3.display(),
            state3.display(),
        ),
    )
    .unwrap();
    std::fs::write(
        cfg3.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nSERVICE=qeminga-test-preserve\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test\nLABELS=qeminga-kvm\nEPHEMERAL=1\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/_work\nVOL_UNIT={unit3_vol}\nVOL_INSTALL_DIR={inst3_vol}\nVOL_HOOK_DIR={hooks3_vol}\nVOL_STATE_DIR={state3_vol}\n",
            inst3.display(),
            state3.display(),
            hooks3.display(),
            cfg3.display(),
            inst3.display(),
        ),
    )
    .unwrap();

    // Dedicated bin with logged systemctl/chown/virsh plus userdel/groupdel for the full retry flow.
    let bin3 = case3.join("bin");
    std::fs::create_dir_all(&bin3).unwrap();
    let user_flag3 = case3.join("user_exists");
    std::fs::write(&user_flag3, b"").unwrap();
    write_exec(
        &bin3.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin3.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin3.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin3.join("getent"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(
        &bin3.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
exit 0
"#,
    );
    write_exec(
        &bin3.join("chown"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_CHOWN_LOG:?}"
exit 0
"#,
    );
    let rt_root = dir.path().join("run");
    std::fs::create_dir_all(&rt_root).unwrap();
    let repl_rt_dir = rt_root.join("qeminga-test-preserve");
    write_exec(
        &bin3.join("stat"),
        &format!(
            r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then
    if [ "$3" = "{}" ]; then
        echo "995:700"
        exit 0
    fi
    echo "0:755"
    exit 0
fi
exec /usr/bin/stat "$@"
"#,
            repl_rt_dir.display()
        ),
    );
    write_exec(
        &bin3.join("runuser"),
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
        &bin3.join("virsh"),
        r#"#!/bin/sh
printf '%s\n' "${XDG_RUNTIME_DIR:-}" >> "${FAKE_VIRSH_RT_LOG:?}"
if [ -f "${FAKE_VIRSH_FAIL:?}" ]; then
    echo "error: failed to connect to the hypervisor" >&2
    exit 1
fi
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    let unit_dir3 = units3.to_str().unwrap();
    let env3 = [
        ("FAKE_USER_FLAG", user_flag3.to_str().unwrap()),
        ("FAKE_SC_LOG", sc_log3.to_str().unwrap()),
        ("FAKE_CHOWN_LOG", chown_log3.to_str().unwrap()),
        ("FAKE_VIRSH_RT_LOG", virsh_rt_log3.to_str().unwrap()),
        ("FAKE_VIRSH_FAIL", virsh_fail_flag3.to_str().unwrap()),
        ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
        ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir3),
        ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir3),
        ("QEMINGA_KVM_DEVICE", "/dev/null"),
        ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls3.to_str().unwrap()),
        ("QEMINGA_AAVMF_CODE", aavmf_code3.to_str().unwrap()),
        ("QEMINGA_AAVMF_VARS", aavmf_vars3.to_str().unwrap()),
    ];
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
        &env3,
        Some(&bin3),
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
    assert!(
        !unit3.exists() && !inst3.exists(),
        "partial uninstall removes the owned unit file and runner binary dir"
    );
    let partial_rec = std::fs::read_to_string(cfg3.join("install.env")).unwrap();
    for expected in [
        "RECORD_STATE=partial-uninstall\n",
        "OWNED_UNIT=0\n",
        "OWNED_INSTALL_DIR=0\n",
        "OWNED_CONFIG_DIR=1\n",
        "OWNED_STATE_DIR=1\n",
        "OWNED_HOOK_DIR=1\n",
    ] {
        assert!(
            partial_rec.contains(expected),
            "partial uninstall must persist released ownership flags ({expected:?}):\n{partial_rec}"
        );
    }

    // Independently created replacement service, matching /run/$SERVICE runtime dir, and
    // replacement runner directory (with writable _work/ and config.sh) claim the released names!
    let repl_unit_body = "[Unit]\nDescription=independently created replacement service\n";
    std::fs::write(&unit3, repl_unit_body).unwrap();
    std::fs::create_dir_all(repl_rt_dir.join("libvirt")).unwrap();
    std::fs::set_permissions(&repl_rt_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(inst3.join("_work")).unwrap();
    std::fs::write(inst3.join("replacement.txt"), b"do-not-delete-replacement").unwrap();
    std::fs::write(
        inst3.join("_work/keep-replacement-work.txt"),
        b"do-not-scrub-replacement-jit-work",
    )
    .unwrap();
    let repl_cfg_log = case3.join("replacement-config-sh.log");
    write_exec(
        &inst3.join("config.sh"),
        &format!(
            "#!/bin/sh\nprintf 'INVOKED args=%s token=%s\\n' \"$*\" \"${{ACTIONS_RUNNER_INPUT_TOKEN:-}}\" > \"{}\"\nexit 0\n",
            repl_cfg_log.display()
        ),
    );

    // update MUST reject RECORD_STATE=partial-uninstall without touching replacements.
    let upd_partial = run_setup_env(
        &["update", "--config-dir", cfg3.to_str().unwrap()],
        &env3,
        Some(&bin3),
    );
    assert!(
        !upd_partial.status.success(),
        "update MUST reject partial-uninstall state: {}",
        text(&upd_partial)
    );
    assert!(
        text(&upd_partial).contains("partial-uninstall"),
        "update refusal should mention partial-uninstall state: {}",
        text(&upd_partial)
    );

    // install MUST also reject RECORD_STATE=partial-uninstall until uninstall finishes.
    let rm_tok = case3.join("rm-token");
    std::fs::write(&rm_tok, "SECRET_REMOVAL_TOKEN\n").unwrap();
    std::fs::set_permissions(&rm_tok, std::fs::Permissions::from_mode(0o600)).unwrap();
    let inst_partial = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
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
            "--token-file",
            rm_tok.to_str().unwrap(),
            "--skip-packages",
            "--no-start",
        ],
        &env3,
        Some(&bin3),
    );
    assert!(
        !inst_partial.status.success(),
        "install MUST reject partial-uninstall state: {}",
        text(&inst_partial)
    );

    // Also verify a symlinked replacement _work under released INSTALL_DIR does NOT break
    // domain-only cleanup when the generated hook runs during uninstall.
    let sym_probe_target = case3.join("sym-work-target");
    std::fs::create_dir_all(&sym_probe_target).unwrap();
    std::fs::write(sym_probe_target.join("untouched.txt"), b"keep").unwrap();
    let sym_hook_out = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin3.display()))
        .arg(format!("FAKE_VIRSH_RT_LOG={}", virsh_rt_log3.display()))
        .arg(format!("FAKE_VIRSH_FAIL={}", virsh_fail_flag3.display()))
        .arg(format!(
            "QEMINGA_RUNNER_POLICY={}",
            cfg3.join("policy.env").display()
        ))
        .arg(hooks3.join("hook-job-completed.sh"))
        .arg("--domains-only")
        .output()
        .unwrap();
    assert!(
        !sym_hook_out.status.success(),
        "with virsh failing, --domains-only should still fail on virsh error (not unknown arg)"
    );
    assert!(
        !text(&sym_hook_out).contains("unexpected argument"),
        "generated hook must accept --domains-only: {}",
        text(&sym_hook_out)
    );

    // Now libvirt domain cleanup succeeds and the operator runs the documented retry WITH --token-file.
    std::fs::remove_file(&virsh_fail_flag3).unwrap();
    let _ = std::fs::remove_file(&sc_log3);
    let _ = std::fs::remove_file(&chown_log3);
    let _ = std::fs::remove_file(&virsh_rt_log3);
    let retry_uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg3.to_str().unwrap(),
            "--token-file",
            rm_tok.to_str().unwrap(),
            "--purge-user",
        ],
        &env3,
        Some(&bin3),
    );
    assert!(
        retry_uninst.status.success(),
        "partial-uninstall retry must succeed once domain cleanup succeeds: {}",
        text(&retry_uninst)
    );
    assert_eq!(
        std::fs::read_to_string(&unit3).unwrap(),
        repl_unit_body,
        "retry MUST preserve independently created replacement systemd unit"
    );
    let retry_sc = std::fs::read_to_string(&sc_log3).unwrap_or_default();
    assert!(
        !retry_sc.contains("stop qeminga-test-preserve.service")
            && !retry_sc.contains("disable qeminga-test-preserve.service"),
        "retry MUST NOT stop or disable replacement unit with OWNED_UNIT=0: {retry_sc}"
    );
    assert!(
        inst3.join("replacement.txt").exists(),
        "retry MUST preserve independently created replacement runner directory"
    );
    assert!(
        inst3.join("_work/keep-replacement-work.txt").exists(),
        "retry with real generated hook MUST NOT scrub replacement JIT workspace under released INSTALL_DIR"
    );
    let retry_rt_log = std::fs::read_to_string(&virsh_rt_log3).unwrap_or_default();
    assert!(
        !retry_rt_log.is_empty()
            && !retry_rt_log.contains(repl_rt_dir.to_str().unwrap())
            && retry_rt_log.contains("qeminga-uninstall."),
        "retry with OWNED_UNIT=0 MUST use a private temporary runtime dir instead of replacement /run/$SERVICE: {retry_rt_log}"
    );
    assert!(
        !repl_cfg_log.exists(),
        "retry with --token-file MUST NEVER hand the removal token to a replacement directory's config.sh"
    );
    let retry_chown = std::fs::read_to_string(&chown_log3).unwrap_or_default();
    assert!(
        !retry_chown.contains(inst3.to_str().unwrap()),
        "retry MUST NOT chown a replacement runner directory with OWNED_INSTALL_DIR=0: {retry_chown}"
    );
    assert!(
        !state3.exists() && !hooks3.exists() && !cfg3.exists() && !user_flag3.exists(),
        "owned state dir, hook dir, config dir, and managed user must be cleaned up on retry"
    );

    // Also verify end-to-end partial-uninstall retry when the replacement $INSTALL_DIR/_work
    // is a symlink: the generated hook MUST skip WORK_DIR validation and still clean the VM disk!
    let case3b = dir.path().join("preserve-images-sym-work");
    let inst3b = case3b.join("runner");
    let state3b = case3b.join("state");
    let hooks3b = case3b.join("hooks");
    let cfg3b = case3b.join("cfg");
    let vm_disk3b = state3b.join("images/qeminga-e2e-56-1-x86_64/root.qcow2");
    std::fs::create_dir_all(vm_disk3b.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&inst3b).unwrap();
    std::fs::create_dir_all(&hooks3b).unwrap();
    std::fs::create_dir_all(&cfg3b).unwrap();
    std::fs::write(&vm_disk3b, b"stray-vm-disk").unwrap();
    std::fs::write(&user_flag3, b"").unwrap();
    let render3b = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks3b.to_str().unwrap(),
    ]);
    assert!(render3b.status.success(), "{}", text(&render3b));
    let state3b_vol = live_volume_id(&state3b);
    let inst3b_vol = live_volume_id(&inst3b);
    let hooks3b_vol = live_volume_id(&hooks3b);
    std::fs::write(
        cfg3b.join("policy.env"),
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/_work\nIMAGES_DIR={}/images\nSTATE_VOL={state3b_vol}\nINSTALL_VOL={inst3b_vol}\nLIBVIRT_CONNECT=qemu:///session\n",
            inst3b.display(),
            state3b.display(),
            inst3b.display(),
            state3b.display(),
        ),
    )
    .unwrap();
    std::fs::write(
        cfg3b.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=partial-uninstall\nSERVICE=qeminga-test-preserve\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test\nLABELS=qeminga-kvm\nEPHEMERAL=1\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/_work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_INSTALL_DIR=0\nOWNED_UNIT=0\nVOL_HOOK_DIR={hooks3b_vol}\nVOL_STATE_DIR={state3b_vol}\n",
            inst3b.display(),
            state3b.display(),
            hooks3b.display(),
            cfg3b.display(),
            inst3b.display(),
        ),
    )
    .unwrap();
    std::os::unix::fs::symlink(&sym_probe_target, inst3b.join("_work")).unwrap();
    let retry_sym = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg3b.to_str().unwrap(),
            "--purge-user",
        ],
        &env3,
        Some(&bin3),
    );
    assert!(
        retry_sym.status.success(),
        "partial-uninstall retry must succeed even when replacement INSTALL_DIR/_work is a symlink: {}",
        text(&retry_sym)
    );
    assert!(
        sym_probe_target.join("untouched.txt").exists(),
        "symlink target of replacement _work MUST remain untouched"
    );
    assert!(
        !state3b.exists() && !hooks3b.exists() && !cfg3b.exists(),
        "owned state/hooks/cfg must be cleaned up despite symlink in released replacement path"
    );
}

#[test]
fn ensure_service_user_refuses_unrelated_account_and_extra_groups() {
    let dir = private_tempdir();
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
    let dir = private_tempdir();
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
    write_mock_systemctl(
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
            r#"source "$1"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_USER="qeminga-runner"; MANAGED_USER_UID=995; MANAGED_USER_GID=995; OPT_SERVICE="qeminga-kvm-runner"; OPT_ALLOW_AUTO_UPDATE=0; OPT_EPHEMERAL=0; register_runner_with_rollback 1 "TOK" --unattended"#,
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
        ch.contains("-h root:root"),
        "rollback must restore locked runner permissions: {ch}"
    );
}

#[test]
fn jit_workspace_validation_and_post_job_cleanup() {
    let dir = private_tempdir();
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
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let service_rt = rt_root.join("qeminga-test-rt");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [
        &bin,
        &units,
        &rt_root,
        &service_rt,
        &inst,
        &state,
        &hooks,
        &cfg,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let unit_dir = units.to_str().unwrap();

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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "is-active" ]; then
    if [ "${FAKE_KEEP_SERVICE_RT:-0}" = "1" ]; then
        echo inactive; exit 3
    elif [ -d "${FAKE_SERVICE_RT:-}" ]; then
        echo active; exit 0
    else
        echo inactive; exit 3
    fi
fi
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
    // Fake virsh validates the XDG/DBus/libvirt environment supplied by cmd_uninstall's
    // built-in domain-only cleanup hook and simulates session libvirt daemon autospawn.
    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
set -eu
case "${FAKE_VIRSH_CASE:-1}" in
    1)
        if [ ! -f "${FAKE_RT_SEEN_LOG:?}" ]; then
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
            sleep 30 </dev/null >/dev/null 2>&1 &
            pid1=$!
            sleep 30 </dev/null >/dev/null 2>&1 &
            pid2=$!
            printf '%s\n' "$pid1" > "$XDG_RUNTIME_DIR/libvirt/libvirtd.pid"
            printf '%s\n' "$pid2" > "$XDG_RUNTIME_DIR/libvirt/virtlogd.pid"
            printf '%s\n%s\n' "$pid1" "$pid2" > "${FAKE_DAEMON_PIDS_LOG:?}"
        fi
        exit 0
        ;;
    2)
        if [ ! -f "${FAKE_RT_SEEN_LOG:?}" ]; then
            mkdir -p "$XDG_RUNTIME_DIR/libvirt"
            printf '%s\n' "$XDG_RUNTIME_DIR" > "${FAKE_RT_SEEN_LOG:?}"
            sleep 30 </dev/null >/dev/null 2>&1 &
            pid=$!
            printf '%s\n' "$pid" > "$XDG_RUNTIME_DIR/libvirt/virtqemud.pid"
            printf '%s\n' "$pid" > "${FAKE_DAEMON_PIDS_LOG:?}"
        fi
        exit 0
        ;;
    3)
        if [ ! -f "${FAKE_RT_SEEN_LOG:?}" ]; then
            mode="$(/usr/bin/stat -c '%a' "$XDG_RUNTIME_DIR")"
            [ "$mode" = "700" ] || { echo "expected mode 700, got $mode" >&2; exit 1; }
            printf '%s\n' "$XDG_RUNTIME_DIR" > "${FAKE_RT_SEEN_LOG:?}"
        fi
        exit 0
        ;;
    4)
        if [ ! -f "${FAKE_RT_SEEN_LOG:?}" ]; then
            mkdir -p "$XDG_RUNTIME_DIR/libvirt"
            printf '%s\n' "$XDG_RUNTIME_DIR" > "${FAKE_RT_SEEN_LOG:?}"
            sleep 30 </dev/null >/dev/null 2>&1 &
            pid=$!
            printf '%s\n' "$pid" > "$XDG_RUNTIME_DIR/libvirt/libvirtd.pid"
            printf '%s\n' "$pid" > "${FAKE_DAEMON_PIDS_LOG:?}"
        fi
        echo "error: failed to connect to the hypervisor" >&2
        exit 1
        ;;
esac
"#,
    );

    let write_install_env = |cfg_dir: &Path,
                             service: &str,
                             inst_dir: &Path,
                             state_dir: &Path,
                             hook_dir: &Path| {
        let unit_file = units.join(format!("{service}.service"));
        std::fs::write(&unit_file, "[Unit]\n").unwrap();
        let state_vol = live_volume_id(state_dir);
        let inst_vol = live_volume_id(inst_dir);
        let hook_vol = live_volume_id(hook_dir);
        let unit_vol = live_volume_id(&unit_file);
        std::fs::write(
            cfg_dir.join("policy.env"),
            format!(
                "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nSTATE_VOL={state_vol}\nINSTALL_VOL={inst_vol}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            cfg_dir.join("install.env"),
            format!(
                "RECORD_SCHEMA=1\nSERVICE={service}\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=test\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nVOL_UNIT={unit_vol}\nVOL_INSTALL_DIR={inst_vol}\nVOL_HOOK_DIR={hook_vol}\nVOL_STATE_DIR={state_vol}\n",
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
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("FAKE_VIRSH_CASE", "1"),
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
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("FAKE_VIRSH_CASE", "2"),
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
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("FAKE_VIRSH_CASE", "3"),
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
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("FAKE_VIRSH_CASE", "4"),
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
    let dir = private_tempdir();

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
    let dir = private_tempdir();
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
    let dir = private_tempdir();
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
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:755"; exit 0; fi
exec /usr/bin/stat "$@"
"#,
    );

    let rt_root = dir.path().join("run");
    let inst = dir.path().join("runner");
    let other_inst = dir.path().join("other-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [
        rt_root.clone(),
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
    let rt_env = [("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap())];

    // 1. update WITHOUT install.env must fail closed before modifying anything.
    let no_rec = run_setup_env(
        &[
            "update",
            "--install-dir",
            inst.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
        ],
        &rt_env,
        Some(&bin),
    );
    assert!(
        !no_rec.status.success() && text(&no_rec).contains("missing installation record"),
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
        &rt_env,
        Some(&bin),
    );
    assert!(
        !bad_dir.status.success() && text(&bad_dir).contains("does not match installation record"),
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
        &rt_env,
        Some(&bin),
    );
    assert!(
        !bad_svc.status.success() && text(&bad_svc).contains("does not match installation record"),
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
        &rt_env,
        Some(&bin),
    );
    assert!(
        !on_user_only.status.success() && text(&on_user_only).contains("user-only"),
        "update on user-only record must be refused: {}",
        text(&on_user_only)
    );
}

#[test]
fn fresh_install_refuses_existing_systemd_unit_without_install_record() {
    let dir = private_tempdir();
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
    rc="${FAKE_IS_ACTIVE_RC:-3}"
    if [ "$rc" -eq 0 ]; then echo active; else echo inactive; fi
    exit "$rc"
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
    let dir = private_tempdir();
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
    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
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
    write_exec(&bin.join("useradd"), FAKE_USERADD_GECOS);
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), FAKE_GETENT_GECOS);
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
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
    let dir = private_tempdir();
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
    write_mock_systemctl(
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

    for (case_name, mock_u, mock_g) in [
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
                ("FAKE_LIVE_UID", mock_u),
                ("FAKE_LIVE_GID", mock_g),
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
            "uninstall with {case_name} MUST fail closed: {}",
            text(&out)
        );
        assert!(
            !runuser_log.exists(),
            "{case_name}: uninstall must NEVER invoke runuser before verifying UID/GID"
        );
        assert!(
            !chown_log.exists(),
            "{case_name}: uninstall must NEVER chown runner credentials before verifying UID/GID"
        );
        assert!(
            !systemctl_log.exists(),
            "{case_name}: uninstall must NEVER stop/disable service before verifying UID/GID"
        );
        assert!(
            cfg.join("install.env").exists()
                && inst.join(".credentials").exists()
                && unit_file.exists(),
            "{case_name}: mismatch must leave install.env, credentials, and unit intact for recovery"
        );
    }
}

#[test]
fn install_fails_without_marking_installed_when_service_start_rejects_firewall() {
    let dir = private_tempdir();
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
    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
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

    let rt_root = dir.path().join("run");
    std::fs::create_dir_all(&rt_root).unwrap();
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
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
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
    let dir = private_tempdir();
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
    write_exec(&bin.join("useradd"), FAKE_USERADD_GECOS);
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), FAKE_GETENT_GECOS);
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
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
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let fake_tar_src = dir.path().join("tar-src");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();
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
        "flock",
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
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
        .env("QEMINGA_RUNTIME_ROOT", &rt_root)
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
        .env("QEMINGA_RUNTIME_ROOT", &rt_root)
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

#[test]
fn fresh_install_refuses_config_or_state_dir_created_after_preflight_without_mutating_it() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();

    let user_flag = dir.path().join("user_exists");
    let chown_log = dir.path().join("chown.log");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let tok_file = dir.path().join("token");
    std::fs::write(&tok_file, "FAKE_REG_TOKEN\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Fake apt-get simulates another provisioning process creating $RACE_CREATE_DIR
    // with restrictive permissions and foreign contents AFTER preflight has already passed.
    write_exec(
        &bin.join("apt-get"),
        r#"#!/bin/sh
if [ "$1" = "install" ] && [ -n "${RACE_CREATE_DIR:-}" ]; then
    mkdir -m "${RACE_CREATE_MODE:-0700}" -p "$RACE_CREATE_DIR"
    printf 'foreign-owner-data\n' > "$RACE_CREATE_DIR/foreign-service.conf"
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
    write_exec(&bin.join("useradd"), FAKE_USERADD_GECOS);
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), FAKE_GETENT_GECOS);
    write_exec(
        &bin.join("chown"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_CHOWN_LOG:?}"
exit 0
"#,
    );
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
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

    let unit_dir = etc_units.to_str().unwrap();

    // 1. Another process creates --config-dir after preflight (during install_packages):
    //    install MUST fail atomically on EEXIST without changing group/mode or writing install.env.
    let cfg1 = dir.path().join("race-cfg");
    let state1 = dir.path().join("race-state-1");
    let inst1 = dir.path().join("race-runner-1");
    let hooks1 = dir.path().join("race-hooks-1");
    let cfg_race = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--service",
            "qeminga-race-cfg",
            "--install-dir",
            inst1.to_str().unwrap(),
            "--state-dir",
            state1.to_str().unwrap(),
            "--hook-dir",
            hooks1.to_str().unwrap(),
            "--config-dir",
            cfg1.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("RACE_CREATE_DIR", cfg1.to_str().unwrap()),
            ("RACE_CREATE_MODE", "0700"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !cfg_race.status.success(),
        "install MUST fail closed if --config-dir appears after preflight: {}",
        text(&cfg_race)
    );
    assert!(
        cfg1.join("foreign-service.conf").exists(),
        "foreign file in raced --config-dir must remain intact"
    );
    assert!(
        !cfg1.join("install.env").exists(),
        "install MUST NEVER write install.env into a pre-existing raced --config-dir"
    );
    let cfg1_mode = std::fs::metadata(&cfg1).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        cfg1_mode, 0o700,
        "install MUST NEVER alter mode of a raced --config-dir (got {cfg1_mode:#o})"
    );
    let chowns1 = std::fs::read_to_string(&chown_log).unwrap_or_default();
    assert!(
        !chowns1.contains(cfg1.to_str().unwrap()),
        "install MUST NEVER chown a raced --config-dir: {chowns1}"
    );
    assert!(
        !user_flag.exists(),
        "failed fresh --config-dir claim MUST NOT leave an orphaned unrecorded service user behind"
    );

    // 2. Another process creates --state-dir after preflight (during install_packages):
    //    install MUST fail atomically on EEXIST, leave the foreign state dir untouched,
    //    and record OWNED_STATE_DIR=0 so uninstall cleans up only our config dir & user.
    //    (Note: user_flag is NOT cleared manually — case 1 must have left no orphaned user!)
    let _ = std::fs::remove_file(&chown_log);
    let cfg2 = dir.path().join("race-cfg-2");
    let state2 = dir.path().join("race-state-2");
    let inst2 = dir.path().join("race-runner-2");
    let hooks2 = dir.path().join("race-hooks-2");
    let state_race = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--service",
            "qeminga-race-state",
            "--install-dir",
            inst2.to_str().unwrap(),
            "--state-dir",
            state2.to_str().unwrap(),
            "--hook-dir",
            hooks2.to_str().unwrap(),
            "--config-dir",
            cfg2.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("RACE_CREATE_DIR", state2.to_str().unwrap()),
            ("RACE_CREATE_MODE", "0755"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !state_race.status.success(),
        "install MUST fail closed if --state-dir appears after preflight: {}",
        text(&state_race)
    );
    assert!(
        state2.join("foreign-service.conf").exists(),
        "foreign file in raced --state-dir must remain intact"
    );
    let state2_mode = std::fs::metadata(&state2).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        state2_mode, 0o755,
        "install MUST NEVER alter mode of a raced --state-dir (got {state2_mode:#o})"
    );
    let chowns2 = std::fs::read_to_string(&chown_log).unwrap_or_default();
    assert!(
        !chowns2.contains(state2.to_str().unwrap()),
        "install MUST NEVER chown a raced --state-dir: {chowns2}"
    );
    let rec2 = std::fs::read_to_string(cfg2.join("install.env")).unwrap();
    assert!(
        rec2.contains("OWNED_CONFIG_DIR=1\n") && rec2.contains("OWNED_STATE_DIR=0\n"),
        "install record must mark raced state dir unowned:\n{rec2}"
    );
    let cleanup2 = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg2.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        cleanup2.status.success(),
        "uninstall after raced state dir should clean up owned resources: {}",
        text(&cleanup2)
    );
    assert!(
        state2.join("foreign-service.conf").exists() && !cfg2.exists() && !user_flag.exists(),
        "uninstall must keep raced foreign state dir while removing owned config dir and user"
    );
}

#[test]
fn state_subdir_init_failure_persists_owned_state_dir_for_retry_and_uninstall() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let fake_tar_src = dir.path().join("tar-src");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("bin")).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("externals")).unwrap();

    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("config.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let good_tarball = dir.path().join("runner-state-init.tar.gz");
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
    let fail_runuser_flag = dir.path().join("fail_runuser");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
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
    write_exec(&bin.join("useradd"), FAKE_USERADD_GECOS);
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), FAKE_GETENT_GECOS);
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
if [ -f "${FAKE_FAIL_RUNUSER:?}" ]; then
    echo "runuser: simulated PAM session / disk quota failure" >&2
    exit 1
fi
while [ $# -gt 0 ]; do
    case "$1" in
        --) shift; break ;;
        *) shift ;;
    esac
done
exec "$@"
"#,
    );
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
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

    let unit_dir = etc_units.to_str().unwrap();
    let common_env = [
        ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
        ("FAKE_FAIL_RUNUSER", fail_runuser_flag.to_str().unwrap()),
        ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
        ("QEMINGA_KVM_DEVICE", "/dev/null"),
        ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
        ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
        ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
        ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
        ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
    ];

    // Path A: runuser fails while initializing state subdirs -> OWNED_STATE_DIR=1 is already
    // persisted, so ordinary retry succeeds once runuser works again.
    let cfg_a = dir.path().join("cfg-a");
    let state_a = dir.path().join("state-a");
    let inst_a = dir.path().join("runner-a");
    let hooks_a = dir.path().join("hooks-a");
    std::fs::write(&fail_runuser_flag, b"1").unwrap();
    let fail_a = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "state-init-box-a",
            "--service",
            "qeminga-state-init-a",
            "--install-dir",
            inst_a.to_str().unwrap(),
            "--state-dir",
            state_a.to_str().unwrap(),
            "--hook-dir",
            hooks_a.to_str().unwrap(),
            "--config-dir",
            cfg_a.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(
        !fail_a.status.success(),
        "first install should fail when runuser cannot create state subdirs: {}",
        text(&fail_a)
    );
    assert!(
        state_a.is_dir(),
        "top-level state dir was created before child initialization failed"
    );
    let rec_a = std::fs::read_to_string(cfg_a.join("install.env")).unwrap();
    for expected in [
        "RECORD_STATE=installing\n",
        "OWNED_CONFIG_DIR=1\n",
        "OWNED_STATE_DIR=1\n",
        "OWNED_INSTALL_DIR=0\n",
        "OWNED_HOOK_DIR=0\n",
        "OWNED_UNIT=0\n",
    ] {
        assert!(
            rec_a.contains(expected),
            "OWNED_STATE_DIR=1 must be persisted BEFORE runuser child init ({expected:?}):\n{rec_a}"
        );
    }

    // Clear runuser failure and verify ordinary install retry succeeds cleanly!
    std::fs::remove_file(&fail_runuser_flag).unwrap();
    let retry_a = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "state-init-box-a",
            "--service",
            "qeminga-state-init-a",
            "--install-dir",
            inst_a.to_str().unwrap(),
            "--state-dir",
            state_a.to_str().unwrap(),
            "--hook-dir",
            hooks_a.to_str().unwrap(),
            "--config-dir",
            cfg_a.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(
        retry_a.status.success(),
        "ordinary retry after state-subdir init failure must succeed: {}",
        text(&retry_a)
    );
    for sub in [
        "work",
        "images",
        "image-cache",
        ".config",
        ".cache",
        ".local/share",
    ] {
        assert!(
            state_a.join(sub).is_dir(),
            "retry must initialize state subdir {sub}"
        );
    }
    let rec_a_done = std::fs::read_to_string(cfg_a.join("install.env")).unwrap();
    assert!(
        rec_a_done.contains("RECORD_STATE=installed\n"),
        "retry must finalize RECORD_STATE=installed:\n{rec_a_done}"
    );

    // Path B: runuser fails while initializing state subdirs -> uninstall --purge-user
    // cleans up the created state root, managed user, and config dir cleanly!
    let _ = std::fs::remove_file(&user_flag);
    std::fs::write(&fail_runuser_flag, b"1").unwrap();
    let cfg_b = dir.path().join("cfg-b");
    let state_b = dir.path().join("state-b");
    let inst_b = dir.path().join("runner-b");
    let hooks_b = dir.path().join("hooks-b");
    let fail_b = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "state-init-box-b",
            "--service",
            "qeminga-state-init-b",
            "--install-dir",
            inst_b.to_str().unwrap(),
            "--state-dir",
            state_b.to_str().unwrap(),
            "--hook-dir",
            hooks_b.to_str().unwrap(),
            "--config-dir",
            cfg_b.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(!fail_b.status.success(), "{}", text(&fail_b));
    assert!(state_b.is_dir(), "state root created before runuser failed");

    std::fs::remove_file(&fail_runuser_flag).unwrap();
    let uninst_b = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg_b.to_str().unwrap(),
            "--purge-user",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(
        uninst_b.status.success(),
        "uninstall after state-subdir init failure must succeed: {}",
        text(&uninst_b)
    );
    assert!(
        !state_b.exists() && !cfg_b.exists() && !user_flag.exists(),
        "uninstall must clean up the created state root, config dir, and managed user"
    );
}

#[test]
fn uninstall_persists_release_before_removing_resources_or_reloading_systemd() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();

    let user_flag = dir.path().join("user_exists");
    let mktemp_count = dir.path().join("mktemp.count");
    let daemon_reload_snapshot = dir.path().join("daemon-reload-install.env");
    let cfg = dir.path().join("cfg");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::create_dir_all(&inst).unwrap();
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(&user_flag, b"").unwrap();

    let unit_file = units.join("qeminga-wal-test.service");
    std::fs::write(&unit_file, "[Unit]\nDescription=wal test runner\n").unwrap();
    std::fs::write(inst.join("runner-bin.txt"), b"owned-runner").unwrap();
    let unit_vol = live_volume_id(&unit_file);
    let inst_vol = live_volume_id(&inst);
    let hook_vol = live_volume_id(&hooks);
    let state_vol = live_volume_id(&state);
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-wal-test\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=wal-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\nVOL_UNIT={unit_vol}\nVOL_INSTALL_DIR={inst_vol}\nVOL_HOOK_DIR={hook_vol}\nVOL_STATE_DIR={state_vol}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
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
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
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
    // Fake systemctl captures a snapshot of install.env at the exact moment daemon-reload runs.
    write_mock_systemctl(
        &bin.join("systemctl"),
        &format!(
            r#"#!/bin/sh
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
if [ "$1" = "daemon-reload" ] && [ -f "{}" ]; then
    cp "{}" "${{FAKE_RELOAD_SNAP:?}}"
fi
exit 0
"#,
            cfg.join("install.env").display(),
            cfg.join("install.env").display(),
        ),
    );
    // Fake mktemp counts .install.env.* staging writes and simulates ENOSPC on the Nth write.
    write_exec(
        &bin.join("mktemp"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in
        *.install.env.*)
            n=0
            [ -f "${FAKE_MKTEMP_COUNT:?}" ] && n="$(cat "${FAKE_MKTEMP_COUNT:?}")"
            n=$((n + 1))
            printf '%s\n' "$n" > "${FAKE_MKTEMP_COUNT:?}"
            if [ -n "${FAIL_ON_RECORD_WRITE_N:-}" ] && [ "$n" -eq "$FAIL_ON_RECORD_WRITE_N" ]; then
                echo "mktemp: simulated ENOSPC on config filesystem" >&2
                exit 1
            fi
            ;;
    esac
done
exec /usr/bin/mktemp "$@"
"#,
    );

    let unit_dir = units.to_str().unwrap();

    // 1. If persisting STAGED_UNIT fails (ENOSPC on record write #1, before mv -T), unit_file
    //    and inst MUST remain untouched and daemon-reload MUST NOT run!
    let fail_unit_write = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_MKTEMP_COUNT", mktemp_count.to_str().unwrap()),
            ("FAKE_RELOAD_SNAP", daemon_reload_snapshot.to_str().unwrap()),
            ("FAIL_ON_RECORD_WRITE_N", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !fail_unit_write.status.success(),
        "uninstall must fail when persisting unit staging fails: {}",
        text(&fail_unit_write)
    );
    assert!(
        unit_file.exists(),
        "unit_file MUST NOT be moved or unlinked when persisting STAGED_UNIT fails"
    );
    assert!(
        inst.join("runner-bin.txt").exists(),
        "runner dir MUST NOT be deleted before unit release succeeds"
    );
    assert!(
        !daemon_reload_snapshot.exists(),
        "systemctl daemon-reload MUST NOT run before OWNED_UNIT=0 is persisted"
    );

    // 2. Allow writes #1..#3 (unit stage, OWNED_UNIT=0 before daemon-reload, clear STAGED_UNIT)
    //    to succeed, and fail write #4 (STAGED_INSTALL_DIR before moving runner dir):
    //    - daemon-reload MUST observe RECORD_STATE=partial-uninstall and OWNED_UNIT=0 already saved;
    //    - unit_file is removed;
    //    - inst MUST remain intact on disk because staging write #4 failed!
    let _ = std::fs::remove_file(&mktemp_count);
    let _ = std::fs::remove_file(&daemon_reload_snapshot);
    let fail_inst_write = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_MKTEMP_COUNT", mktemp_count.to_str().unwrap()),
            ("FAKE_RELOAD_SNAP", daemon_reload_snapshot.to_str().unwrap()),
            ("FAIL_ON_RECORD_WRITE_N", "4"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !fail_inst_write.status.success(),
        "uninstall must fail when persisting install-dir staging fails: {}",
        text(&fail_inst_write)
    );
    let snap = std::fs::read_to_string(&daemon_reload_snapshot)
        .expect("daemon-reload should run after unit release record write");
    assert!(
        snap.contains("RECORD_STATE=partial-uninstall\n") && snap.contains("OWNED_UNIT=0\n"),
        "systemctl daemon-reload MUST run AFTER OWNED_UNIT=0 is persisted:\n{snap}"
    );
    assert!(
        !unit_file.exists(),
        "unit_file should be removed after OWNED_UNIT=0 was persisted"
    );
    assert!(
        inst.join("runner-bin.txt").exists(),
        "runner dir MUST NOT be removed when persisting STAGED_INSTALL_DIR fails"
    );
    let mid_rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        mid_rec.contains("OWNED_UNIT=0\n") && mid_rec.contains("OWNED_INSTALL_DIR=1\n"),
        "record must stay synchronized with disk after failed runner-dir staging write:\n{mid_rec}"
    );

    // 3. Another service claims the released unit name, ENOSPC clears, and retry finishes cleanly
    //    without touching the replacement unit!
    let repl_unit = "[Unit]\nDescription=replacement service after unit release\n";
    std::fs::write(&unit_file, repl_unit).unwrap();
    let _ = std::fs::remove_file(&mktemp_count);
    let ok_retry = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_MKTEMP_COUNT", mktemp_count.to_str().unwrap()),
            ("FAKE_RELOAD_SNAP", daemon_reload_snapshot.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        ok_retry.status.success(),
        "retry once config filesystem recovers must finish uninstall: {}",
        text(&ok_retry)
    );
    assert_eq!(
        std::fs::read_to_string(&unit_file).unwrap(),
        repl_unit,
        "retry must preserve independently created replacement unit"
    );
    assert!(
        !inst.exists()
            && !hooks.exists()
            && !state.exists()
            && !cfg.exists()
            && !user_flag.exists(),
        "retry must remove still-owned runner dir, hooks, state, config, and user"
    );
}

#[test]
fn fresh_install_refuses_systemd_mask_symlink_and_rolls_back_bootstrap_on_record_failure() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let fake_tar_src = dir.path().join("tar-src");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("bin")).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("externals")).unwrap();

    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("config.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let good_tarball = dir.path().join("runner-mask-test.tar.gz");
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
    let chmod_log = dir.path().join("chmod.log");
    let chown_log = dir.path().join("chown.log");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
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
        r#"#!/bin/sh
comment=""
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--comment) comment="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '%s\n' "$comment" > "${FAKE_USER_FLAG:?}"
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        r#"#!/bin/sh
if [ "${FAIL_USERDEL:-0}" = "1" ]; then
    echo "userdel: simulated ENOSPC updating /etc/passwd" >&2
    exit 1
fi
rm -f "${FAKE_USER_FLAG:?}"
exit 0
"#,
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("getent"),
        r#"#!/bin/sh
if [ "$1" = "passwd" ] && [ -f "${FAKE_USER_FLAG:?}" ]; then
    comment="$(cat "${FAKE_USER_FLAG:?}")"
    printf '%s:x:995:995:%s:/var/lib/qeminga-runner:/usr/sbin/nologin\n' "$2" "$comment"
    exit 0
fi
exit 0
"#,
    );
    write_exec(
        &bin.join("chown"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_CHOWN_LOG:?}"
exit 0
"#,
    );
    write_exec(
        &bin.join("chmod"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_CHMOD_LOG:?}"
exec /usr/bin/chmod "$@"
"#,
    );
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
    // When check_unit_not_occupied runs right before publishing the unit (detected by
    // $RACE_MASK_TRIGGER existing on disk), fake systemctl plants either a systemd mask
    // symlink ($RACE_MASK_UNIT -> /dev/null) or a directory ($RACE_DIR_UNIT)!
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "list-unit-files" ]; then
    if [ -n "${RACE_MASK_UNIT:-}" ] && [ -n "${RACE_MASK_TRIGGER:-}" ] && [ -e "$RACE_MASK_TRIGGER" ] && [ ! -L "$RACE_MASK_UNIT" ]; then
        ln -s /dev/null "$RACE_MASK_UNIT"
    fi
    if [ -n "${RACE_DIR_UNIT:-}" ] && [ -n "${RACE_MASK_TRIGGER:-}" ] && [ -e "$RACE_MASK_TRIGGER" ] && [ ! -d "$RACE_DIR_UNIT" ]; then
        mkdir -p "$RACE_DIR_UNIT"
    fi
    exit 0
fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
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
    write_exec(
        &bin.join("mktemp"),
        r#"#!/bin/sh
if [ -n "${FAIL_RECORD_MKTEMP_AFTER_USER:-}" ] && [ -f "${FAKE_USER_FLAG:?}" ]; then
    for a in "$@"; do
        case "$a" in
            *.install.env.*)
                echo "mktemp: simulated ENOSPC during post-useradd record write" >&2
                exit 1
                ;;
        esac
    done
fi
exec /usr/bin/mktemp "$@"
"#,
    );

    let unit_dir = etc_units.to_str().unwrap();

    // 1. Fresh unit publication MUST reject a systemd mask symlink (-> /dev/null) appearing
    //    after check_unit_not_occupied, without following it, chmod'ing /dev/null, leaking
    //    temp files, or setting OWNED_UNIT=1.
    let cfg1 = dir.path().join("mask-cfg");
    let state1 = dir.path().join("mask-state");
    let inst1 = dir.path().join("mask-runner");
    let hooks1 = dir.path().join("mask-hooks");
    let mask_unit = etc_units.join("qeminga-mask-race.service");
    let mask_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "mask-box",
            "--service",
            "qeminga-mask-race",
            "--install-dir",
            inst1.to_str().unwrap(),
            "--state-dir",
            state1.to_str().unwrap(),
            "--hook-dir",
            hooks1.to_str().unwrap(),
            "--config-dir",
            cfg1.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHMOD_LOG", chmod_log.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("RACE_MASK_UNIT", mask_unit.to_str().unwrap()),
            (
                "RACE_MASK_TRIGGER",
                inst1.join("bin/runsvc.sh").to_str().unwrap(),
            ),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !mask_out.status.success(),
        "fresh install MUST fail closed when a systemd mask symlink appears before publication: {}",
        text(&mask_out)
    );
    assert_eq!(
        std::fs::read_link(&mask_unit).unwrap(),
        std::path::Path::new("/dev/null"),
        "systemd mask symlink to /dev/null MUST remain untouched"
    );
    let chmods = std::fs::read_to_string(&chmod_log).unwrap_or_default();
    assert!(
        !chmods.contains(mask_unit.to_str().unwrap()),
        "install MUST NEVER run chmod on a raced systemd mask symlink (would chmod /dev/null!): {chmods}"
    );
    let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
    assert!(
        !chowns.contains(mask_unit.to_str().unwrap()),
        "install MUST NEVER run chown on a raced systemd mask symlink: {chowns}"
    );
    let mask_rec = std::fs::read_to_string(cfg1.join("install.env")).unwrap();
    assert!(
        mask_rec.contains("OWNED_UNIT=0\n"),
        "failed fresh unit publication must NOT claim OWNED_UNIT=1:\n{mask_rec}"
    );
    let leftover_temps: Vec<_> = std::fs::read_dir(&etc_units)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
        .collect();
    assert!(
        leftover_temps.is_empty(),
        "failed unit publication must clean up staging temp files: {leftover_temps:?}"
    );

    // 1b. Fresh unit publication MUST also reject a directory appearing at $unit_path
    //     (GNU ln without -T would link into the directory and claim OWNED_UNIT=1!).
    let _ = std::fs::remove_file(&user_flag);
    let cfg_dir_u = dir.path().join("dir-unit-cfg");
    let state_dir_u = dir.path().join("dir-unit-state");
    let inst_dir_u = dir.path().join("dir-unit-runner");
    let hooks_dir_u = dir.path().join("dir-unit-hooks");
    let dir_unit = etc_units.join("qeminga-dir-race.service");
    let dir_unit_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "dir-unit-box",
            "--service",
            "qeminga-dir-race",
            "--install-dir",
            inst_dir_u.to_str().unwrap(),
            "--state-dir",
            state_dir_u.to_str().unwrap(),
            "--hook-dir",
            hooks_dir_u.to_str().unwrap(),
            "--config-dir",
            cfg_dir_u.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHMOD_LOG", chmod_log.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("RACE_DIR_UNIT", dir_unit.to_str().unwrap()),
            (
                "RACE_MASK_TRIGGER",
                inst_dir_u.join("bin/runsvc.sh").to_str().unwrap(),
            ),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !dir_unit_out.status.success(),
        "fresh install MUST fail closed when a directory appears at unit_path (requires ln -T): {}",
        text(&dir_unit_out)
    );
    let inside_dir_unit: Vec<_> = std::fs::read_dir(&dir_unit)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        inside_dir_unit.is_empty(),
        "ln -T must NOT create any file inside a directory at unit_path: {inside_dir_unit:?}"
    );
    let dir_unit_rec = std::fs::read_to_string(cfg_dir_u.join("install.env")).unwrap();
    assert!(
        dir_unit_rec.contains("OWNED_UNIT=0\n"),
        "failed unit publication against directory destination must NOT claim OWNED_UNIT=1:\n{dir_unit_rec}"
    );

    // 2. If the post-useradd install.env write fails on a fresh install and userdel succeeds,
    //    BOTH the newly created user AND the reserved config dir are cleanly rolled back.
    let _ = std::fs::remove_file(&user_flag);
    let cfg2 = dir.path().join("enospc-cfg");
    let state2 = dir.path().join("enospc-state");
    let inst2 = dir.path().join("enospc-runner");
    let hooks2 = dir.path().join("enospc-hooks");
    let enospc_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "enospc-box",
            "--service",
            "qeminga-enospc",
            "--install-dir",
            inst2.to_str().unwrap(),
            "--state-dir",
            state2.to_str().unwrap(),
            "--hook-dir",
            hooks2.to_str().unwrap(),
            "--config-dir",
            cfg2.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHMOD_LOG", chmod_log.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("FAIL_RECORD_MKTEMP_AFTER_USER", "1"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !enospc_out.status.success(),
        "fresh install must fail when post-useradd install.env write fails: {}",
        text(&enospc_out)
    );
    assert!(
        !user_flag.exists(),
        "fresh install MUST roll back newly created service user when userdel succeeds"
    );
    assert!(
        !cfg2.exists(),
        "fresh install MUST roll back reserved config dir when userdel succeeds"
    );

    // 3. If BOTH the post-useradd install.env write AND rollback userdel fail (e.g. full /etc),
    //    the durable pre-useradd user-pending record MUST be preserved, stderr MUST identify
    //    the surviving account, and a later `uninstall --purge-user` MUST recover cleanly!
    let cfg3 = dir.path().join("enospc-keep-cfg");
    let state3 = dir.path().join("enospc-keep-state");
    let inst3 = dir.path().join("enospc-keep-runner");
    let hooks3 = dir.path().join("enospc-keep-hooks");
    let enospc_userdel_fail = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "enospc-keep-box",
            "--service",
            "qeminga-enospc-keep",
            "--install-dir",
            inst3.to_str().unwrap(),
            "--state-dir",
            state3.to_str().unwrap(),
            "--hook-dir",
            hooks3.to_str().unwrap(),
            "--config-dir",
            cfg3.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHMOD_LOG", chmod_log.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("FAIL_RECORD_MKTEMP_AFTER_USER", "1"),
            ("FAIL_USERDEL", "1"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(!enospc_userdel_fail.status.success());
    let fail_text = text(&enospc_userdel_fail);
    assert!(
        user_flag.exists(),
        "simulated failed userdel leaves user on host"
    );
    assert!(
        fail_text.contains("qeminga-runner") && fail_text.contains("install.env"),
        "failed bootstrap rollback MUST identify the surviving account and recovery record: {fail_text}"
    );
    let pending_rec = std::fs::read_to_string(cfg3.join("install.env"))
        .expect("failed userdel rollback MUST preserve durable recovery record at install.env");
    let install_id = pending_rec
        .lines()
        .find_map(|l| l.strip_prefix("INSTALL_ID="))
        .unwrap_or("");
    assert!(
        pending_rec.contains("RECORD_STATE=user-pending\n")
            && pending_rec.contains("USER=qeminga-runner\n")
            && install_id.len() >= 16,
        "preserved bootstrap recovery record must be user-pending with non-empty INSTALL_ID:\n{pending_rec}"
    );
    let recorded_gecos = std::fs::read_to_string(&user_flag).unwrap();
    assert_eq!(
        recorded_gecos.trim(),
        format!("qeminga-runner-{install_id}"),
        "useradd MUST stamp the installation marker into the account GECOS"
    );

    // Once /etc space returns, uninstall --purge-user MUST cleanly purge the surviving account!
    let recover_uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg3.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHMOD_LOG", chmod_log.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        recover_uninst.status.success(),
        "uninstall --purge-user must recover a preserved user-pending record: {}",
        text(&recover_uninst)
    );
    assert!(
        !user_flag.exists() && !cfg3.exists(),
        "recovery uninstall must purge surviving user and remove config dir"
    );
}

#[test]
fn uninstall_retains_account_and_recovers_staged_removal_when_delete_fails() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();

    struct RestoreCreds(PathBuf);
    impl Drop for RestoreCreds {
        fn drop(&mut self) {
            if let Ok(entries) = std::fs::read_dir(&self.0) {
                for ent in entries.flatten() {
                    let p = ent.path();
                    let _ = std::fs::set_permissions(
                        p.join("runner/creds"),
                        std::fs::Permissions::from_mode(0o755),
                    );
                }
            }
            let _ = std::fs::set_permissions(
                self.0.join("runner/creds"),
                std::fs::Permissions::from_mode(0o755),
            );
        }
    }
    let _restore = RestoreCreds(dir.path().to_path_buf());

    let user_flag = dir.path().join("user_exists");
    let cfg = dir.path().join("cfg");
    let inst = dir.path().join("runner");
    let cred_dir = inst.join("creds");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::create_dir_all(&cred_dir).unwrap();
    std::fs::create_dir_all(state.join("images")).unwrap();
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(&user_flag, b"").unwrap();

    let unit_file = units.join("qeminga-staged-rm.service");
    std::fs::write(&unit_file, "[Unit]\nDescription=staged rm runner\n").unwrap();
    std::fs::write(
        cred_dir.join(".credentials_rsaparams"),
        b"PRIVATE-KEY-MATERIAL",
    )
    .unwrap();
    // Make creds subdir read-only (0555) so staging rename(2) succeeds while
    // fs_ops safe-rmtree hits real kernel EACCES trying to unlink private keys.
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let unit_vol = live_volume_id(&unit_file);
    let inst_vol = live_volume_id(&inst);
    let hook_vol = live_volume_id(&hooks);
    let state_vol = live_volume_id(&state);
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-staged-rm\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=staged-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\nVOL_UNIT={unit_vol}\nVOL_INSTALL_DIR={inst_vol}\nVOL_HOOK_DIR={hook_vol}\nVOL_STATE_DIR={state_vol}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(
        &bin.join("systemctl"),
        "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then echo inactive; exit 3; fi\nexit 0\n",
    );
    write_exec(&bin.join("virsh"), FAKE_VIRSH);
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

    let unit_dir = units.to_str().unwrap();
    let virsh_log = dir.path().join("virsh.log");
    let env = [
        ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
        ("FAKE_LOG", virsh_log.to_str().unwrap()),
        ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
        ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
        ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
    ];

    // 1. First uninstall --purge-user fails when safe-rmtree cannot delete the read-only creds subdir.
    //    Service account and install.env MUST be retained!
    let first = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &env,
        Some(&bin),
    );
    assert!(
        !first.status.success(),
        "uninstall must fail when runner directory deletion fails: {}",
        text(&first)
    );
    assert!(
        user_flag.exists() && cfg.join("install.env").exists(),
        "service account and install.env MUST be retained when runner deletion fails"
    );
    let rec_after_fail = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let staged_inst_str = rec_after_fail
        .lines()
        .find_map(|l| l.strip_prefix("STAGED_INSTALL_DIR="))
        .unwrap_or("")
        .to_string();
    assert!(
        !staged_inst_str.is_empty(),
        "failed staged deletion must persist STAGED_INSTALL_DIR:\n{rec_after_fail}"
    );
    let staged_inst = PathBuf::from(&staged_inst_str);

    // 2. An independent replacement claims the public runner directory path (with config.sh!).
    //    Ensure the original directory was moved out of the public path into private staging.
    assert!(
        !inst.exists(),
        "original runner dir should have been moved to a private root-controlled staging dir before release"
    );
    std::fs::create_dir_all(&inst).unwrap();
    std::fs::write(inst.join("replacement.txt"), b"replacement-runner").unwrap();
    let repl_cfg_log = dir.path().join("repl-config-sh.log");
    write_exec(
        &inst.join("config.sh"),
        &format!(
            "#!/bin/sh\nprintf 'INVOKED\\n' > \"{}\"\nexit 0\n",
            repl_cfg_log.display()
        ),
    );
    let rm_tok = dir.path().join("rm-tok");
    std::fs::write(&rm_tok, "SECRET_RM_TOK\n").unwrap();
    std::fs::set_permissions(&rm_tok, std::fs::Permissions::from_mode(0o600)).unwrap();

    // 3. Retry --purge-user WHILE deletion still fails: MUST STILL fail, MUST STILL retain
    //    the account (never purge while .credentials_rsaparams exists on disk!), and MUST NOT
    //    touch the replacement runner dir or hand it the removal token!
    let retry_still_fail = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            rm_tok.to_str().unwrap(),
            "--purge-user",
        ],
        &env,
        Some(&bin),
    );
    assert!(
        !retry_still_fail.status.success(),
        "retry --purge-user MUST still fail while staged runner deletion fails: {}",
        text(&retry_still_fail)
    );
    assert!(
        user_flag.exists() && cfg.join("install.env").exists(),
        "retry MUST retain service account and install.env until staged private key deletion succeeds"
    );
    assert!(
        inst.join("replacement.txt").exists() && !repl_cfg_log.exists(),
        "replacement runner dir and config.sh must remain untouched"
    );

    // 4. Clear the deletion failure -> retry --purge-user deletes the staged runner dir
    //    (including .credentials_rsaparams), purges the user, removes cfg/state/hooks,
    //    AND leaves the replacement runner dir untouched!
    std::fs::set_permissions(
        staged_inst.join("runner/creds"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let retry_ok = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            rm_tok.to_str().unwrap(),
            "--purge-user",
        ],
        &env,
        Some(&bin),
    );
    assert!(
        retry_ok.status.success(),
        "retry once volume is writable must finish staged deletion and purge user: {}",
        text(&retry_ok)
    );
    let leftover_staged: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".qeminga-removing.")
        })
        .collect();
    assert!(
        leftover_staged.is_empty(),
        "staged removal directory containing private credentials must be completely deleted: {leftover_staged:?}"
    );
    assert!(
        inst.join("replacement.txt").exists() && !repl_cfg_log.exists(),
        "replacement runner dir at public path must survive recovery untouched"
    );
    assert!(
        !user_flag.exists() && !cfg.exists() && !state.exists() && !hooks.exists(),
        "managed user, config, state, and hooks must be cleanly removed after staged deletion succeeds"
    );
}

#[test]
fn concurrent_install_invocations_serialize_and_retain_all_ownership_flags() {
    use std::time::{Duration, Instant};

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let etc_units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let fake_tar_src = dir.path().join("tar-src");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc_units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("bin")).unwrap();
    std::fs::create_dir_all(fake_tar_src.join("externals")).unwrap();

    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &fake_tar_src.join("config.sh"),
        &format!(
            r#"#!/bin/sh
dir="$(dirname "$0")"
printf '{{"gitHubUrl":"{REPO_URL}","agentName":"lock-box","workFolder":"%s","disableUpdate":true,"ephemeral":false}}\n' "${{HOME}}/work" > "$dir/.runner"
exit 0
"#
        ),
    );
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let good_tarball = dir.path().join("runner-concurrent.tar.gz");
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
    let download_started = dir.path().join("download_started");
    let release_download = dir.path().join("release_download");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
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
    write_exec(&bin.join("useradd"), FAKE_USERADD_GECOS);
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), FAKE_GETENT_GECOS);
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("virsh"), FAKE_VIRSH);
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
exit 0
"#,
    );
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
    // Install #1 pauses during tarball download until release_download appears.
    // Install #2 pauses during verify_private_repo (if it ran concurrently without a lock!)
    // so Install #1 finishes while Install #2 is still checking prerequisites — reproducing
    // the exact stale-OWNED_* clobbering bug when unserialized!
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in
        *api.github.com/repos/*)
            if [ "${INSTALL_ROLE:-}" = "two" ]; then
                i=0
                while [ ! -f "${RELEASE_DOWNLOAD:?}" ] && [ "$i" -lt 600 ]; do
                    sleep 0.05
                    i=$((i + 1))
                done
                sleep 0.4
            fi
            printf '404'
            exit 0
            ;;
    esac
done
if [ "${INSTALL_ROLE:-}" = "one" ]; then
    : > "${DOWNLOAD_STARTED:?}"
    i=0
    while [ ! -f "${RELEASE_DOWNLOAD:?}" ] && [ "$i" -lt 600 ]; do
        sleep 0.05
        i=$((i + 1))
    done
fi
out=""
while [ $# -gt 0 ]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
cp "${FAKE_GOOD_TARBALL:?}" "$out"
exit 0
"#,
    );

    let real_flock = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v flock"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    assert!(!real_flock.is_empty(), "flock must be available on PATH");
    let lock_waiting_two = dir.path().join("lock_waiting_two");
    let lock_acquired_two = dir.path().join("lock_acquired_two");
    write_exec(
        &bin.join("flock"),
        &format!(
            r#"#!/bin/sh
if [ "${{INSTALL_ROLE:-}}" = "two" ]; then
    : > "${{LOCK_WAITING_TWO:?}}"
    "{real_flock}" "$@"
    rc=$?
    : > "${{LOCK_ACQUIRED_TWO:?}}"
    exit "$rc"
fi
exec "{real_flock}" "$@"
"#
        ),
    );

    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let inst = dir.path().join("runner");
    let hooks = dir.path().join("hooks");
    let unit_dir = etc_units.to_str().unwrap();
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let spawn_install = |role: &str| {
        Command::new("bash")
            .arg(script())
            .args([
                "install",
                "--repo",
                REPO_URL,
                "--name",
                "lock-box",
                "--service",
                "qeminga-lock-svc",
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
            ])
            .env("PATH", &path_env)
            .env("INSTALL_ROLE", role)
            .env("LOCK_WAITING_TWO", &lock_waiting_two)
            .env("LOCK_ACQUIRED_TWO", &lock_acquired_two)
            .env("FAKE_USER_FLAG", &user_flag)
            .env("FAKE_GOOD_TARBALL", &good_tarball)
            .env("DOWNLOAD_STARTED", &download_started)
            .env("RELEASE_DOWNLOAD", &release_download)
            .env("QEMINGA_KVM_DEVICE", "/dev/null")
            .env("QEMINGA_CGROUP_CONTROLLERS", &cg_ctrls)
            .env("QEMINGA_RUNTIME_ROOT", &rt_root)
            .env("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir)
            .env("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir)
            .env("QEMINGA_AAVMF_CODE", &aavmf_code)
            .env("QEMINGA_AAVMF_VARS", &aavmf_vars)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };

    let mut child1 = spawn_install("one");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut exited_early = false;
    while !download_started.exists() && Instant::now() < deadline {
        if child1.try_wait().unwrap().is_some() {
            exited_early = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !download_started.exists() {
        let _ = std::fs::write(&release_download, b"go");
        if !exited_early {
            let _ = child1.kill();
        }
        let out1 = child1.wait_with_output().unwrap();
        panic!(
            "first install should reach tarball download with partial installing record on disk (exited_early={exited_early}, status={:?}): {}",
            out1.status,
            text(&out1)
        );
    }

    // Launch overlapping second install while first install holds the lock mid-download,
    // and wait until child2 actually signals it has reached flock acquisition before
    // releasing child1 so both installs genuinely contend even on slow workers.
    let mut child2 = spawn_install("two");
    let lock_deadline = Instant::now() + Duration::from_secs(30);
    let mut child1_exited = false;
    let mut child2_exited = false;
    while !lock_waiting_two.exists() && Instant::now() < lock_deadline {
        if child1.try_wait().unwrap().is_some() {
            child1_exited = true;
            break;
        }
        if child2.try_wait().unwrap().is_some() {
            child2_exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !lock_waiting_two.exists() {
        let _ = std::fs::write(&release_download, b"go");
        if !child1_exited {
            let _ = child1.kill();
        }
        if !child2_exited {
            let _ = child2.kill();
        }
        let out1 = child1.wait_with_output().unwrap();
        let out2 = child2.wait_with_output().unwrap();
        panic!(
            "second install should reach flock acquisition while first holds lock (child1_exited={child1_exited}, status1={:?}, child2_exited={child2_exited}, status2={:?}):\n--- child1 ---\n{}\n--- child2 ---\n{}",
            out1.status,
            out2.status,
            text(&out1),
            text(&out2)
        );
    }
    // Give child2 a brief moment inside flock(2) and verify it stays blocked while child1 holds the lock.
    std::thread::sleep(Duration::from_millis(50));
    if lock_acquired_two.exists() || child2.try_wait().unwrap().is_some() {
        let _ = std::fs::write(&release_download, b"go");
        let _ = child1.kill();
        if child2.try_wait().unwrap().is_none() {
            let _ = child2.kill();
        }
        let out1 = child1.wait_with_output().unwrap();
        let out2 = child2.wait_with_output().unwrap();
        panic!(
            "second install must block on flock until first install releases lock (lock_acquired_two={}, status1={:?}, status2={:?}):\n--- child1 ---\n{}\n--- child2 ---\n{}",
            lock_acquired_two.exists(),
            out1.status,
            out2.status,
            text(&out1),
            text(&out2)
        );
    }

    // Release first install and wait for both processes to complete.
    std::fs::write(&release_download, b"go").unwrap();
    let out1 = child1.wait_with_output().unwrap();
    let out2 = child2.wait_with_output().unwrap();
    assert!(
        out1.status.success(),
        "first install must succeed: {}",
        text(&out1)
    );
    assert!(
        out2.status.success(),
        "serialized second install should observe completed record and succeed: {}",
        text(&out2)
    );
    assert!(
        lock_acquired_two.exists(),
        "second install must acquire the lock after first install exits"
    );

    let final_rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    for expected in [
        "RECORD_STATE=installed\n",
        "OWNED_CONFIG_DIR=1\n",
        "OWNED_STATE_DIR=1\n",
        "OWNED_INSTALL_DIR=1\n",
        "OWNED_HOOK_DIR=1\n",
        "OWNED_UNIT=1\n",
    ] {
        assert!(
            final_rec.contains(expected),
            "overlapping install MUST NOT clobber completed ownership flags ({expected:?}):\n{final_rec}"
        );
    }

    // Confirm subsequent uninstall cleanly removes both the runner dir and unit!
    let virsh_log = dir.path().join("virsh.log");
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_LOG", virsh_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(uninst.status.success(), "{}", text(&uninst));
    assert!(
        !inst.exists() && !etc_units.join("qeminga-lock-svc.service").exists() && !cfg.exists(),
        "subsequent uninstall must remove installed runner dir, unit, and config"
    );
}

#[test]
fn uninstall_and_cleanup_hook_refuse_symlinked_images_dir_without_deleting_target() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let inst = dir.path().join("runner");
    let victim = dir.path().join("victim-workspace");
    let victim_run = victim.join("qeminga-e2e-99-1-x86_64");
    for d in [
        &bin,
        &units,
        &rt_root,
        &hooks,
        &cfg,
        &state,
        &inst,
        &victim_run,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let victim_file = victim_run.join("precious.qcow2");
    std::fs::write(&victim_file, b"must-not-be-deleted").unwrap();

    // Service user replaces $STATE_DIR/images with a symlink pointing to victim workspace!
    std::os::unix::fs::symlink(&victim, state.join("images")).unwrap();

    let render = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks.to_str().unwrap(),
    ]);
    assert!(render.status.success(), "{}", text(&render));
    std::fs::write(
        cfg.join("policy.env"),
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/_work\nIMAGES_DIR={}/images\nLIBVIRT_CONNECT=qemu:///session\n",
            inst.display(),
            state.display(),
            inst.display(),
            state.display(),
        ),
    )
    .unwrap();
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=partial-uninstall\nSERVICE=qeminga-sym-img\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=sym-img\nLABELS=qeminga-kvm\nEPHEMERAL=1\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/_work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_INSTALL_DIR=0\nOWNED_UNIT=0\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            inst.display(),
        ),
    )
    .unwrap();

    let user_flag = dir.path().join("user_exists");
    std::fs::write(&user_flag, b"").unwrap();
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
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
    // virsh reports domain absent so an unanchored cleanup would try to delete $IMAGES_DIR/qeminga-e2e-99-1-x86_64!
    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    // 1. Direct hook-job-completed.sh --domains-only MUST refuse symlinked $STATE_DIR/images.
    let hook_out = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
        .arg(format!(
            "QEMINGA_RUNNER_POLICY={}",
            cfg.join("policy.env").display()
        ))
        .arg(hooks.join("hook-job-completed.sh"))
        .arg("--domains-only")
        .output()
        .unwrap();
    assert!(
        !hook_out.status.success(),
        "hook-job-completed.sh --domains-only MUST refuse symlinked images dir: {}",
        text(&hook_out)
    );
    assert!(
        victim_file.exists(),
        "matching qeminga-e2e-* dir at symlink target MUST survive hook-job-completed.sh"
    );

    // 2. uninstall --purge-user MUST fail, preserve partial-uninstall state, retain the user,
    //    and leave the matching directory at the symlink destination completely intact!
    let unit_dir = units.to_str().unwrap();
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst.status.success(),
        "uninstall MUST fail closed on symlinked images dir: {}",
        text(&uninst)
    );
    assert!(
        victim_file.exists(),
        "matching qeminga-e2e-* dir at symlink destination MUST survive uninstall"
    );
    let kept_rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        kept_rec.contains("RECORD_STATE=partial-uninstall\n") && user_flag.exists(),
        "failed symlinked-images uninstall must preserve partial-uninstall record and user:\n{kept_rec}"
    );

    // 3. Fallback path (service account unavailable so cleanup hook cannot run):
    //    uninstall MUST STILL fail closed on symlinked $STATE_DIR/images and preserve
    //    $STATE_DIR/.config/libvirt metadata + partial-uninstall install.env!
    let libvirt_xml = state.join(".config/libvirt/qemu/qeminga-e2e-99-1-x86_64.xml");
    std::fs::create_dir_all(libvirt_xml.parent().unwrap()).unwrap();
    std::fs::write(&libvirt_xml, b"<domain/>").unwrap();
    std::fs::remove_file(&user_flag).unwrap();
    let fallback_uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !fallback_uninst.status.success(),
        "fallback uninstall without service user MUST fail closed on symlinked images dir: {}",
        text(&fallback_uninst)
    );
    assert!(
        libvirt_xml.exists() && victim_file.exists() && cfg.join("install.env").exists(),
        "fallback uninstall MUST preserve .config/libvirt metadata, symlink target, and install.env"
    );
    let fallback_rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        fallback_rec.contains("RECORD_STATE=partial-uninstall\n")
            && fallback_rec.contains("OWNED_STATE_DIR=1\n"),
        "fallback uninstall on symlinked images must preserve partial-uninstall state:\n{fallback_rec}"
    );
}

#[test]
fn partial_uninstall_retry_ignores_legacy_hook_on_disk_and_protects_replacement_work() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let inst = dir.path().join("runner");
    let stray_vm = state.join("images/qeminga-e2e-88-1-x86_64");
    for d in [
        &bin,
        &units,
        &rt_root,
        &hooks,
        &cfg,
        &stray_vm,
        &inst.join("_work"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(stray_vm.join("root.qcow2"), b"stray-vm").unwrap();
    let repl_work_file = inst.join("_work/precious-replacement-work.txt");
    std::fs::write(&repl_work_file, b"replacement-runner-workspace").unwrap();

    // Plant a legacy 46337ed-style hook on disk that ignores CLI arguments (such as --domains-only)
    // and unconditionally scrubs WORK_DIR from policy.env!
    let legacy_hook_log = dir.path().join("legacy-hook-ran.log");
    write_exec(
        &hooks.join("hook-job-completed.sh"),
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
printf 'LEGACY_RAN args=%s\n' "$*" > "{}"
WORK_DIR=""
while IFS='=' read -r k v; do
    [ "$k" = "WORK_DIR" ] && WORK_DIR="$v"
done <"${{QEMINGA_RUNNER_POLICY:?}}"
if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    find -P "$WORK_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf -- {{}} +
fi
exit 0
"#,
            legacy_hook_log.display()
        ),
    );
    let state_vol = live_volume_id(&state);
    let inst_vol = live_volume_id(&inst);
    let hook_vol = live_volume_id(&hooks);
    std::fs::write(
        cfg.join("policy.env"),
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/_work\nIMAGES_DIR={}/images\nSTATE_VOL={state_vol}\nINSTALL_VOL={inst_vol}\nLIBVIRT_CONNECT=qemu:///session\n",
            inst.display(),
            state.display(),
            inst.display(),
            state.display(),
        ),
    )
    .unwrap();
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=partial-uninstall\nSERVICE=qeminga-legacy-hook\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=legacy\nLABELS=qeminga-kvm\nEPHEMERAL=1\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/_work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_INSTALL_DIR=0\nOWNED_UNIT=0\nVOL_HOOK_DIR={hook_vol}\nVOL_STATE_DIR={state_vol}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            inst.display(),
        ),
    )
    .unwrap();

    let user_flag = dir.path().join("user_exists");
    std::fs::write(&user_flag, b"").unwrap();
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
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
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    let unit_dir = units.to_str().unwrap();
    let out = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        out.status.success(),
        "partial-uninstall retry with legacy hook on disk should succeed via current installer cleanup: {}",
        text(&out)
    );
    assert!(
        !legacy_hook_log.exists(),
        "uninstall MUST NOT invoke an outdated/legacy hook-job-completed.sh from disk"
    );
    assert!(
        repl_work_file.exists(),
        "replacement runner workspace MUST survive retry even when legacy 46337ed hook was on disk"
    );
    assert!(
        !state.exists() && !hooks.exists() && !cfg.exists() && !user_flag.exists(),
        "owned state, legacy hooks, config, and user must be cleanly removed"
    );
}

#[test]
fn pending_user_recovery_requires_install_id_marker_and_refuses_unrelated_account() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let inst = dir.path().join("runner");
    let hooks = dir.path().join("hooks");
    for d in [&bin, &units, &rt_root, &cfg] {
        std::fs::create_dir_all(d).unwrap();
    }

    let userdel_log = dir.path().join("userdel.log");
    let usermod_log = dir.path().join("usermod.log");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let tok_file = dir.path().join("tok");
    std::fs::write(&tok_file, "FAKE_TOK\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Unrelated pre-existing account with private primary group and no supplementary groups,
    // carrying a non-matching GECOS comment!
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
case "$1" in
    -u) echo 1001 ;;
    -g) echo 1001 ;;
    -gn) echo qeminga-runner ;;
    -nG) echo "qeminga-runner" ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(
        &bin.join("getent"),
        r#"#!/bin/sh
if [ "$1" = "passwd" ] && [ "$2" = "qeminga-runner" ]; then
    echo "qeminga-runner:x:1001:1001:Unrelated Local User:/home/qeminga-runner:/bin/bash"
    exit 0
fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_USERDEL_LOG:?}\"\nexit 0\n",
    );
    write_exec(
        &bin.join("usermod"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_USERMOD_LOG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:755"; exit 0; fi
exec /usr/bin/stat "$@"
"#,
    );

    let unit_dir = units.to_str().unwrap();

    // 1. user-pending record WITH an INSTALL_ID that does NOT match the live account's GECOS.
    let pending_with_id = format!(
        "RECORD_SCHEMA=1\nRECORD_STATE=user-pending\nUSER=qeminga-runner\nUSER_CREATED=1\nCONFIG_DIR={}\nINSTALL_ID=abcdef0123456789abcdef0123456789\n",
        cfg.display()
    );
    std::fs::write(cfg.join("install.env"), &pending_with_id).unwrap();

    let bad_purge = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USERDEL_LOG", userdel_log.to_str().unwrap()),
            ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !bad_purge.status.success(),
        "uninstall --purge-user MUST refuse to delete an unrelated account without matching INSTALL_ID marker: {}",
        text(&bad_purge)
    );
    assert!(
        !userdel_log.exists(),
        "userdel MUST NOT run on an unverified pending account"
    );
    assert!(
        cfg.join("install.env").exists(),
        "ambiguous user-pending install.env MUST be preserved for manual recovery"
    );

    let bad_install = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "pending-box",
            "--service",
            "qeminga-pending-svc",
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
        &[
            ("FAKE_USERDEL_LOG", userdel_log.to_str().unwrap()),
            ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !bad_install.status.success(),
        "install retry MUST refuse to adopt/modify an unrelated account without matching INSTALL_ID marker: {}",
        text(&bad_install)
    );
    assert!(
        !usermod_log.exists(),
        "usermod MUST NOT change shell or grant kvm group to an unverified account"
    );
    assert!(
        cfg.join("install.env").exists(),
        "ambiguous user-pending install.env MUST remain intact after refused install retry"
    );

    // 2. Legacy/incomplete user-pending record WITHOUT INSTALL_ID MUST also be refused!
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=user-pending\nUSER=qeminga-runner\nUSER_CREATED=1\nCONFIG_DIR={}\n",
            cfg.display()
        ),
    )
    .unwrap();
    let missing_id_purge = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USERDEL_LOG", userdel_log.to_str().unwrap()),
            ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !missing_id_purge.status.success() && !userdel_log.exists(),
        "user-pending record missing INSTALL_ID must fail closed without calling userdel: {}",
        text(&missing_id_purge)
    );
}

#[test]
fn uninstall_preserves_ownership_and_account_when_backing_volume_is_unavailable() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let runner_vol = dir.path().join("runner-vol");
    let offline_backup = dir.path().join("offline-backup");
    let fake_tar_src = dir.path().join("tar-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &runner_vol,
        &offline_backup,
        &fake_tar_src.join("bin"),
        &fake_tar_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }

    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
    );
    write_exec(&fake_tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("config.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&fake_tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    let good_tarball = dir.path().join("runner-vol.tar.gz");
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
    let tok_file = dir.path().join("tok");
    std::fs::write(&tok_file, "FAKE_TOK\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Real major:minor of tempdir for realistic mountinfo entries.
    let dev_out = Command::new("stat")
        .args(["-c", "%Hr:%Lr", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let root_dev = String::from_utf8(dev_out.stdout).unwrap();
    let root_dev = root_dev.trim();

    let mountinfo_mounted = dir.path().join("mountinfo.mounted");
    std::fs::write(
        &mountinfo_mounted,
        format!(
            "29 1 {root_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             44 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();
    let mountinfo_unmounted = dir.path().join("mountinfo.unmounted");
    std::fs::write(
        &mountinfo_unmounted,
        format!("29 1 {root_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"),
    )
    .unwrap();

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
    write_exec(&bin.join("useradd"), FAKE_USERADD_GECOS);
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), FAKE_GETENT_GECOS);
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );
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

    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let inst = runner_vol.join("runner");
    let unit_dir = units.to_str().unwrap();

    // 1. Install with runner_vol mounted -> install.env MUST record VOL_INSTALL_DIR.
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "vol-box",
            "--service",
            "qeminga-vol-svc",
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
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mountinfo_mounted.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        inst_out.status.success(),
        "install on dedicated runner volume must succeed: {}",
        text(&inst_out)
    );
    let rec_installed = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_installed.contains("VOL_INSTALL_DIR=") && rec_installed.contains("sdb1"),
        "install.env MUST record backing volume for INSTALL_DIR:\n{rec_installed}"
    );

    // Plant credentials inside a locked subdir so we can also test staged retry when volume disappears.
    let cred_dir = inst.join("creds");
    std::fs::create_dir_all(&cred_dir).unwrap();
    std::fs::write(cred_dir.join(".credentials_rsaparams"), b"KEY-MATERIAL").unwrap();

    // 2. Unmount runner_vol (hide runner dir and remove runner_vol from mountinfo).
    //    uninstall --purge-user MUST fail closed and retain OWNED_INSTALL_DIR=1 + user + install.env!
    std::fs::rename(&inst, offline_backup.join("runner")).unwrap();
    let uninst_unmounted = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_unmounted.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_unmounted.status.success(),
        "uninstall MUST refuse to treat absent runner dir as deleted when backing volume is unmounted: {}",
        text(&uninst_unmounted)
    );
    assert!(
        user_flag.exists() && cfg.join("install.env").exists(),
        "service account and install.env MUST be preserved while runner volume is unavailable"
    );
    let rec_after_unmounted = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after_unmounted.contains("OWNED_INSTALL_DIR=1\n"),
        "OWNED_INSTALL_DIR MUST stay 1 when runner volume is unmounted:\n{rec_after_unmounted}"
    );

    // 3. Remount runner_vol with a read-only creds subdir (mode 0555) so staging rename succeeds
    //    and deletion fails, persisting STAGED_INSTALL_DIR.
    std::fs::rename(offline_backup.join("runner"), &inst).unwrap();
    std::fs::set_permissions(&cred_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let stage_fail = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_mounted.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !stage_fail.status.success(),
        "deletion of read-only staged credentials subdir must fail: {}",
        text(&stage_fail)
    );
    let rec_staged = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let staged_dir_str = rec_staged
        .lines()
        .find_map(|l| l.strip_prefix("STAGED_INSTALL_DIR="))
        .unwrap_or("")
        .to_string();
    assert!(
        !staged_dir_str.is_empty(),
        "failed deletion must record STAGED_INSTALL_DIR:\n{rec_staged}"
    );
    let staged_dir = PathBuf::from(&staged_dir_str);

    // 4. Unmount runner_vol AGAIN while STAGED_INSTALL_DIR is pending -> retry MUST NOT clear
    //    STAGED_INSTALL_DIR or purge user when the parent volume is unavailable!
    std::fs::rename(&staged_dir, offline_backup.join("staged")).unwrap();
    let retry_unmounted = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_unmounted.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !retry_unmounted.status.success(),
        "retry MUST refuse to clear STAGED_INSTALL_DIR when backing volume is unavailable: {}",
        text(&retry_unmounted)
    );
    let rec_still_staged = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_still_staged.contains(&format!("STAGED_INSTALL_DIR={staged_dir_str}\n"))
            && user_flag.exists(),
        "STAGED_INSTALL_DIR and user MUST remain preserved when volume is unmounted:\n{rec_still_staged}"
    );

    // 5. Remount runner_vol and make staged creds writable -> retry finishes cleanly!
    std::fs::rename(offline_backup.join("staged"), &staged_dir).unwrap();
    std::fs::set_permissions(
        staged_dir.join("runner/creds"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let retry_ok = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_mounted.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        retry_ok.status.success(),
        "retry once volume returns and is writable must finish cleanly: {}",
        text(&retry_ok)
    );
    assert!(
        !staged_dir.exists() && !cfg.exists() && !user_flag.exists(),
        "staged dir, config dir, and managed account must be removed after volume reconciliation"
    );
}

#[test]
fn uninstall_refuses_same_filesystem_bind_mount_without_deleting_shared_cache() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let inst = dir.path().join("runner");
    let shared_cache = state.join("image-cache");
    for d in [
        &bin,
        &units,
        &rt_root,
        &cfg,
        &shared_cache,
        &state.join("images"),
        &hooks,
        &inst,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let shared_img = shared_cache.join("ubuntu-24.04-shared.qcow2");
    std::fs::write(&shared_img, b"DONOR-SHARED-CLOUD-IMAGE").unwrap();

    let dev_out = Command::new("stat")
        .args(["-c", "%Hr:%Lr", state.to_str().unwrap()])
        .output()
        .unwrap();
    let same_dev = String::from_utf8(dev_out.stdout).unwrap();
    let same_dev = same_dev.trim();

    // Same-filesystem bind mount: IDENTICAL major:minor (`same_dev`) as /, distinct mount_id 99!
    let mountinfo_with_bind = dir.path().join("mountinfo.bind");
    std::fs::write(
        &mountinfo_with_bind,
        format!(
            "29 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             99 29 {same_dev} /srv/shared-cache {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
            shared_cache.display()
        ),
    )
    .unwrap();
    let mountinfo_plain = dir.path().join("mountinfo.plain");
    std::fs::write(
        &mountinfo_plain,
        format!("29 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"),
    )
    .unwrap();

    let syn_vol_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            state.to_str().unwrap(),
        ])
        .env("QEMINGA_MOUNTINFO", &mountinfo_plain)
        .output()
        .unwrap();
    assert!(syn_vol_out.status.success(), "{}", text(&syn_vol_out));
    let syn_vol = String::from_utf8(syn_vol_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let user_flag = dir.path().join("user_exists");
    std::fs::write(&user_flag, b"").unwrap();
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-bind-svc\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=bind-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=0\nVOL_INSTALL_DIR={syn_vol}\nVOL_HOOK_DIR={syn_vol}\nVOL_STATE_DIR={syn_vol}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
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
        &bin.join("virsh"),
        r#"#!/bin/sh
if [ "${FAKE_VIRSH_FAIL:-0}" = "1" ]; then
    echo "error: failed to connect" >&2
    exit 1
fi
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    let unit_dir = units.to_str().unwrap();

    // 1. Partial-uninstall branch (cleanup_rc=1) MUST NOT cross same-FS bind mount into image-cache!
    let partial_bind = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_VIRSH_FAIL", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_with_bind.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(!partial_bind.status.success());
    assert!(
        shared_img.exists(),
        "partial-uninstall cleanup MUST NOT delete files inside same-filesystem bind mount image-cache"
    );

    // 2. Normal uninstall (cleanup_rc=0) MUST refuse to descend into same-FS bind mount under STATE_DIR,
    //    leave shared_img intact, and retain OWNED_STATE_DIR=1 + install.env + user!
    let full_bind = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_with_bind.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !full_bind.status.success(),
        "uninstall MUST refuse to remove STATE_DIR containing a same-filesystem bind mount: {}",
        text(&full_bind)
    );
    assert!(
        shared_img.exists(),
        "shared donor image cache file MUST survive uninstall when bind-mounted on same filesystem"
    );
    assert!(
        user_flag.exists() && cfg.join("install.env").exists(),
        "install.env and service account MUST be preserved when bind mount blocks state removal"
    );
    let rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec.contains("OWNED_STATE_DIR=1\n"),
        "OWNED_STATE_DIR must remain 1 when bind mount blocks staging/removal:\n{rec}"
    );

    // 3. Once the bind mount is unmounted, retry succeeds cleanly!
    let after_umount = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_plain.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        after_umount.status.success(),
        "retry after bind mount is removed must finish cleanly: {}",
        text(&after_umount)
    );
    assert!(!state.exists() && !cfg.exists() && !user_flag.exists());
}

#[test]
fn uninstall_staging_uses_rename_only_and_retains_ownership_on_exdev() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let inst = dir.path().join("runner");
    for d in [&bin, &units, &rt_root, &cfg, &state, &hooks, &inst] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(inst.join(".credentials_rsaparams"), b"KEY-DATA").unwrap();
    let mv_log = dir.path().join("mv.log");

    // 1. Direct rename-only check: fs_ops rename-only MUST fail without copying on EXDEV
    //    (tested between distinct filesystems /tmp and /dev/shm when distinct, or verified
    //    via source/dest invariants), AND uninstall staging MUST NOT invoke external `mv`!
    write_exec(
        &bin.join("mv"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_MV_LOG:?}"
exec /bin/mv "$@"
"#,
    );
    let user_flag = dir.path().join("user_exists");
    std::fs::write(&user_flag, b"").unwrap();
    let inst_vol = live_volume_id(&inst);
    let hook_vol = live_volume_id(&hooks);
    let state_vol = live_volume_id(&state);
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-rename-svc\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=rename-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=0\nVOL_INSTALL_DIR={inst_vol}\nVOL_HOOK_DIR={hook_vol}\nVOL_STATE_DIR={state_vol}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
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
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    let unit_dir = units.to_str().unwrap();
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_MV_LOG", mv_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(uninst.status.success(), "{}", text(&uninst));
    let mv_calls = std::fs::read_to_string(&mv_log).unwrap_or_default();
    assert!(
        !mv_calls.contains(".qeminga-removing."),
        "uninstall staging MUST use rename-only os.rename rather than mv (which falls back to copy-and-delete on EXDEV): {mv_calls}"
    );

    // 2. Verify fs_ops rename-only directly rejects cross-device rename without copying!
    let shm_root = Path::new("/dev/shm");
    if shm_root.is_dir() {
        let src_dir = dir.path().join("xdev-src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(src_dir.join("cred"), b"keep-me").unwrap();
        let dst_parent = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(shm_root)
            .unwrap();
        let src_dev = std::os::unix::fs::MetadataExt::dev(&std::fs::metadata(&src_dir).unwrap());
        let dst_dev =
            std::os::unix::fs::MetadataExt::dev(&std::fs::metadata(dst_parent.path()).unwrap());
        if src_dev != dst_dev {
            let dst_path = dst_parent.path().join("xdev-dst");
            let xdev_out = Command::new("bash")
                .args([
                    "-c",
                    r#"source "$1"; fs_ops rename-only "$2" "$3""#,
                    "_",
                    script().to_str().unwrap(),
                    src_dir.to_str().unwrap(),
                    dst_path.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                !xdev_out.status.success(),
                "fs_ops rename-only MUST fail on EXDEV without copy fallback: {}",
                text(&xdev_out)
            );
            assert!(
                src_dir.join("cred").exists() && !dst_path.exists(),
                "EXDEV failure must leave source intact and destination absent (zero copy fallback)"
            );
        }
    }
}

#[test]
fn installer_lock_dir_is_outside_service_runtime_paths_and_rejects_collisions() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let rt_root = dir.path().join("run");
    let cfg = dir.path().join("cfg");
    for d in [&bin, &rt_root, &cfg] {
        std::fs::create_dir_all(d).unwrap();
    }

    // 1. A leading dot in --service (e.g. .qeminga-runner.locks) MUST be rejected by check_service_name.
    let dot_svc = run_setup(&[
        "render-unit",
        "--service",
        ".qeminga-runner.locks",
        "--arch",
        "x86_64",
    ]);
    assert!(
        !dot_svc.status.success(),
        "dot-prefixed --service must be rejected so it can never collide with hidden lock dirs: {}",
        text(&dot_svc)
    );

    // 2. Default installer lock dir MUST NOT live at /run/qeminga-runner.locks (which collides
    //    with RuntimeDirectory=qeminga-runner.locks when --service qeminga-runner.locks is passed!).
    write_exec(
        &bin.join("id"),
        "#!/bin/sh\nif [ \"$1\" = \"-u\" ] && [ -z \"${2:-}\" ]; then echo 0; exit 0; fi\nexit 0\n",
    );
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:755"; exit 0; fi
exec /usr/bin/stat "$@"
"#,
    );
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let lock_ok = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; OPT_CONFIG_DIR="$2"; OPT_SERVICE="qeminga-runner.locks"; acquire_install_lock"#,
            "_",
            script().to_str().unwrap(),
            cfg.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("QEMINGA_RUNTIME_ROOT", &rt_root)
        .output()
        .unwrap();
    assert!(
        lock_ok.status.success(),
        "acquire_install_lock should succeed with --service qeminga-runner.locks: {}",
        text(&lock_ok)
    );
    assert!(
        !rt_root.join("qeminga-runner.locks").exists(),
        "default lock dir MUST NOT live at <rt_root>/qeminga-runner.locks (service RuntimeDirectory namespace)"
    );
    assert!(
        rt_root.join(".qeminga-runner.locks").is_dir(),
        "default lock dir should live in hidden non-unit-name path <rt_root>/.qeminga-runner.locks"
    );

    // 3. Even when QEMINGA_LOCK_DIR is explicitly overridden into <rt_root>/<name>, a colliding
    //    --service <name> MUST be rejected before installing or rendering!
    let custom_lock = rt_root.join("custom-lock-dir");
    let collide_render = run_setup_env(
        &[
            "render-unit",
            "--service",
            "custom-lock-dir",
            "--arch",
            "x86_64",
        ],
        &[
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_LOCK_DIR", custom_lock.to_str().unwrap()),
        ],
        None,
    );
    assert!(
        !collide_render.status.success()
            && text(&collide_render).contains("collides with installer lock directory"),
        "render-unit MUST reject --service whose RuntimeDirectory collides with QEMINGA_LOCK_DIR: {}",
        text(&collide_render)
    );
}

#[test]
fn cleanup_hook_and_uninstall_traverse_search_only_parent_directory() {
    struct RestoreMode(PathBuf);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let inst = dir.path().join("runner");
    let search_parent = dir.path().join("search-only-parent");
    let state = search_parent.join("state");
    let orphan1 = state.join("images/qeminga-e2e-55-1-x86_64");
    let orphan2 = state.join("images/qeminga-e2e-56-1-x86_64");
    for d in [
        &bin,
        &units,
        &rt_root,
        &hooks,
        &cfg,
        &inst,
        &orphan1,
        &orphan2,
        &state.join("work"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(orphan1.join("disk.qcow2"), b"orphan-1").unwrap();
    std::fs::write(orphan2.join("disk.qcow2"), b"orphan-2").unwrap();

    let render = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks.to_str().unwrap(),
    ]);
    assert!(render.status.success(), "{}", text(&render));
    let state_vol = live_volume_id(&state);
    let inst_vol = live_volume_id(&inst);
    let hook_vol = live_volume_id(&hooks);
    std::fs::write(
        cfg.join("policy.env"),
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work\nIMAGES_DIR={}/images\nSTATE_VOL={state_vol}\nINSTALL_VOL={inst_vol}\nLIBVIRT_CONNECT=qemu:///session\n",
            inst.display(),
            state.display(),
            state.display(),
            state.display(),
        ),
    )
    .unwrap();
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-searchonly-svc\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=so-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=0\nVOL_INSTALL_DIR={inst_vol}\nVOL_HOOK_DIR={hook_vol}\nVOL_STATE_DIR={state_vol}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    let user_flag = dir.path().join("user_exists");
    std::fs::write(&user_flag, b"").unwrap();
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:711"; exit 0; fi
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
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    // Restrict search_parent to mode 0111 (--x--x--x, search-only, NO read bit even for owner!),
    // reproducing how a root-owned 0711 parent appears to unprivileged qeminga-runner!
    let _guard = RestoreMode(search_parent.clone());
    std::fs::set_permissions(&search_parent, std::fs::Permissions::from_mode(0o111)).unwrap();

    // 1. hook-job-completed.sh MUST traverse search-only parent via O_PATH and remove orphan1 & orphan2!
    let hook_out = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
        .arg(format!(
            "QEMINGA_RUNNER_POLICY={}",
            cfg.join("policy.env").display()
        ))
        .arg(hooks.join("hook-job-completed.sh"))
        .arg("--domains-only")
        .output()
        .unwrap();
    assert!(
        hook_out.status.success(),
        "hook-job-completed.sh MUST traverse search-only 0711/0111 parent via O_PATH: {}",
        text(&hook_out)
    );
    assert!(
        !orphan1.exists() && !orphan2.exists(),
        "orphan run dirs under search-only parent must be removed"
    );

    // 2. Grant write+search (0311, still NO read bit!) so root-simulated staging rename inside
    //    search_parent can proceed while O_RDONLY on search_parent would still fail with EACCES.
    std::fs::create_dir_all(&orphan1).unwrap();
    std::fs::write(orphan1.join("disk.qcow2"), b"orphan-1-again").unwrap();
    std::fs::set_permissions(&search_parent, std::fs::Permissions::from_mode(0o311)).unwrap();
    let unit_dir = units.to_str().unwrap();
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        uninst.status.success(),
        "uninstall MUST traverse search-only parent via O_PATH and succeed cleanly: {}",
        text(&uninst)
    );
    assert!(!state.exists() && !cfg.exists() && !user_flag.exists());
}

#[test]
fn recursive_chown_enforces_mount_boundary_in_deregister_register_and_lock() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let inst = dir.path().join("runner");
    let shared_bind = inst.join("shared-data");
    for d in [
        &bin,
        &units,
        &rt_root,
        &cfg,
        &state.join("images"),
        &hooks,
        &shared_bind,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let shared_file = shared_bind.join("donor-secret.txt");
    std::fs::write(&shared_file, b"DONOR-DATA").unwrap();
    let cfg_sh_log = dir.path().join("config-sh.log");
    write_exec(
        &inst.join("config.sh"),
        &format!(
            "#!/bin/sh\nprintf 'CALLED\\n' >> \"{}\"\nexit 0\n",
            cfg_sh_log.display()
        ),
    );
    let rm_tok = dir.path().join("rm-tok");
    std::fs::write(&rm_tok, "FAKE_RM_INPUT\n").unwrap();
    std::fs::set_permissions(&rm_tok, std::fs::Permissions::from_mode(0o600)).unwrap();

    let dev_out = Command::new("stat")
        .args(["-c", "%Hr:%Lr", inst.to_str().unwrap()])
        .output()
        .unwrap();
    let same_dev = String::from_utf8(dev_out.stdout).unwrap();
    let same_dev = same_dev.trim();
    let mountinfo_bind = dir.path().join("mountinfo.bind");
    std::fs::write(
        &mountinfo_bind,
        format!(
            "29 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             99 29 {same_dev} /srv/donor-data {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
            shared_bind.display()
        ),
    )
    .unwrap();

    let user_flag = dir.path().join("user_exists");
    let chown_log = dir.path().join("chown.log");
    std::fs::write(&user_flag, b"").unwrap();
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-chown-mnt\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=chown-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=0\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
if [ ! -f "${FAKE_USER_FLAG:?}" ]; then exit 1; fi
if [ "$1" = "-u" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
if [ "$1" = "-g" ] && [ "$2" = "qeminga-runner" ]; then echo 995; exit 0; fi
exit 0
"#,
    );
    write_exec(&bin.join("chown"), FAKE_CHOWN);
    write_exec(&bin.join("userdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
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
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    let unit_dir = units.to_str().unwrap();

    // 1. Uninstall with --token-file MUST refuse deregistration BEFORE chowning runner/
    //    when a same-FS bind mount exists under runner/!
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            rm_tok.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_bind.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !uninst.status.success(),
        "uninstall with bind mount beneath runner dir MUST fail closed: {}",
        text(&uninst)
    );
    let chown_lines = std::fs::read_to_string(&chown_log).unwrap_or_default();
    assert!(
        !chown_lines.contains(inst.to_str().unwrap()),
        "deregistration MUST NOT chown runner dir or shared bind mount before mount check:\n{chown_lines}"
    );
    assert!(
        !cfg_sh_log.exists() && shared_file.exists() && cfg.join("install.env").exists(),
        "refused deregistration must leave config.sh uninvoked, shared bind mount intact, and install.env preserved"
    );

    // 2. lock_runner_permissions and register_runner_with_rollback MUST also refuse to chown
    //    when a bind mount exists beneath OPT_INSTALL_DIR!
    let _ = std::fs::remove_file(&chown_log);
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    for (label, snippet) in [
        (
            "lock_runner_permissions",
            r#"source "$1"; OPT_USER="qeminga-runner"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_ALLOW_AUTO_UPDATE=0; lock_runner_permissions"#,
        ),
        (
            "register_runner_with_rollback",
            r#"source "$1"; OPT_USER="qeminga-runner"; OPT_INSTALL_DIR="$2"; OPT_STATE_DIR="$3"; OPT_SERVICE="qeminga-chown-mnt"; OPT_ALLOW_AUTO_UPDATE=0; register_runner_with_rollback 0 "DUMMY" --unattended"#,
        ),
    ] {
        let _ = std::fs::remove_file(&chown_log);
        let out = Command::new("bash")
            .args([
                "-c",
                snippet,
                "_",
                script().to_str().unwrap(),
                inst.to_str().unwrap(),
                state.to_str().unwrap(),
            ])
            .env("PATH", &path_env)
            .env("FAKE_USER_FLAG", &user_flag)
            .env("FAKE_CHOWN_LOG", &chown_log)
            .env("QEMINGA_MOUNTINFO", &mountinfo_bind)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "{label} MUST refuse when bind mount exists under OPT_INSTALL_DIR: {}",
            text(&out)
        );
        let logged = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            !logged.contains(inst.to_str().unwrap()),
            "{label} MUST NOT chown OPT_INSTALL_DIR when bind mount is present:\n{logged}"
        );
    }
}

#[test]
fn update_and_reinstall_refuse_replacement_volume_for_runner_and_unit() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let rt_root = dir.path().join("run");
    let runner_vol = dir.path().join("runner-vol");
    let units_vol = dir.path().join("units-vol");
    let fake_tar_src = dir.path().join("tar-src");
    for d in [
        &bin,
        &rt_root,
        &runner_vol,
        &units_vol,
        &fake_tar_src.join("bin"),
        &fake_tar_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    write_exec(
        &fake_tar_src.join("config.sh"),
        r#"#!/bin/sh
work=""; url=""; name=""
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
    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
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

    let user_flag = dir.path().join("user_gecos");
    let sc_log = dir.path().join("systemctl.log");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let tok_file = dir.path().join("reg-input");
    std::fs::write(&tok_file, "FAKE_REG_INPUT\n").unwrap();
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
        r#"#!/bin/sh
comment=""
while [ $# -gt 0 ]; do
    case "$1" in
        --comment|-c) comment="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '%s\n' "$comment" > "${FAKE_USER_FLAG:?}"
exit 0
"#,
    );
    write_exec(
        &bin.join("getent"),
        r#"#!/bin/sh
if [ "$1" = "passwd" ] && [ "$2" = "qeminga-runner" ]; then
    [ -f "${FAKE_USER_FLAG:?}" ] || exit 2
    comment="$(cat "${FAKE_USER_FLAG:?}")"
    printf 'qeminga-runner:x:995:995:%s:/var/lib/qeminga-runner:/usr/sbin/nologin\n' "$comment"
    exit 0
fi
exit 0
"#,
    );
    write_exec(&bin.join("userdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then rc="${FAKE_IS_ACTIVE_RC:-3}"; if [ "$rc" -eq 0 ]; then echo active; else echo inactive; fi; exit "$rc"; fi
exit 0
"#,
    );
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in
        *api.github.com/repos/*) printf '404'; exit 0 ;;
    esac
done
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

    let mountinfo_orig = dir.path().join("mountinfo.orig");
    std::fs::write(
        &mountinfo_orig,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n\
             43 29 8:33 / {} rw,relatime shared:3 - ext4 /dev/sdc1 rw\n",
            runner_vol.display(),
            units_vol.display()
        ),
    )
    .unwrap();
    let mountinfo_repl_runner = dir.path().join("mountinfo.repl-runner");
    std::fs::write(
        &mountinfo_repl_runner,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:49 / {} rw,relatime shared:2 - xfs /dev/sdd1 rw\n\
             43 29 8:33 / {} rw,relatime shared:3 - ext4 /dev/sdc1 rw\n",
            runner_vol.display(),
            units_vol.display()
        ),
    )
    .unwrap();
    let mountinfo_repl_units = dir.path().join("mountinfo.repl-units");
    std::fs::write(
        &mountinfo_repl_units,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n\
             43 29 8:65 / {} rw,relatime shared:3 - xfs /dev/sde1 rw\n",
            runner_vol.display(),
            units_vol.display()
        ),
    )
    .unwrap();

    let inst = runner_vol.join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units_vol.to_str().unwrap();

    // 1. Fresh install on original runner_vol and units_vol succeeds.
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "upd-vol-box",
            "--service",
            "qeminga-upd-vol",
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
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mountinfo_orig.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Plant replacement-volume files inside existing runner/bin and runner/externals.
    let repl_bin_file = inst.join("bin/replacement-payload");
    let repl_ext_file = inst.join("externals/replacement-ext");
    std::fs::write(&repl_bin_file, b"FOREIGN-BIN").unwrap();
    std::fs::write(&repl_ext_file, b"FOREIGN-EXT").unwrap();

    // 2. `update` against a REPLACEMENT runner volume MUST fail closed BEFORE stopping the
    //    service or removing bin/externals!
    let _ = std::fs::remove_file(&sc_log);
    let upd_out = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_IS_ACTIVE_RC", "0"),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mountinfo_repl_runner.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !upd_out.status.success(),
        "update MUST refuse a replacement filesystem for INSTALL_DIR: {}",
        text(&upd_out)
    );
    assert!(
        repl_bin_file.exists() && repl_ext_file.exists(),
        "replacement filesystem contents in bin/ and externals/ MUST remain untouched"
    );
    let sc_after_upd = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        !sc_after_upd.contains("stop "),
        "update MUST NOT stop the service before verifying INSTALL_DIR volume:\n{sc_after_upd}"
    );

    // 3. Reinstall (`install`) with OWNED_UNIT=1 against a REPLACEMENT units volume MUST fail
    //    closed BEFORE stopping the service or overwriting the replacement unit file!
    let unit_path = units_vol.join("qeminga-upd-vol.service");
    let repl_unit_body = "[Unit]\nDescription=Replacement Foreign Service\n";
    std::fs::write(&unit_path, repl_unit_body).unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let reinst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "upd-vol-box",
            "--service",
            "qeminga-upd-vol",
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
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_IS_ACTIVE_RC", "0"),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mountinfo_repl_units.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !reinst_out.status.success(),
        "reinstall MUST refuse a replacement filesystem for owned systemd unit: {}",
        text(&reinst_out)
    );
    assert_eq!(
        std::fs::read_to_string(&unit_path).unwrap(),
        repl_unit_body,
        "replacement unit file MUST NOT be overwritten when VOL_UNIT mismatches"
    );
    let sc_after_reinst = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        !sc_after_reinst.contains("stop "),
        "reinstall MUST NOT stop the service when VOL_UNIT mismatches:\n{sc_after_reinst}"
    );
}

#[test]
fn cleanup_hook_refuses_bind_mount_directly_at_work_dir_or_images_root() {
    let dir = private_tempdir();
    let hooks = dir.path().join("hooks");
    let state = dir.path().join("state");
    let work = state.join("work");
    let work_sub = work.join("nested-bind");
    let images = state.join("images");
    let run_dir = images.join("qeminga-e2e-77-1-x86_64");
    let run_sub = run_dir.join("nested-bind");
    for d in [&hooks, &work_sub, &run_sub] {
        std::fs::create_dir_all(d).unwrap();
    }
    let work_file = work.join("shared-work.txt");
    let work_sub_file = work_sub.join("shared-sub.txt");
    let img_disk = run_dir.join("disk.qcow2");
    let img_sub_file = run_sub.join("shared-img.txt");
    std::fs::write(&work_file, b"SHARED-WORK").unwrap();
    std::fs::write(&work_sub_file, b"SHARED-WORK-SUB").unwrap();
    std::fs::write(&img_disk, b"SHARED-IMG-DISK").unwrap();
    std::fs::write(&img_sub_file, b"SHARED-IMG-SUB").unwrap();

    let render = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks.to_str().unwrap(),
    ]);
    assert!(render.status.success(), "{}", text(&render));
    let hook_src = std::fs::read_to_string(hooks.join("hook-job-completed.sh")).unwrap();
    let py_start = hook_src
        .find("<<'PY'\n")
        .expect("images_ops python heredoc must exist")
        + "<<'PY'\n".len();
    let py_end = hook_src[py_start..]
        .find("\nPY\n")
        .expect("images_ops python heredoc end must exist")
        + py_start;
    let images_ops_py = &hook_src[py_start..py_end];
    let py_file = dir.path().join("images_ops_rendered.py");
    std::fs::write(&py_file, images_ops_py).unwrap();

    // Part A (runs unconditionally on all hosts): execute the EXACT rendered images_ops Python
    // source with a synthetic /proc/self/mountinfo stub covering:
    //   1. bind mount directly at WORK_DIR
    //   2. bind mount beneath WORK_DIR
    //   3. bind mount directly at STATE_DIR/images
    //   4. bind mount beneath STATE_DIR/images/qeminga-e2e-...
    let dev_out = Command::new("stat")
        .args(["-c", "%Hr:%Lr", state.to_str().unwrap()])
        .output()
        .unwrap();
    let same_dev = String::from_utf8(dev_out.stdout).unwrap();
    let same_dev = same_dev.trim();

    let harness = r#"
import builtins, io, os, runpy, sys
fake_mi = os.environ["FAKE_MOUNTINFO_TEXT"]
real_open = builtins.open
def patched_open(file, *args, **kwargs):
    if file == "/proc/self/mountinfo":
        return io.StringIO(fake_mi)
    return real_open(file, *args, **kwargs)
builtins.open = patched_open
script = sys.argv[1]
sys.argv = [script] + sys.argv[2:]
runpy.run_path(script, run_name="__main__")
"#;

    let mnt_id_out = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-c",
            r#"import os, sys
fd = os.open(sys.argv[1], os.O_PATH)
try:
    for line in open(f"/proc/self/fdinfo/{fd}"):
        if line.startswith("mnt_id:"):
            print(line.split(":", 1)[1].strip())
            break
finally:
    os.close(fd)
"#,
            state.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(mnt_id_out.status.success(), "{}", text(&mnt_id_out));
    let root_mnt_id: u64 = String::from_utf8(mnt_id_out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let bind_mnt_id = root_mnt_id + 10000;
    let fake_state_vol = "mp:/,root:/,fs:ext4,src:/dev/sda1";
    let inst_unused = dir.path().join("runner-unused");

    let cases: [(&str, String, Vec<&str>); 4] = [
        (
            "bind mount directly at WORK_DIR",
            format!(
                "{root_mnt_id} 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                 {bind_mnt_id} {root_mnt_id} {same_dev} /srv/shared-work {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
                work.display()
            ),
            vec![
                "scrub-work",
                state.to_str().unwrap(),
                inst_unused.to_str().unwrap(),
                fake_state_vol,
                fake_state_vol,
                work.to_str().unwrap(),
            ],
        ),
        (
            "bind mount beneath WORK_DIR",
            format!(
                "{root_mnt_id} 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                 {bind_mnt_id} {root_mnt_id} {same_dev} /srv/shared-sub {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
                work_sub.display()
            ),
            vec![
                "scrub-work",
                state.to_str().unwrap(),
                inst_unused.to_str().unwrap(),
                fake_state_vol,
                fake_state_vol,
                work.to_str().unwrap(),
            ],
        ),
        (
            "bind mount directly at STATE_DIR/images",
            format!(
                "{root_mnt_id} 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                 {bind_mnt_id} {root_mnt_id} {same_dev} /srv/shared-images {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
                images.display()
            ),
            vec![
                "remove",
                state.to_str().unwrap(),
                inst_unused.to_str().unwrap(),
                fake_state_vol,
                fake_state_vol,
                "qeminga-e2e-77-1-x86_64",
            ],
        ),
        (
            "bind mount beneath STATE_DIR/images/<dom>",
            format!(
                "{root_mnt_id} 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                 {bind_mnt_id} {root_mnt_id} {same_dev} /srv/shared-sub {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
                run_sub.display()
            ),
            vec![
                "remove",
                state.to_str().unwrap(),
                inst_unused.to_str().unwrap(),
                fake_state_vol,
                fake_state_vol,
                "qeminga-e2e-77-1-x86_64",
            ],
        ),
    ];

    for (label, mi_text, args) in cases {
        let out = Command::new("/usr/bin/python3")
            .arg("-I")
            .arg("-c")
            .arg(harness)
            .arg(&py_file)
            .args(&args)
            .env("FAKE_MOUNTINFO_TEXT", &mi_text)
            .output()
            .unwrap();
        let msg = text(&out);
        assert!(
            !out.status.success() && msg.contains("cross mount point"),
            "images_ops MUST refuse {label} specifically for crossing a mount point: {msg}"
        );
        assert!(
            work_file.exists()
                && work_sub_file.exists()
                && img_disk.exists()
                && img_sub_file.exists(),
            "{label}: zero files may be deleted when bind mount is rejected"
        );
    }

    // Part B (runs when kernel permits unprivileged user+mount namespaces): verify real kernel
    // same-FS `mount --bind` directly at WORK_DIR and at STATE_DIR/images against unmodified hook!
    let can_unshare = Command::new("unshare")
        .args(["-Ur", "-m", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if can_unshare {
        let bin = dir.path().join("bin");
        let cfg = dir.path().join("cfg");
        let inst = dir.path().join("runner");
        let src_shared = dir.path().join("real-shared-src");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::create_dir_all(&inst).unwrap();
        std::fs::create_dir_all(src_shared.join("qeminga-e2e-88-1-x86_64")).unwrap();
        let src_work_file = src_shared.join("precious-work.txt");
        let src_img_file = src_shared.join("qeminga-e2e-88-1-x86_64/precious.qcow2");
        std::fs::write(&src_work_file, b"REAL-KERNEL-WORK").unwrap();
        std::fs::write(&src_img_file, b"REAL-KERNEL-IMG").unwrap();
        write_exec(
            &bin.join("virsh"),
            r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
        );
        let live_state_vol = live_volume_id(&state);
        let live_inst_vol = live_volume_id(&inst);
        std::fs::write(
            cfg.join("policy.env"),
            format!(
                "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}\nIMAGES_DIR={}\nSTATE_VOL={live_state_vol}\nINSTALL_VOL={live_inst_vol}\nLIBVIRT_CONNECT=qemu:///session\n",
                inst.display(),
                state.display(),
                work.display(),
                images.display(),
            ),
        )
        .unwrap();

        for (label, mount_target) in [
            ("real kernel bind mount at WORK_DIR", work.as_path()),
            ("real kernel bind mount at IMAGES_DIR", images.as_path()),
        ] {
            let out = Command::new("unshare")
                .args([
                    "-Ur",
                    "-m",
                    "sh",
                    "-c",
                    r#"mount --bind "$1" "$2" || exit 99
                       PATH="$3:/usr/bin:/bin" QEMINGA_RUNNER_POLICY="$4" "$5"
                       rc=$?
                       umount "$2" || true
                       exit "$rc""#,
                    "_",
                    src_shared.to_str().unwrap(),
                    mount_target.to_str().unwrap(),
                    bin.to_str().unwrap(),
                    cfg.join("policy.env").to_str().unwrap(),
                    hooks.join("hook-job-completed.sh").to_str().unwrap(),
                ])
                .output()
                .unwrap();
            let msg = text(&out);
            assert!(
                !out.status.success()
                    && out.status.code() != Some(99)
                    && (msg.contains("cross mount point") || msg.contains("mount boundary")),
                "{label}: unmodified hook-job-completed.sh MUST refuse bind mount: {msg}"
            );
            assert!(
                src_work_file.exists() && src_img_file.exists(),
                "{label}: shared bind-mounted files MUST remain untouched"
            );
        }
    }
}

#[test]
fn volume_verification_resolves_overmounted_tree_and_persistent_fs_uuid() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let data_dir = dir.path().join("data");
    let nested_dir = data_dir.join("nested");
    let nested_runner = nested_dir.join("runner");
    let offline_backup = dir.path().join("offline-backup");
    let runner_vol = dir.path().join("runner-vol");
    let fake_tar_src = dir.path().join("tar-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &nested_runner,
        &offline_backup,
        &runner_vol,
        &fake_tar_src.join("bin"),
        &fake_tar_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }

    // Part A: Directory overmount (mirroring tests/fixtures/mountinfo/directory_overmount.txt):
    //   Row 40 (parent=27, mp=<data>/nested, /dev/sdb1) is SHADOWED by later row 41
    //   (parent=27, mp=<data>, /dev/sdc1)!
    //   Even though row 40 has a LONGER pathname than row 41, lookups under <data>/nested/runner
    //   reach row 41 (/dev/sdc1), NOT shadowed row 40 (/dev/sdb1).
    let mi_before_overmount = dir.path().join("mi.before");
    std::fs::write(
        &mi_before_overmount,
        format!(
            "27 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             40 27 8:2 / {} rw,relatime shared:5 - ext4 /dev/sdb1 rw\n",
            nested_dir.display()
        ),
    )
    .unwrap();
    let mi_after_overmount = dir.path().join("mi.after");
    std::fs::write(
        &mi_after_overmount,
        format!(
            "27 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             40 27 8:2 / {} rw,relatime shared:5 - ext4 /dev/sdb1 rw\n\
             41 27 8:3 / {} rw,relatime shared:6 - ext4 /dev/sdc1 rw\n",
            nested_dir.display(),
            data_dir.display()
        ),
    )
    .unwrap();

    let vol_orig_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            nested_runner.to_str().unwrap(),
        ])
        .env("QEMINGA_MOUNTINFO", &mi_before_overmount)
        .env(
            "QEMINGA_FS_UUID_MAP",
            "40=11111111-1111-1111-1111-111111111111",
        )
        .output()
        .unwrap();
    assert!(
        vol_orig_out.status.success(),
        "volume-id before overmount failed: {}",
        text(&vol_orig_out)
    );
    let vol_orig = String::from_utf8(vol_orig_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    // After overmount 41 hides 40, verify-volume MUST reject BOTH present replacement AND absent path!
    let verify_present_overmounted = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops verify-volume "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            nested_runner.to_str().unwrap(),
            &vol_orig,
        ])
        .env("QEMINGA_MOUNTINFO", &mi_after_overmount)
        .env(
            "QEMINGA_FS_UUID_MAP",
            "40=11111111-1111-1111-1111-111111111111,41=22222222-2222-2222-2222-222222222222",
        )
        .output()
        .unwrap();
    assert!(
        !verify_present_overmounted.status.success(),
        "verify-volume MUST detect directory overmount 41 shadowing longer-path row 40 (present target): {}",
        text(&verify_present_overmounted)
    );
    let absent_under_overmount = nested_dir.join("absent-runner");
    let verify_absent_overmounted = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops verify-volume "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            absent_under_overmount.to_str().unwrap(),
            &vol_orig,
        ])
        .env("QEMINGA_MOUNTINFO", &mi_after_overmount)
        .env(
            "QEMINGA_FS_UUID_MAP",
            "40=11111111-1111-1111-1111-111111111111,41=22222222-2222-2222-2222-222222222222",
        )
        .output()
        .unwrap();
    assert!(
        !verify_absent_overmounted.status.success(),
        "verify-volume MUST detect directory overmount 41 shadowing longer-path row 40 (absent target): {}",
        text(&verify_absent_overmounted)
    );

    // Part A2 (runs when kernel permits unprivileged user+mount namespaces): real kernel
    // directory overmount with NO QEMINGA_MOUNTINFO override, proving live /proc/self/fdinfo
    // mnt_id lookup resolves to the overmount rather than the shadowed longer-path mount!
    let can_unshare = Command::new("unshare")
        .args(["-Ur", "-m", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if can_unshare {
        let live_base = dir.path().join("live-overmount");
        let live_data = live_base.join("data");
        let live_nested = live_data.join("nested");
        let src_a = live_base.join("src-a");
        let src_b = live_base.join("src-b");
        for d in [
            &live_nested,
            &src_a.join("runner"),
            &src_b.join("nested/runner"),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let live_overmount_out = Command::new("unshare")
            .args([
                "-Ur",
                "-m",
                "bash",
                "-c",
                r#"set -euo pipefail
                   source "$1"
                   mount --bind "$2" "$3" || exit 99
                   orig_vol="$(fs_ops volume-id "$3/runner")"
                   mount --bind "$4" "$5" || exit 99
                   if fs_ops verify-volume "$3/runner" "$orig_vol"; then
                       echo "UNEXPECTED_PASS_PRESENT" >&2
                       exit 1
                   fi
                   if fs_ops verify-volume "$3/missing" "$orig_vol"; then
                       echo "UNEXPECTED_PASS_ABSENT" >&2
                       exit 1
                   fi
                   echo "REAL_KERNEL_OVERMOUNT_DETECTED"
                "#,
                "_",
                script().to_str().unwrap(),
                src_a.to_str().unwrap(),
                live_nested.to_str().unwrap(),
                src_b.to_str().unwrap(),
                live_data.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            live_overmount_out.status.success()
                && text(&live_overmount_out).contains("REAL_KERNEL_OVERMOUNT_DETECTED"),
            "real kernel /proc/self/fdinfo mnt_id lookup must detect directory overmount: {}",
            text(&live_overmount_out)
        );
    }

    // Part B: Reusable /dev/sdb1 device name across remounts with DIFFERENT persistent UUID!
    write_exec(
        &fake_tar_src.join("config.sh"),
        r#"#!/bin/sh
work=""; url=""; name=""
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
    write_exec(
        &fake_tar_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
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

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let tok_file = dir.path().join("reg-input");
    std::fs::write(&tok_file, "FAKE_REG_INPUT\n").unwrap();
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
        r#"#!/bin/sh
comment=""
while [ $# -gt 0 ]; do
    case "$1" in
        --comment|-c) comment="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '%s\n' "$comment" > "${FAKE_USER_FLAG:?}"
exit 0
"#,
    );
    write_exec(
        &bin.join("getent"),
        r#"#!/bin/sh
if [ "$1" = "passwd" ] && [ "$2" = "qeminga-runner" ]; then
    [ -f "${FAKE_USER_FLAG:?}" ] || exit 2
    comment="$(cat "${FAKE_USER_FLAG:?}")"
    printf 'qeminga-runner:x:995:995:%s:/var/lib/qeminga-runner:/usr/sbin/nologin\n' "$comment"
    exit 0
fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nrm -f \"${FAKE_USER_FLAG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("passwd"), "#!/bin/sh\nexit 0\n");
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
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ "$1" = "show" ]; then echo "not-found"; exit 0; fi
if [ "$1" = "is-active" ]; then echo inactive; exit 3; fi
exit 0
"#,
    );
    write_exec(&bin.join("systemd-analyze"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in
        *api.github.com/repos/*) printf '404'; exit 0 ;;
    esac
done
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
    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );

    let mi_sdb1 = dir.path().join("mi.sdb1");
    std::fs::write(
        &mi_sdb1,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();
    let mi_sdc1_same_disk = dir.path().join("mi.sdc1");
    std::fs::write(
        &mi_sdc1_same_disk,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:33 / {} rw,relatime shared:2 - ext4 /dev/sdc1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();

    let inst = runner_vol.join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    // Install on Disk A (/dev/sdb1, UUID aaaaaaaa-...).
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "uuid-box",
            "--service",
            "qeminga-uuid-svc",
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
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mi_sdb1.to_str().unwrap()),
            (
                "QEMINGA_FS_UUID_MAP",
                "29=00000000-0000-0000-0000-000000000001,42=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    let rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec.contains("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        "install.env MUST record persistent filesystem UUID in VOL_INSTALL_DIR:\n{rec}"
    );

    // Swap in Disk B at the EXACT SAME mountpoint and EXACT SAME /dev/sdb1 name, but DIFFERENT UUID!
    std::fs::rename(&inst, offline_backup.join("runner")).unwrap();
    let uninst_diff_disk = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_sdb1.to_str().unwrap()),
            (
                "QEMINGA_FS_UUID_MAP",
                "29=00000000-0000-0000-0000-000000000001,42=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_diff_disk.status.success(),
        "uninstall MUST refuse a different filesystem reusing /dev/sdb1: {}",
        text(&uninst_diff_disk)
    );
    assert!(
        user_flag.exists() && cfg.join("install.env").exists(),
        "service account and install.env MUST stay preserved when a different disk reuses /dev/sdb1"
    );

    // Remount Disk A (UUID aaaaaaaa-...) even after device renumbering /dev/sdb1 -> /dev/sdc1 -> succeeds!
    std::fs::rename(offline_backup.join("runner"), &inst).unwrap();
    let uninst_orig_disk = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_sdc1_same_disk.to_str().unwrap()),
            (
                "QEMINGA_FS_UUID_MAP",
                "29=00000000-0000-0000-0000-000000000001,42=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ),
        ],
        Some(&bin),
    );
    assert!(
        uninst_orig_disk.status.success(),
        "uninstall MUST succeed when original persistent filesystem UUID returns (even if renumbered to /dev/sdc1): {}",
        text(&uninst_orig_disk)
    );
    assert!(!inst.exists() && !cfg.exists() && !user_flag.exists());
}

#[test]
fn reinstall_preserves_legacy_record_when_owned_dir_without_vol_is_missing() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let inst = dir.path().join("runner"); // intentionally ABSENT (offline legacy volume!)
    for d in [&bin, &units, &rt_root, &cfg, &state, &hooks] {
        std::fs::create_dir_all(d).unwrap();
    }
    let unit_path = units.join("qeminga-legacy-miss.service");
    std::fs::write(&unit_path, "[Unit]\n").unwrap();

    // Legacy install.env: OWNED_INSTALL_DIR=1 with NO VOL_INSTALL_DIR and NO INSTALL_ID.
    let legacy_rec = format!(
        "RECORD_SCHEMA=1\nRECORD_STATE=installed\nSERVICE=qeminga-legacy-miss\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=legacy-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\n",
        inst.display(),
        state.display(),
        hooks.display(),
        cfg.display(),
        state.display(),
    );
    std::fs::write(cfg.join("install.env"), &legacy_rec).unwrap();

    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let tok_file = dir.path().join("reg-input");
    std::fs::write(&tok_file, "FAKE_REG_INPUT\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
case "$1" in
    -u) echo 995 ;;
    -g) echo 995 ;;
    -gn) echo qeminga-runner ;;
    -nG) echo "qeminga-runner kvm" ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(&bin.join("getent"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("usermod"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:755"; exit 0; fi
exec /usr/bin/stat "$@"
"#,
    );
    write_mock_systemctl(
        &bin.join("systemctl"),
        "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then echo inactive; exit 3; fi\nexit 0\n",
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in
        *api.github.com/repos/*) printf '404'; exit 0 ;;
    esac
done
exit 22
"#,
    );

    let unit_dir = units.to_str().unwrap();
    let out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "legacy-box",
            "--service",
            "qeminga-legacy-miss",
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
        &[
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !out.status.success(),
        "reinstall MUST refuse when an owned directory in a legacy record (no VOL_*) is absent: {}",
        text(&out)
    );
    assert!(
        !inst.exists(),
        "reinstall MUST NOT recreate absent legacy owned directory on visible filesystem"
    );
    let after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        !after.contains("VOL_INSTALL_DIR="),
        "legacy install.env MUST NOT be overwritten with a replacement VOL_INSTALL_DIR:\n{after}"
    );

    // Part B: Present-directory case — create `inst` with an unrelated sentinel file while
    // `VOL_INSTALL_DIR` is still empty. Reinstall MUST still refuse BEFORE downloading,
    // stopping an active service, touching `inst/donor-sentinel`, or fingerprinting whatever
    // is mounted now into `install.env`, and must direct the operator to `migrate-record --confirm-volumes`!
    std::fs::create_dir_all(&inst).unwrap();
    std::fs::write(inst.join("donor-sentinel"), b"UNCONFIRMED-VOLUME\n").unwrap();
    let sc_log = dir.path().join("sc.log");
    let curl_log = dir.path().join("curl.log");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
if [ "$1" = "is-active" ]; then echo active; exit 0; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_CURL_LOG:?}"
exit 22
"#,
    );
    let out_present = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "legacy-box",
            "--service",
            "qeminga-legacy-miss",
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
        &[
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_CURL_LOG", curl_log.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    let present_msg = text(&out_present);
    assert!(
        !out_present.status.success()
            && present_msg.contains("migrate-record")
            && present_msg.contains("--confirm-volumes"),
        "reinstall MUST refuse present legacy runner dir with empty VOL_INSTALL_DIR and direct to migrate-record --confirm-volumes: {present_msg}"
    );
    assert_eq!(
        std::fs::read(inst.join("donor-sentinel")).unwrap(),
        b"UNCONFIRMED-VOLUME\n",
        "present unconfirmed directory must remain untouched"
    );
    assert!(
        !sc_log.exists() && !curl_log.exists(),
        "reinstall must refuse empty VOL_INSTALL_DIR before calling systemctl or curl"
    );
    let after_present = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        !after_present.contains("VOL_INSTALL_DIR="),
        "legacy install.env must NOT adopt a live VOL_INSTALL_DIR without operator migration:\n{after_present}"
    );

    // Part C: Populate VOL_INSTALL_DIR/VOL_STATE_DIR/VOL_HOOK_DIR while leaving VOL_UNIT empty
    // with OWNED_UNIT=1 -> reinstall MUST also refuse empty VOL_UNIT before touching anything!
    let vol_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            inst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(vol_out.status.success());
    let live_vol = String::from_utf8(vol_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let rec_no_unit_vol = format!(
        "{legacy_rec}VOL_INSTALL_DIR={live_vol}\nVOL_STATE_DIR={live_vol}\nVOL_HOOK_DIR={live_vol}\nVOL_UNIT=\n"
    );
    std::fs::write(cfg.join("install.env"), &rec_no_unit_vol).unwrap();
    let out_no_unit_vol = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "legacy-box",
            "--service",
            "qeminga-legacy-miss",
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
        &[
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_CURL_LOG", curl_log.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    let unit_vol_msg = text(&out_no_unit_vol);
    assert!(
        !out_no_unit_vol.status.success()
            && unit_vol_msg.contains("VOL_UNIT")
            && unit_vol_msg.contains("migrate-record"),
        "reinstall MUST refuse empty VOL_UNIT for owned unit and direct to migrate-record --confirm-volumes: {unit_vol_msg}"
    );
    assert!(
        !sc_log.exists() && !curl_log.exists(),
        "reinstall must refuse empty VOL_UNIT before calling systemctl or curl"
    );
}

#[test]
fn post_bootstrap_install_id_marker_blocks_recycled_uid_and_preserves_legacy_migration() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let cfg = dir.path().join("cfg");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let inst = dir.path().join("runner");
    for d in [&bin, &units, &rt_root, &cfg, &state, &hooks, &inst] {
        std::fs::create_dir_all(d).unwrap();
    }
    let unit_path = units.join("qeminga-marker-svc.service");
    std::fs::write(&unit_path, "[Unit]\n").unwrap();
    write_exec(&inst.join("config.sh"), "#!/bin/sh\nexit 0\n");

    let userdel_log = dir.path().join("userdel.log");
    let usermod_log = dir.path().join("usermod.log");
    let chown_log = dir.path().join("chown.log");
    let runuser_log = dir.path().join("runuser.log");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let tok_file = dir.path().join("reg-input");
    std::fs::write(&tok_file, "FAKE_REG_INPUT\n").unwrap();
    std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    // Live account has RECYCLED numeric IDs 995:995 matching install.env,
    // but an unrelated GECOS comment!
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo 0; exit 0; fi
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
        &bin.join("getent"),
        r#"#!/bin/sh
if [ "$1" = "passwd" ] && [ "$2" = "qeminga-runner" ]; then
    echo "qeminga-runner:x:995:995:Recycled Unrelated Account:/home/qeminga-runner:/bin/bash"
    exit 0
fi
exit 0
"#,
    );
    write_exec(
        &bin.join("userdel"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_USERDEL_LOG:?}\"\nexit 0\n",
    );
    write_exec(
        &bin.join("usermod"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_USERMOD_LOG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("chown"), FAKE_CHOWN);
    write_exec(
        &bin.join("runuser"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_RUNUSER_LOG:?}\"\nexit 0\n",
    );
    write_exec(&bin.join("groupdel"), "#!/bin/sh\nexit 0\n");
    write_mock_systemctl(&bin.join("systemctl"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("stat"),
        r#"#!/bin/sh
if [ "$1" = "-c" ] && [ "$2" = "%u" ]; then echo 0; exit 0; fi
if [ "$1" = "-c" ] && [ "$2" = "%u:%a" ]; then echo "0:755"; exit 0; fi
exec /usr/bin/stat "$@"
"#,
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
for a in "$@"; do
    case "$a" in
        *api.github.com/repos/*) printf '404'; exit 0 ;;
    esac
done
exit 22
"#,
    );

    let unit_dir = units.to_str().unwrap();
    let common_env = [
        ("FAKE_USERDEL_LOG", userdel_log.to_str().unwrap()),
        ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
        ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
        ("FAKE_RUNUSER_LOG", runuser_log.to_str().unwrap()),
        ("QEMINGA_KVM_DEVICE", "/dev/null"),
        ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
        ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
        ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
        ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
        ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
    ];

    // 1. Marked `installed` record MUST block update, uninstall --purge-user, and reinstall reuse!
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nINSTALL_ID=deadbeef01234567deadbeef01234567\nSERVICE=qeminga-marker-svc\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=marker-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    let upd_bad = run_setup_env(
        &["update", "--config-dir", cfg.to_str().unwrap()],
        &common_env,
        Some(&bin),
    );
    assert!(
        !upd_bad.status.success(),
        "update MUST reject recycled account missing INSTALL_ID GECOS marker: {}",
        text(&upd_bad)
    );

    let uninst_bad = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            tok_file.to_str().unwrap(),
            "--purge-user",
        ],
        &common_env,
        Some(&bin),
    );
    assert!(
        !uninst_bad.status.success(),
        "uninstall --purge-user MUST reject recycled account missing INSTALL_ID GECOS marker: {}",
        text(&uninst_bad)
    );

    let reinst_bad = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "marker-box",
            "--service",
            "qeminga-marker-svc",
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
        !reinst_bad.status.success(),
        "install MUST reject reusing recycled account missing INSTALL_ID GECOS marker: {}",
        text(&reinst_bad)
    );

    // 2. Marked `user-only` record MUST also block uninstall --purge-user on recycled IDs!
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=user-only\nINSTALL_ID=deadbeef01234567deadbeef01234567\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nCONFIG_DIR={}\n",
            cfg.display(),
        ),
    )
    .unwrap();
    let user_only_bad = run_setup_env(
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
        !user_only_bad.status.success(),
        "user-only uninstall --purge-user MUST reject recycled account missing INSTALL_ID marker: {}",
        text(&user_only_bad)
    );
    assert!(
        !userdel_log.exists()
            && !usermod_log.exists()
            && !chown_log.exists()
            && !runuser_log.exists()
            && cfg.join("install.env").exists(),
        "mismatched marker must block userdel, usermod, chown, and runuser while preserving install.env"
    );

    // 3. Legacy `user-only` record WITHOUT INSTALL_ID stays distinguishable and allows clean
    //    uninstall --purge-user migration when numeric IDs match!
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=user-only\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nCONFIG_DIR={}\n",
            cfg.display(),
        ),
    )
    .unwrap();
    let legacy_ok = run_setup_env(
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
        legacy_ok.status.success() && userdel_log.exists() && !cfg.exists(),
        "legacy record without INSTALL_ID must still migrate cleanly via uninstall --purge-user: {}",
        text(&legacy_ok)
    );
}

#[test]
fn cleanup_hook_verifies_recorded_parent_volume_against_overmount() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let state_vol = dir.path().join("state-vol");
    let runner_vol = dir.path().join("runner-vol");
    for d in [&bin, &units, &rt_root, &state_vol, &runner_vol] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let (good_tarball, good_sha) = build_fake_runner_tarball(dir.path());

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-input");
    std::fs::write(&reg_file, "FAKE_REG_INPUT\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let mi_install = dir.path().join("mi.install");
    std::fs::write(
        &mi_install,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n\
             43 29 8:33 / {} rw,relatime shared:3 - ext4 /dev/sdc1 rw\n",
            state_vol.display(),
            runner_vol.display()
        ),
    )
    .unwrap();

    let inst = runner_vol.join("runner");
    let state = state_vol.join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    // 1. Install records STATE_VOL and INSTALL_VOL inside root-owned policy.env!
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "pol-vol-box",
            "--service",
            "qeminga-pol-vol",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mi_install.to_str().unwrap()),
            (
                "QEMINGA_FS_UUID_MAP",
                "29=00000000-0000-0000-0000-000000000001,42=11111111-1111-1111-1111-111111111111,43=22222222-2222-2222-2222-222222222222",
            ),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    let policy_text = std::fs::read_to_string(cfg.join("policy.env")).unwrap();
    let state_vol_rec = policy_text
        .lines()
        .find_map(|l| l.strip_prefix("STATE_VOL="))
        .unwrap_or("");
    let install_vol_rec = policy_text
        .lines()
        .find_map(|l| l.strip_prefix("INSTALL_VOL="))
        .unwrap_or("");
    assert!(
        state_vol_rec.contains("11111111-1111-1111-1111-111111111111")
            && install_vol_rec.contains("22222222-2222-2222-2222-222222222222"),
        "root-owned policy.env MUST carry STATE_VOL and INSTALL_VOL:\n{policy_text}"
    );

    // 2. Live kernel overmount test (when user+mount namespaces are enabled) AND unconditional
    //    mismatch check: overmounting STATE_DIR or INSTALL_DIR with a replacement volume MUST
    //    make hook-job-completed.sh fail closed WITHOUT touching replacement work/images/_work!
    let jit_work = inst.join("_work");
    std::fs::create_dir_all(&jit_work).unwrap();
    let work_file = state.join("work/replacement-work.txt");
    let img_dir = state.join("images/qeminga-e2e-91-1-x86_64");
    let img_file = img_dir.join("replacement.qcow2");
    let jit_file = jit_work.join("replacement-jit.txt");
    std::fs::create_dir_all(&img_dir).unwrap();
    std::fs::write(&work_file, b"REPL-WORK").unwrap();
    std::fs::write(&img_file, b"REPL-IMG").unwrap();
    std::fs::write(&jit_file, b"REPL-JIT").unwrap();

    // Since real /proc/self/mountinfo has the host root FS (not UUID 1111.../2222...), running the
    // unmodified hook-job-completed.sh right now ALREADY sees a replacement/overmounted parent!
    let hook_state_overmount = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
        .arg(format!(
            "QEMINGA_RUNNER_POLICY={}",
            cfg.join("policy.env").display()
        ))
        .arg(hooks.join("hook-job-completed.sh"))
        .output()
        .unwrap();
    assert!(
        !hook_state_overmount.status.success(),
        "hook-job-completed.sh MUST refuse cleanup when STATE_DIR parent volume does not match STATE_VOL: {}",
        text(&hook_state_overmount)
    );
    assert!(
        work_file.exists() && img_file.exists(),
        "replacement work/ and images/ files MUST survive when STATE_DIR is overmounted"
    );

    // JIT workspace policy pointing WORK_DIR under INSTALL_DIR with valid STATE_VOL and mismatched INSTALL_VOL:
    let jit_state_vol = live_volume_id(&state);
    let jit_policy = cfg.join("jit-policy.env");
    std::fs::write(
        &jit_policy,
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}\nIMAGES_DIR={}/images\nLIBVIRT_CONNECT=qemu:///session\nSTATE_VOL={jit_state_vol}\nINSTALL_VOL={}\n",
            inst.display(),
            state.display(),
            jit_work.display(),
            state.display(),
            install_vol_rec,
        ),
    )
    .unwrap();
    let hook_jit_overmount = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
        .arg(format!("QEMINGA_RUNNER_POLICY={}", jit_policy.display()))
        .arg(hooks.join("hook-job-completed.sh"))
        .output()
        .unwrap();
    let jit_overmount_msg = text(&hook_jit_overmount);
    assert!(
        !hook_jit_overmount.status.success() && !jit_overmount_msg.contains("missing recorded"),
        "hook-job-completed.sh MUST refuse JIT WORK_DIR cleanup specifically for mismatched INSTALL_VOL: {jit_overmount_msg}"
    );
    assert!(
        jit_file.exists(),
        "replacement JIT workspace files MUST survive when INSTALL_DIR is overmounted"
    );

    // 3. Positive check with REAL live host volume IDs: hook-job-completed.sh MUST succeed
    //    when STATE_VOL / INSTALL_VOL match the real kernel mount, AND when unshare is
    //    available: (a) a real kernel bind-mount overmount of STATE_DIR with a DIFFERENT
    //    directory MUST be refused without deleting replacement files, while (b) a systemd-
    //    style self-bind-mount of STATE_DIR onto itself MUST be accepted and clean work/!
    let live_state_vol_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            state.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        live_state_vol_out.status.success(),
        "{}",
        text(&live_state_vol_out)
    );
    let live_state_vol = String::from_utf8(live_state_vol_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let live_inst_vol_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            inst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        live_inst_vol_out.status.success(),
        "{}",
        text(&live_inst_vol_out)
    );
    let live_inst_vol = String::from_utf8(live_inst_vol_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let real_policy = cfg.join("real-vol-policy.env");
    std::fs::write(
        &real_policy,
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work\nIMAGES_DIR={}/images\nLIBVIRT_CONNECT=qemu:///session\nSTATE_VOL={live_state_vol}\nINSTALL_VOL={live_inst_vol}\n",
            inst.display(),
            state.display(),
            state.display(),
            state.display(),
        ),
    )
    .unwrap();

    let can_unshare = Command::new("unshare")
        .args(["-Ur", "-m", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if can_unshare {
        let repl_state = dir.path().join("repl-state");
        std::fs::create_dir_all(repl_state.join("work")).unwrap();
        std::fs::create_dir_all(repl_state.join("images/qeminga-e2e-99-1-x86_64")).unwrap();
        let repl_work_file = repl_state.join("work/keep-me.txt");
        let repl_img_file = repl_state.join("images/qeminga-e2e-99-1-x86_64/keep.qcow2");
        std::fs::write(&repl_work_file, b"KEEP-OVERMOUNT").unwrap();
        std::fs::write(&repl_img_file, b"KEEP-IMG").unwrap();

        // (a) Overmounting STATE_DIR with a DIFFERENT directory on the SAME filesystem MUST fail closed!
        let overmount_out = Command::new("unshare")
            .args([
                "-Ur",
                "-m",
                "bash",
                "-c",
                r#"set -euo pipefail
mount --bind "$1" "$2"
export PATH="$3:/usr/bin:/bin"
export QEMINGA_RUNNER_POLICY="$4"
"$5""#,
                "_",
                repl_state.to_str().unwrap(),
                state.to_str().unwrap(),
                bin.to_str().unwrap(),
                real_policy.to_str().unwrap(),
                hooks.join("hook-job-completed.sh").to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !overmount_out.status.success(),
            "live kernel bind-overmount of STATE_DIR with a replacement dir MUST be refused: {}",
            text(&overmount_out)
        );
        assert!(
            repl_work_file.exists() && repl_img_file.exists(),
            "files inside replacement bind-mounted STATE_DIR MUST survive untouched"
        );

        // (b) Systemd-style self-bind-mount (`mount --bind $STATE_DIR $STATE_DIR`, as produced by
        //     ProtectSystem=strict + StateDirectory=/ReadWritePaths=) MUST succeed and clean work/!
        let self_bind_out = Command::new("unshare")
            .args([
                "-Ur",
                "-m",
                "bash",
                "-c",
                r#"set -euo pipefail
mount --bind "$1" "$1"
export PATH="$2:/usr/bin:/bin"
export QEMINGA_RUNNER_POLICY="$3"
"$4""#,
                "_",
                state.to_str().unwrap(),
                bin.to_str().unwrap(),
                real_policy.to_str().unwrap(),
                hooks.join("hook-job-completed.sh").to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            self_bind_out.status.success(),
            "systemd-style self-bind-mount of STATE_DIR MUST succeed when recorded volume matches: {}",
            text(&self_bind_out)
        );
        assert!(
            !work_file.exists() && !img_file.exists(),
            "matching volume cleanup under self-bind-mount must clean work/ and orphan images/"
        );
    } else {
        let match_out = Command::new("env")
            .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
            .arg(format!("QEMINGA_RUNNER_POLICY={}", real_policy.display()))
            .arg(hooks.join("hook-job-completed.sh"))
            .output()
            .unwrap();
        assert!(
            match_out.status.success(),
            "hook-job-completed.sh must succeed when STATE_VOL matches live mount: {}",
            text(&match_out)
        );
        assert!(
            !work_file.exists() && !img_file.exists(),
            "matching volume cleanup must clean work/ and orphan images/"
        );
    }
}

#[test]
fn reinstall_refuses_bind_mounted_hook_policy_or_jit_file_without_truncating() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    for d in [&bin, &units, &rt_root] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let (good_tarball, good_sha) = build_fake_runner_tarball(dir.path());

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-input");
    std::fs::write(&reg_file, "FAKE_REG_INPUT\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let base_args = [
        "install",
        "--repo",
        REPO_URL,
        "--name",
        "bind-file-box",
        "--service",
        "qeminga-bind-file",
        "--install-dir",
        inst.to_str().unwrap(),
        "--state-dir",
        state.to_str().unwrap(),
        "--hook-dir",
        hooks.to_str().unwrap(),
        "--config-dir",
        cfg.to_str().unwrap(),
        "--token-file",
        reg_file.to_str().unwrap(),
        "--runner-sha256",
        good_sha.as_str(),
        "--skip-packages",
        "--no-start",
    ];

    let dev_out = Command::new("stat")
        .args(["-c", "%Hr:%Lr", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let same_dev = String::from_utf8(dev_out.stdout).unwrap();
    let same_dev = same_dev.trim();

    let mi_clean = dir.path().join("mi.clean");
    std::fs::write(
        &mi_clean,
        format!("29 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"),
    )
    .unwrap();

    // 1. Fresh install succeeds cleanly.
    let first = run_setup_env(
        &base_args,
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mi_clean.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(first.status.success(), "{}", text(&first));

    // 2. Plant a file bind mount on hook-job-started.sh and separately on policy.env ->
    //    reinstall MUST refuse BEFORE truncating or overwriting either file!
    for (label, target_file) in [
        ("bind-mounted hook file", hooks.join("hook-job-started.sh")),
        ("bind-mounted policy.env", cfg.join("policy.env")),
    ] {
        let orig = std::fs::read(&target_file).unwrap();
        std::fs::write(&target_file, b"DONOR-BIND-SENTINEL\n").unwrap();
        let mi_file_bind = dir.path().join("mi.file-bind");
        std::fs::write(
            &mi_file_bind,
            format!(
                "29 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                 99 29 {same_dev} /srv/donor-file {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
                target_file.display()
            ),
        )
        .unwrap();
        let reinst = run_setup_env(
            &base_args,
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("QEMINGA_MOUNTINFO", mi_file_bind.to_str().unwrap()),
            ],
            Some(&bin),
        );
        assert!(
            !reinst.status.success(),
            "reinstall MUST refuse {label}: {}",
            text(&reinst)
        );
        assert_eq!(
            std::fs::read(&target_file).unwrap(),
            b"DONOR-BIND-SENTINEL\n",
            "{label} MUST NOT be truncated or overwritten by reinstall"
        );
        std::fs::write(&target_file, orig).unwrap();
    }

    // 3. Also test a bind-mounted cfg/jitconfig file (even if currently absent or present):
    let jit_dest = cfg.join("jitconfig");
    std::fs::write(&jit_dest, b"DONOR-JIT-TARGET\n").unwrap();
    let jit_blob = make_jit_config(REPO_URL, &format!("{}/work", state.display()));
    let jit_in = dir.path().join("jit-in");
    std::fs::write(&jit_in, format!("{jit_blob}\n")).unwrap();
    std::fs::set_permissions(&jit_in, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(inst.join(".runner")).unwrap();
    let mi_jit_bind = dir.path().join("mi.jit-bind");
    std::fs::write(
        &mi_jit_bind,
        format!(
            "29 1 {same_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             99 29 {same_dev} /srv/donor-jit {} rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
            jit_dest.display()
        ),
    )
    .unwrap();
    let jit_reinst = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "bind-file-box",
            "--service",
            "qeminga-bind-file",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--jitconfig-file",
            jit_in.to_str().unwrap(),
            "--ephemeral",
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mi_jit_bind.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !jit_reinst.status.success(),
        "reinstall MUST refuse bind-mounted jitconfig destination: {}",
        text(&jit_reinst)
    );
    assert_eq!(
        std::fs::read(&jit_dest).unwrap(),
        b"DONOR-JIT-TARGET\n",
        "bind-mounted jitconfig MUST NOT receive JIT credentials or be truncated"
    );

    // 4. Live kernel file bind-mount check (when unshare is available): publish_managed_file
    //    MUST refuse a real kernel file bind mount with zero truncation even without QEMINGA_MOUNTINFO!
    let can_unshare = Command::new("unshare")
        .args(["-Ur", "-m", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if can_unshare {
        let donor_file = dir.path().join("donor-host-file");
        std::fs::write(&donor_file, b"LIVE-DONOR-CONTENT\n").unwrap();
        let hook_target = hooks.join("hook-job-started.sh");
        let live_bind_out = Command::new("unshare")
            .args([
                "-Ur",
                "-m",
                "bash",
                "-c",
                r#"set -euo pipefail
mount --bind "$1" "$2"
source "$3"
printf 'OVERWRITE\n' | publish_managed_file "$2" 0755"#,
                "_",
                donor_file.to_str().unwrap(),
                hook_target.to_str().unwrap(),
                script().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !live_bind_out.status.success(),
            "publish_managed_file MUST refuse a live kernel file bind mount: {}",
            text(&live_bind_out)
        );
        assert_eq!(
            std::fs::read(&donor_file).unwrap(),
            b"LIVE-DONOR-CONTENT\n",
            "live kernel bind-mounted donor file MUST NOT be truncated or modified"
        );
    }
}

#[test]
fn update_revalidates_volume_after_download_and_pins_extraction_to_verified_fd() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let runner_vol = dir.path().join("runner-vol");
    for d in [&bin, &units, &rt_root, &runner_vol] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let (good_tarball, good_sha) = build_fake_runner_tarball(dir.path());

    let user_flag = dir.path().join("user_gecos");
    let sc_log = dir.path().join("systemctl.log");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-input");
    std::fs::write(&reg_file, "FAKE_REG_INPUT\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let mi_live = dir.path().join("mi.live");
    let mi_orig_text = format!(
        "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
         42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n",
        runner_vol.display()
    );
    let mi_unmounted_text = "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n".to_string();
    std::fs::write(&mi_live, &mi_orig_text).unwrap();

    let inst = runner_vol.join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    // 1. Fresh install on mounted runner_vol.
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "upd-mid-box",
            "--service",
            "qeminga-upd-mid",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mi_live.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Plant replacement-volume files inside runner/bin and runner/externals.
    let repl_bin = inst.join("bin/underlying-sentinel");
    let repl_ext = inst.join("externals/underlying-ext");
    std::fs::write(&repl_bin, b"UNDERLYING-BIN").unwrap();
    std::fs::write(&repl_ext, b"UNDERLYING-EXT").unwrap();

    // 2. Replace curl so it unmounts runner_vol DURING download!
    let mi_after_download = dir.path().join("mi.after-dl");
    std::fs::write(&mi_after_download, &mi_unmounted_text).unwrap();
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
cp "${FAKE_GOOD_TARBALL:?}" "$out"
cp "${FAKE_MI_SWAP:?}" "${QEMINGA_MOUNTINFO:?}"
exit 0
"#,
    );

    let upd = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_IS_ACTIVE_RC", "0"),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("FAKE_MI_SWAP", mi_after_download.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_live.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !upd.status.success(),
        "update MUST revalidate volume after download and fail when runner volume unmounted mid-download: {}",
        text(&upd)
    );
    assert!(
        repl_bin.exists() && repl_ext.exists(),
        "underlying filesystem tree MUST remain completely untouched when volume unmounts during download"
    );
    let sc_logged = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        !sc_logged.contains("stop "),
        "update MUST NOT stop the service when post-download volume revalidation fails:\n{sc_logged}"
    );
}

#[test]
fn safe_chown_tree_rejects_outside_hard_links_and_uses_verified_fd() {
    let dir = private_tempdir();
    let inst = dir.path().join("runner");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(inst.join("bin")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    let outside_file = outside.join("donor-owned.txt");
    std::fs::write(&outside_file, b"SHARED-INODE").unwrap();
    let linked_inside = inst.join("bin/hardlinked-out");
    std::fs::hard_link(&outside_file, &linked_inside).unwrap();

    // 1. Hard link escaping outside runner/ (nlink=2, inside=1) MUST be refused!
    let reject_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-chown-tree "$2" 995 995"#,
            "_",
            script().to_str().unwrap(),
            inst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !reject_out.status.success(),
        "safe-chown-tree MUST reject regular files hard-linked outside the managed directory: {}",
        text(&reject_out)
    );

    // 2. Even an internal hard link (nlink=2, both names inside runner/) MUST be refused by
    //    safe-chown-tree on a live tree (because one name could be moved outside between walks
    //    without changing st_nlink), whereas removing the duplicate link (st_nlink=1) MUST pass!
    std::fs::remove_file(&outside_file).unwrap();
    let linked_peer = inst.join("bin/hardlinked-peer");
    std::fs::hard_link(&linked_inside, &linked_peer).unwrap();
    let internal_reject_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-chown-tree "$2" 995 995"#,
            "_",
            script().to_str().unwrap(),
            inst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !internal_reject_out.status.success(),
        "safe-chown-tree MUST reject multiply-linked files (st_nlink > 1) on a live tree: {}",
        text(&internal_reject_out)
    );

    // 3. safe-chown-file MUST refuse any hard-linked individual runner file (st_nlink > 1)!
    let file_hardlink_reject = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-chown-file "$2" 995 995 0600"#,
            "_",
            script().to_str().unwrap(),
            linked_inside.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !file_hardlink_reject.status.success(),
        "safe-chown-file MUST reject a hard-linked file (st_nlink > 1): {}",
        text(&file_hardlink_reject)
    );

    // Removing the extra link restores st_nlink=1 -> safe-chown-tree MUST accept it!
    std::fs::remove_file(&linked_peer).unwrap();
    let accept_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-chown-tree "$2" 995 995"#,
            "_",
            script().to_str().unwrap(),
            inst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        accept_out.status.success(),
        "safe-chown-tree MUST allow single-link regular files (st_nlink == 1): {}",
        text(&accept_out)
    );

    // 4. safe-chown-tree MUST refuse unexpected special files (e.g. FIFO) inside the runner tree!
    let fifo_path = inst.join("bin/sneaky.fifo");
    let mkfifo_ok = Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if mkfifo_ok {
        let fifo_reject = Command::new("bash")
            .args([
                "-c",
                r#"source "$1"; fs_ops safe-chown-tree "$2" 995 995"#,
                "_",
                script().to_str().unwrap(),
                inst.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !fifo_reject.status.success(),
            "safe-chown-tree MUST reject special files (FIFOs) inside managed tree: {}",
            text(&fifo_reject)
        );
    }
}

#[test]
fn migrate_record_upgrades_legacy_vol_and_intermediate_unmarked_account() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let runner_vol = dir.path().join("runner-vol");
    let inst = runner_vol.join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [
        &bin,
        &units,
        &rt_root,
        &inst.join("bin"),
        &inst.join("externals"),
        &state.join("images"),
        &hooks,
        &cfg,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let (good_tarball, good_sha) = build_fake_runner_tarball(dir.path());

    let unit_path = units.join("qeminga-mig-svc.service");
    std::fs::write(&unit_path, "[Unit]\n").unwrap();
    std::fs::write(
        cfg.join("policy.env"),
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work\nIMAGES_DIR={}/images\nLIBVIRT_CONNECT=qemu:///session\n",
            inst.display(),
            state.display(),
            state.display(),
            state.display(),
        ),
    )
    .unwrap();

    // Intermediate a3757c3 record:
    // - Legacy 4-field VOL_* (mp,root,fs,src WITHOUT uuid or fsid)
    // - Non-empty INSTALL_ID while genuine legacy account has empty GECOS ""!
    let user_flag = dir.path().join("user_gecos");
    std::fs::write(&user_flag, b"").unwrap(); // empty GECOS (pre-Round-11 useradd!)
    let install_id = "11223344556677889900aabbccddeeff";
    let legacy_vol_root = "mp:/,root:/,fs:ext4,src:/dev/sda1";
    let legacy_vol_runner = format!("mp:{},root:/,fs:ext4,src:/dev/sdb1", runner_vol.display());
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nINSTALL_ID={install_id}\nSERVICE=qeminga-mig-svc\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=mig-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\nVOL_UNIT={legacy_vol_root}\nVOL_INSTALL_DIR={legacy_vol_runner}\nVOL_HOOK_DIR={legacy_vol_root}\nVOL_STATE_DIR={legacy_vol_root}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    let mi_orig = dir.path().join("mi.orig");
    std::fs::write(
        &mi_orig,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();
    let mi_wrong = dir.path().join("mi.wrong");
    std::fs::write(
        &mi_wrong,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:49 / {} rw,relatime shared:2 - xfs /dev/sdd1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();

    let unit_dir = units.to_str().unwrap();
    let uuid_map =
        "29=00000000-0000-0000-0000-000000000001,42=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    // 1. Default update MUST refuse unmigrated intermediate record (both marker and legacy VOL_*).
    let upd_before = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !upd_before.status.success(),
        "default update MUST fail closed on unmigrated intermediate record: {}",
        text(&upd_before)
    );

    // 2. migrate-record WITHOUT confirmation flags MUST refuse!
    let mig_no_confirm = run_setup_env(
        &["migrate-record", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_no_confirm.status.success(),
        "migrate-record without explicit confirmation flags must fail closed"
    );

    // 3. migrate-record --confirm-account-marker MUST refuse when account has non-empty unrelated GECOS!
    std::fs::write(&user_flag, "Recycled Unrelated Account\n").unwrap();
    let mig_unrelated_acct = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-account-marker",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_unrelated_acct.status.success(),
        "migrate-record --confirm-account-marker MUST refuse an account with unrelated non-empty GECOS: {}",
        text(&mig_unrelated_acct)
    );

    // 4. migrate-record --confirm-volumes MUST refuse when mounted filesystem mismatches legacy fields!
    std::fs::write(&user_flag, b"").unwrap();
    let mig_wrong_vol = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_wrong.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_wrong_vol.status.success(),
        "migrate-record --confirm-volumes MUST refuse when filesystem disagrees with legacy VOL_*: {}",
        text(&mig_wrong_vol)
    );

    // 5. Operator-verified migrate-record --confirm-volumes --confirm-account-marker succeeds,
    //    stamping GECOS and upgrading VOL_* in install.env + policy.env!
    let mig_ok = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
            "--confirm-account-marker",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        mig_ok.status.success(),
        "operator-verified migrate-record must succeed on genuine intermediate record: {}",
        text(&mig_ok)
    );
    assert_eq!(
        std::fs::read_to_string(&user_flag).unwrap().trim(),
        format!("qeminga-runner-{install_id}"),
        "migrate-record --confirm-account-marker must stamp GECOS marker"
    );
    let rec_upgraded = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_upgraded.contains("uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        "migrate-record --confirm-volumes must upgrade VOL_INSTALL_DIR to strong UUID identity:\n{rec_upgraded}"
    );
    let pol_upgraded = std::fs::read_to_string(cfg.join("policy.env")).unwrap();
    assert!(
        pol_upgraded.contains("INSTALL_VOL=")
            && pol_upgraded.contains("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        "migrate-record --confirm-volumes must refresh INSTALL_VOL/STATE_VOL in policy.env:\n{pol_upgraded}"
    );

    // 6. After migration, both `update` and `uninstall --purge-user` succeed cleanly!
    let upd_after = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        upd_after.status.success(),
        "update must succeed after migrate-record: {}",
        text(&upd_after)
    );

    let uninst_after = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        uninst_after.status.success() && !inst.exists() && !cfg.exists() && !user_flag.exists(),
        "uninstall --purge-user must succeed cleanly after migrate-record: {}",
        text(&uninst_after)
    );

    // 7. migrate-record MUST refuse user-pending records (even with --confirm-account-marker),
    //    AND MUST refuse overwriting a mismatched strong UUID/fsid VOL_* record even with
    //    --confirm-volumes!
    let pending_cfg = dir.path().join("pending-cfg");
    std::fs::create_dir_all(&pending_cfg).unwrap();
    std::fs::write(
        pending_cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=user-pending\nINSTALL_ID={install_id}\nUSER=qeminga-runner\nUSER_CREATED=1\nCONFIG_DIR={}\n",
            pending_cfg.display()
        ),
    )
    .unwrap();
    std::fs::write(&user_flag, b"").unwrap();
    let mig_pending = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            pending_cfg.to_str().unwrap(),
            "--confirm-account-marker",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !mig_pending.status.success(),
        "migrate-record MUST refuse user-pending records: {}",
        text(&mig_pending)
    );

    let strong_cfg = dir.path().join("strong-cfg");
    let strong_inst = runner_vol.join("strong-runner");
    let strong_state = dir.path().join("strong-state");
    let strong_hooks = dir.path().join("strong-hooks");
    for d in [&strong_cfg, &strong_inst, &strong_state, &strong_hooks] {
        std::fs::create_dir_all(d).unwrap();
    }
    let strong_unit = units.join("qeminga-strong-svc.service");
    std::fs::write(&strong_unit, "[Unit]\n").unwrap();
    let strong_vol_mismatch = format!(
        "mp:{},root:/,fs:ext4,uuid:99999999-9999-9999-9999-999999999999",
        runner_vol.display()
    );
    std::fs::write(
        strong_cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nINSTALL_ID={install_id}\nSERVICE=qeminga-strong-svc\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=strong-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\nVOL_UNIT={legacy_vol_root}\nVOL_INSTALL_DIR={strong_vol_mismatch}\nVOL_HOOK_DIR={legacy_vol_root}\nVOL_STATE_DIR={legacy_vol_root}\n",
            strong_inst.display(),
            strong_state.display(),
            strong_hooks.display(),
            strong_cfg.display(),
            strong_state.display(),
        ),
    )
    .unwrap();
    let mig_strong_mismatch = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            strong_cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_strong_mismatch.status.success(),
        "migrate-record --confirm-volumes MUST refuse overwriting a mismatched strong UUID record: {}",
        text(&mig_strong_mismatch)
    );
}

#[test]
fn private_tempdir_creates_0700_fixture_roots() {
    let dir = private_tempdir();
    let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "test fixture root must be created with mode 0700, got {:o}",
        mode
    );
}

#[test]
fn update_and_cleanup_require_nonempty_recorded_volume_fingerprints() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [
        &bin,
        &units,
        &rt_root,
        &inst.join("bin"),
        &inst.join("externals"),
        &inst.join("_work"),
        &state.join("work"),
        &state.join("images/qeminga-e2e-51-1-x86_64"),
        &hooks,
        &cfg,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let (good_tarball, good_sha) = build_fake_runner_tarball(dir.path());
    let user_flag = dir.path().join("user_gecos");
    let sc_log = dir.path().join("sc.log");
    let install_id = "abcdef0123456789abcdef0123456789";
    std::fs::write(&user_flag, format!("qeminga-runner-{install_id}\n")).unwrap();
    std::fs::write(inst.join("bin/keep-sentinel"), b"KEEP-BIN").unwrap();
    std::fs::write(state.join("work/keep-work"), b"KEEP-WORK").unwrap();
    std::fs::write(
        state.join("images/qeminga-e2e-51-1-x86_64/keep.qcow2"),
        b"KEEP-IMG",
    )
    .unwrap();
    std::fs::write(inst.join("_work/keep-jit"), b"KEEP-JIT").unwrap();
    let unit_path = units.join("qeminga-empty-vol.service");
    std::fs::write(&unit_path, "[Unit]\n").unwrap();

    // 1. Legacy installed record with EMPTY VOL_INSTALL_DIR -> update MUST fail closed BEFORE
    //    stopping the service or removing bin/, directing operator to migrate-record!
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nINSTALL_ID={install_id}\nSERVICE=qeminga-empty-vol\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=empty-vol\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();
    let unit_dir = units.to_str().unwrap();
    let upd_empty = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_IS_ACTIVE_RC", "0"),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    let upd_msg = text(&upd_empty);
    assert!(
        !upd_empty.status.success()
            && upd_msg.contains("migrate-record")
            && upd_msg.contains("--confirm-volumes"),
        "update MUST fail closed on empty VOL_INSTALL_DIR and point to migrate-record --confirm-volumes: {upd_msg}"
    );
    assert!(
        inst.join("bin/keep-sentinel").exists(),
        "runner bin/ MUST remain untouched when VOL_INSTALL_DIR is empty"
    );
    assert!(
        !std::fs::read_to_string(&sc_log)
            .unwrap_or_default()
            .contains("stop "),
        "update MUST NOT stop the service when VOL_INSTALL_DIR is empty"
    );

    // 2. Render hook-job-completed.sh, then run with legacy policy.env supplying empty STATE_VOL=:
    //    destructive cleanup MUST fail closed without deleting work/ or images/!
    let rendered = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks.to_str().unwrap(),
    ]);
    assert!(rendered.status.success(), "{}", text(&rendered));

    let legacy_state_pol = cfg.join("legacy-empty-state.env");
    std::fs::write(
        &legacy_state_pol,
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work\nIMAGES_DIR={}/images\nSTATE_VOL=\nINSTALL_VOL=\nLIBVIRT_CONNECT=qemu:///session\n",
            inst.display(),
            state.display(),
            state.display(),
            state.display(),
        ),
    )
    .unwrap();
    let hook_empty_state = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
        .arg(format!(
            "QEMINGA_RUNNER_POLICY={}",
            legacy_state_pol.display()
        ))
        .arg(hooks.join("hook-job-completed.sh"))
        .output()
        .unwrap();
    assert!(
        !hook_empty_state.status.success(),
        "hook-job-completed.sh MUST refuse destructive cleanup when STATE_VOL is empty: {}",
        text(&hook_empty_state)
    );
    assert!(
        state.join("work/keep-work").exists()
            && state
                .join("images/qeminga-e2e-51-1-x86_64/keep.qcow2")
                .exists(),
        "work/ and images/ MUST survive untouched when STATE_VOL is empty"
    );

    // 3. Valid STATE_VOL but EMPTY INSTALL_VOL for JIT WORK_DIR under INSTALL_DIR -> MUST refuse!
    let live_state_vol_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            state.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(live_state_vol_out.status.success());
    let live_state_vol = String::from_utf8(live_state_vol_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    let legacy_jit_pol = cfg.join("legacy-empty-install.env");
    std::fs::write(
        &legacy_jit_pol,
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/_work\nIMAGES_DIR={}/images\nSTATE_VOL={live_state_vol}\nINSTALL_VOL=\nLIBVIRT_CONNECT=qemu:///session\n",
            inst.display(),
            state.display(),
            inst.display(),
            state.display(),
        ),
    )
    .unwrap();
    let hook_empty_inst = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
        .arg(format!(
            "QEMINGA_RUNNER_POLICY={}",
            legacy_jit_pol.display()
        ))
        .arg(hooks.join("hook-job-completed.sh"))
        .output()
        .unwrap();
    assert!(
        !hook_empty_inst.status.success(),
        "hook-job-completed.sh MUST refuse JIT WORK_DIR scrub when INSTALL_VOL is empty: {}",
        text(&hook_empty_inst)
    );
    assert!(
        inst.join("_work/keep-jit").exists(),
        "JIT _work files MUST survive untouched when INSTALL_VOL is empty"
    );
}

#[test]
fn install_and_update_stage_archive_privately_and_run_deps_in_staging() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let tar_src = dir.path().join("tar-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &tar_src.join("bin"),
        &tar_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    // Provide mock apt-get so install without --skip-packages runs installdependencies.sh!
    write_exec(&bin.join("apt-get"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("dpkg"), "#!/bin/sh\nexit 0\n");

    // Build tarball containing executable bin/installdependencies.sh AND an internal hard link
    // inside bin/ (verifying stage-runner-archive breaks internal hard links to st_nlink==1!).
    write_exec(
        &tar_src.join("bin/installdependencies.sh"),
        r#"#!/bin/sh
live_bin_present=0
[ -e "${FAKE_LIVE_INST:?}/bin" ] && live_bin_present=1
printf '%s|%s|%s\n' "$(pwd -P)" "$0" "$live_bin_present" > "${FAKE_DEPS_LOG:?}"
exit 0
"#,
    );
    write_exec(&tar_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&tar_src.join("bin/Runner.Listener"), "#!/bin/sh\nexit 0\n");
    write_exec(&tar_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&tar_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &tar_src.join("config.sh"),
        r#"#!/bin/sh
if [ "${1:-}" = "remove" ]; then rm -f .runner .credentials; exit 0; fi
dir="$(dirname "$0")"
printf '{"gitHubUrl":"https://github.com/vicaya/qeminga-kvm-controller","agentName":"stage-box","workFolder":"%s","disableUpdate":true,"ephemeral":false}\n' "${HOME}/work" > "$dir/.runner"
exit 0
"#,
    );
    std::fs::write(tar_src.join("bin/shared-a"), b"DUP-PAYLOAD").unwrap();
    std::fs::hard_link(tar_src.join("bin/shared-a"), tar_src.join("bin/shared-b")).unwrap();
    std::fs::write(tar_src.join("externals/ext.txt"), b"ext").unwrap();

    let tarball = dir.path().join("runner-with-deps.tar.gz");
    let tar_status = Command::new("tar")
        .args(["-czf", tarball.to_str().unwrap(), "-C"])
        .arg(&tar_src)
        .arg(".")
        .status()
        .unwrap();
    assert!(tar_status.success());
    let sha_out = Command::new("sha256sum").arg(&tarball).output().unwrap();
    let tarball_sha = String::from_utf8(sha_out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    let deps_log = dir.path().join("deps.log");
    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "stage-box",
            "--service",
            "qeminga-stage-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            tarball_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", tarball.to_str().unwrap()),
            ("FAKE_DEPS_LOG", deps_log.to_str().unwrap()),
            ("FAKE_LIVE_INST", inst.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(out.status.success(), "{}", text(&out));

    let deps_rec = std::fs::read_to_string(&deps_log).unwrap_or_default();
    let deps_rec = deps_rec.trim();
    let parts: Vec<&str> = deps_rec.split('|').collect();
    assert_eq!(parts.len(), 3, "unexpected deps log format: '{deps_rec}'");
    assert!(
        parts[0].contains(".qeminga-extract.")
            && parts[0].ends_with("/payload")
            && !parts[0].starts_with(inst.to_str().unwrap())
            && parts[1] == "./bin/installdependencies.sh"
            && parts[2] == "0",
        "installdependencies.sh MUST execute FD-pinned as ./bin/installdependencies.sh inside private .qeminga-extract.*/payload BEFORE publishing live OPT_INSTALL_DIR/bin: got '{deps_rec}'"
    );
    // Staging directory must be cleaned up, and published files must exist with st_nlink == 1.
    let leftover_stage = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".qeminga-extract.")
        });
    assert!(
        !leftover_stage,
        "staging directory must be removed after publish"
    );
    assert!(inst.join("bin/shared-a").is_file() && inst.join("bin/shared-b").is_file());
    let nlink_a = std::os::unix::fs::MetadataExt::nlink(
        &std::fs::metadata(inst.join("bin/shared-a")).unwrap(),
    );
    assert_eq!(
        nlink_a, 1,
        "staged internal hard links must be materialized as independent st_nlink==1 files"
    );

    // Also verify `update` stages privately, breaks internal hard links, preserves .runner,
    // and cleans up `.qeminga-extract.*`.
    std::fs::write(tar_src.join("bin/v2-a"), b"V2-PAYLOAD").unwrap();
    std::fs::hard_link(tar_src.join("bin/v2-a"), tar_src.join("bin/v2-b")).unwrap();
    let tarball_v2 = dir.path().join("runner-v2.tar.gz");
    let tar_v2_status = Command::new("tar")
        .args(["-czf", tarball_v2.to_str().unwrap(), "-C"])
        .arg(&tar_src)
        .arg(".")
        .status()
        .unwrap();
    assert!(tar_v2_status.success());
    let sha_v2_out = Command::new("sha256sum").arg(&tarball_v2).output().unwrap();
    let tarball_v2_sha = String::from_utf8(sha_v2_out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    let upd_out = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            tarball_v2_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", tarball_v2.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(upd_out.status.success(), "{}", text(&upd_out));
    let leftover_upd_stage = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".qeminga-extract.")
        });
    assert!(
        !leftover_upd_stage,
        "update staging directory must be removed after publish"
    );
    assert!(
        inst.join(".runner").is_file(),
        "update must preserve .runner"
    );
    assert!(inst.join("bin/v2-a").is_file() && inst.join("bin/v2-b").is_file());
    let nlink_v2 =
        std::os::unix::fs::MetadataExt::nlink(&std::fs::metadata(inst.join("bin/v2-a")).unwrap());
    assert_eq!(
        nlink_v2, 1,
        "update must materialize internal archive hard links as independent st_nlink==1 files"
    );
}

#[test]
fn installer_and_cleanup_hook_agree_on_unprivileged_volume_identity() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let empty_by_uuid = dir.path().join("empty-by-uuid");
    for d in [&bin, &units, &rt_root, &empty_by_uuid] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    // Plant a fake blkid returning a root-only UUID; installer MUST NOT depend on root-only blkid!
    write_exec(
        &bin.join("blkid"),
        "#!/bin/sh\necho root-only-blkid-uuid-0000\nexit 0\n",
    );
    let (good_tarball, good_sha) = build_fake_runner_tarball(dir.path());

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    // 1. Install on REAL host mount with empty QEMINGA_BY_UUID_DIR (simulating a disk where
    //    /dev/disk/by-uuid lacks an entry and only root blkid could query the raw device).
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "unpriv-vol-box",
            "--service",
            "qeminga-unpriv-vol",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            good_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_tarball.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_BY_UUID_DIR", empty_by_uuid.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    let policy_text = std::fs::read_to_string(cfg.join("policy.env")).unwrap();
    assert!(
        !policy_text.contains("uuid:") && policy_text.contains("fsid:"),
        "without /dev/disk/by-uuid match, policy.env MUST record unprivileged-verifiable src+fsid (never root-only blkid uuid):\n{policy_text}"
    );
    let script_text = std::fs::read_to_string(script()).unwrap();
    let resolve_fn = script_text
        .split("def resolve_fs_uuid(")
        .nth(1)
        .and_then(|s| s.split("def volume_id_of_fd(").next())
        .expect("resolve_fs_uuid function must exist in setup-kvm-runner.sh");
    assert!(
        !resolve_fn.contains("blkid"),
        "resolve_fs_uuid must not fall back to root-only blkid that the unprivileged cleanup hook cannot verify"
    );
    let hook_text = std::fs::read_to_string(hooks.join("hook-job-completed.sh")).unwrap();
    assert!(
        !hook_text.contains("blkid"),
        "unprivileged cleanup hook must never invoke root-only blkid"
    );

    // 2. Immediately running unmodified hook-job-completed.sh MUST accept the recorded STATE_VOL
    //    and clean work/ + orphan images/ cleanly!
    let work_file = state.join("work/temp.txt");
    let orphan_dir = state.join("images/qeminga-e2e-64-1-x86_64");
    std::fs::create_dir_all(&orphan_dir).unwrap();
    std::fs::write(&work_file, b"SCRUB").unwrap();
    std::fs::write(orphan_dir.join("disk.qcow2"), b"ORPHAN").unwrap();
    let hook_ok = Command::new("env")
        .arg(format!("PATH={}:/usr/bin:/bin", bin.display()))
        .arg(format!(
            "QEMINGA_RUNNER_POLICY={}",
            cfg.join("policy.env").display()
        ))
        .arg(hooks.join("hook-job-completed.sh"))
        .output()
        .unwrap();
    assert!(
        hook_ok.status.success() && !work_file.exists() && !orphan_dir.exists(),
        "cleanup hook MUST verify and clean using the installer's unprivileged-verifiable volume identity: {}",
        text(&hook_ok)
    );
}

#[test]
fn publish_managed_file_cmd_preserves_existing_file_on_producer_failure() {
    let dir = private_tempdir();
    let dest = dir.path().join("managed.env");
    std::fs::write(&dest, b"COMPLETE-PREVIOUS-CONTENT\n").unwrap();

    // Producer emits one partial line and exits 23 -> existing file MUST remain untouched!
    let fail_out = Command::new("bash")
        .args([
            "-c",
            r#"set -euo pipefail
source "$1"
failing_producer() {
    printf 'PARTIAL-LINE\n'
    return 23
}
publish_managed_file_cmd "$2" 0640 "" "" failing_producer"#,
            "_",
            script().to_str().unwrap(),
            dest.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !fail_out.status.success(),
        "publish_managed_file_cmd MUST fail when producer exits non-zero"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"COMPLETE-PREVIOUS-CONTENT\n",
        "existing managed file MUST NOT be overwritten with partial output on producer failure"
    );
    let leftover_tmp = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with(".managed.env."));
    assert!(
        !leftover_tmp,
        "staging temp file must be removed when producer fails"
    );

    // Ensure zero pipelines into publish_managed_file remain anywhere in setup-kvm-runner.sh!
    let script_text = std::fs::read_to_string(script()).unwrap();
    assert!(
        !script_text.contains("| publish_managed_file"),
        "setup-kvm-runner.sh must not pipe concurrent producers into publish_managed_file"
    );
}

#[test]
fn migrate_record_handles_staged_payload_strict_gecos_and_crash_safe_id() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let runner_vol = dir.path().join("runner-vol");
    let inst = runner_vol.join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let staged_inst = runner_vol.join(".qeminga-removing.mig001");
    for d in [
        &bin,
        &units,
        &rt_root,
        &staged_inst.join("runner/bin"),
        &state.join("images"),
        &hooks,
        &cfg,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let usermod_log = dir.path().join("usermod.log");
    let snap_rec_at_usermod = dir.path().join("rec-at-usermod.env");
    write_exec(
        &bin.join("usermod"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_USERMOD_LOG:?}"
if [ -n "${FAKE_SNAP_REC:-}" ] && [ -n "${FAKE_REC_PATH:-}" ] && [ -f "$FAKE_REC_PATH" ]; then
    cp "$FAKE_REC_PATH" "$FAKE_SNAP_REC"
fi
if [ "${FAKE_USERMOD_FAIL:-0}" = "1" ]; then
    echo "simulated usermod interruption" >&2
    exit 1
fi
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--comment)
            if [ -n "${FAKE_USER_FLAG:-}" ]; then
                printf '%s\n' "$2" > "$FAKE_USER_FLAG"
            fi
            shift 2
            ;;
        *) shift ;;
    esac
done
exit 0
"#,
    );
    write_exec(
        &bin.join("getent"),
        r#"#!/bin/sh
if [ "$1" = "passwd" ]; then
    if [ "${FAKE_GETENT_FAIL:-0}" = "1" ]; then
        exit 2
    fi
    if [ -f "${FAKE_USER_FLAG:?}" ]; then
        comment="$(cat "${FAKE_USER_FLAG:?}")"
        printf '%s:x:995:995:%s:/var/lib/qeminga-runner:/usr/sbin/nologin\n' "$2" "$comment"
        exit 0
    fi
    exit 2
fi
exit 0
"#,
    );

    let mi_orig = dir.path().join("mi.orig");
    std::fs::write(
        &mi_orig,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();
    let uuid_map =
        "29=00000000-0000-0000-0000-000000000001,42=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let legacy_vol_root = "mp:/,root:/,fs:ext4,src:/dev/sda1";
    let legacy_vol_runner = format!("mp:{},root:/,fs:ext4,src:/dev/sdb1", runner_vol.display());
    let unit_dir = units.to_str().unwrap();
    let user_flag = dir.path().join("user_gecos");
    std::fs::write(&user_flag, b"").unwrap();

    // 1. Interrupted partial-uninstall with BOTH OWNED_INSTALL_DIR=1 AND STAGED_INSTALL_DIR
    //    holding the moved payload (public `inst` vacated!) and empty INSTALL_ID=:
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=partial-uninstall\nINSTALL_ID=\nSERVICE=qeminga-staged-mig\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=staged-mig\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=0\nSTAGED_UNIT=\nSTAGED_INSTALL_DIR={}\nSTAGED_HOOK_DIR=\nSTAGED_STATE_DIR=\nVOL_UNIT=\nVOL_INSTALL_DIR={legacy_vol_runner}\nVOL_HOOK_DIR={legacy_vol_root}\nVOL_STATE_DIR={legacy_vol_root}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
            staged_inst.display(),
        ),
    )
    .unwrap();
    assert!(!inst.exists(), "public runner path is vacated after rename");

    // 1a. Comment 7a: Failed `getent passwd` MUST fail closed WITHOUT invoking usermod!
    let mig_getent_fail = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-account-marker",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
            ("FAKE_GETENT_FAIL", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_getent_fail.status.success() && !usermod_log.exists(),
        "migrate-record MUST NOT authorize usermod when getent passwd fails: {}",
        text(&mig_getent_fail)
    );

    // 1b. Comment 7b: GECOS with empty first subfield but non-empty contact metadata
    //     (",Room 402,555-0100") MUST be refused WITHOUT invoking usermod!
    std::fs::write(&user_flag, ",Room 402,555-0100\n").unwrap();
    let mig_comma_gecos = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-account-marker",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_comma_gecos.status.success() && !usermod_log.exists(),
        "migrate-record MUST refuse GECOS carrying comma-separated room/contact metadata: {}",
        text(&mig_comma_gecos)
    );

    // 2. Comment 6 + Comment 8: With genuine empty GECOS "", simulate usermod failing on
    //    attempt #1: install.env MUST ALREADY persist the newly generated INSTALL_ID BEFORE
    //    usermod runs, AND retry (attempt #2) MUST reuse that EXACT SAME ID, upgrade VOL_*
    //    via the staged payload even though public `inst` is vacated, and let uninstall finish!
    std::fs::write(&user_flag, b"").unwrap();
    let mig_attempt1 = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
            "--confirm-account-marker",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
            ("FAKE_USERMOD_FAIL", "1"),
            ("FAKE_SNAP_REC", snap_rec_at_usermod.to_str().unwrap()),
            ("FAKE_REC_PATH", cfg.join("install.env").to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_attempt1.status.success(),
        "attempt #1 must fail when usermod fails"
    );
    let rec_at_usermod = std::fs::read_to_string(&snap_rec_at_usermod).unwrap_or_default();
    let persisted_id = rec_at_usermod
        .lines()
        .find_map(|l| l.strip_prefix("INSTALL_ID="))
        .unwrap_or("")
        .to_string();
    assert!(
        persisted_id.len() >= 16,
        "newly generated INSTALL_ID MUST be persisted to install.env BEFORE usermod runs:\n{rec_at_usermod}"
    );

    // Retry attempt #2 with working usermod: must stamp the EXACT SAME persisted_id and upgrade
    // the staged runner payload's VOL_INSTALL_DIR!
    let mig_attempt2 = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
            "--confirm-account-marker",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_USERMOD_LOG", usermod_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        mig_attempt2.status.success(),
        "retry migrate-record on staged payload must succeed reusing persisted INSTALL_ID: {}",
        text(&mig_attempt2)
    );
    assert_eq!(
        std::fs::read_to_string(&user_flag).unwrap().trim(),
        format!("qeminga-runner-{persisted_id}"),
        "retry MUST stamp the exact INSTALL_ID persisted before the interrupted usermod"
    );
    let rec_after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after.contains("uuid:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        "migrate-record MUST upgrade VOL_INSTALL_DIR from staged payload when OWNED_INSTALL_DIR=1 and public path is vacated:\n{rec_after}"
    );

    // Finally uninstall --purge-user reconciles the staged payload and completes cleanly!
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        uninst.status.success() && !staged_inst.exists() && !cfg.exists() && !user_flag.exists(),
        "uninstall --purge-user must cleanly finish reconciling staged payload after migrate-record: {}",
        text(&uninst)
    );
}

#[test]
fn install_and_update_reject_empty_or_incomplete_runner_tarball_before_mutating() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let empty_src = dir.path().join("empty-src");
    let partial_src = dir.path().join("partial-src");
    let valid_src = dir.path().join("valid-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &empty_src,
        &partial_src.join("bin"),
        &partial_src.join("externals"),
        &valid_src.join("bin"),
        &valid_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    write_exec(&bin.join("apt-get"), "#!/bin/sh\nexit 0\n");
    write_exec(&bin.join("dpkg"), "#!/bin/sh\nexit 0\n");
    let sc_log = dir.path().join("systemctl.log");
    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
if [ "$1" = "is-active" ]; then if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi; fi
exit 0
"#,
    );

    let make_tar = |src: &Path, name: &str| -> (PathBuf, String) {
        let tb = dir.path().join(name);
        let st = Command::new("tar")
            .args(["-czf", tb.to_str().unwrap(), "-C"])
            .arg(src)
            .arg(".")
            .status()
            .unwrap();
        assert!(st.success());
        let sha = sha256_of(&std::fs::read(&tb).unwrap());
        (tb, sha)
    };

    // Valid runner v1 bundle.
    write_exec(
        &valid_src.join("bin/Runner.Listener"),
        "#!/bin/sh\nexit 0\n",
    );
    write_exec(&valid_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&valid_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&valid_src.join("env.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &valid_src.join("config.sh"),
        r#"#!/bin/sh
dir="$(dirname "$0")"
printf '{"gitHubUrl":"https://github.com/vicaya/qeminga-kvm-controller","agentName":"bundle-box","workFolder":"%s","disableUpdate":true,"ephemeral":false}\n' "${HOME}/work" > "$dir/.runner"
exit 0
"#,
    );
    std::fs::write(valid_src.join("bin/v1-sentinel"), b"V1").unwrap();
    std::fs::write(valid_src.join("externals/v1-ext"), b"EXT").unwrap();
    let (valid_tb, valid_sha) = make_tar(&valid_src, "valid-v1.tar.gz");

    // Empty valid gzip tar archive.
    let (empty_tb, empty_sha) = make_tar(&empty_src, "empty.tar.gz");

    // Incomplete tarball: has bin/installdependencies.sh + bin/runsvc.sh, missing bin/Runner.Listener!
    write_exec(
        &partial_src.join("bin/installdependencies.sh"),
        "#!/bin/sh\necho RAN > \"${FAKE_DEPS_LOG:?}\"\nexit 0\n",
    );
    write_exec(&partial_src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&partial_src.join("run.sh"), "#!/bin/sh\nexit 0\n");
    write_exec(&partial_src.join("config.sh"), "#!/bin/sh\nexit 0\n");
    let (partial_tb, partial_sha) = make_tar(&partial_src, "partial.tar.gz");

    let deps_log = dir.path().join("deps-should-not-run.log");
    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let unit_dir = units.to_str().unwrap();

    // 1. `install` with incomplete tarball (missing bin/Runner.Listener) MUST fail BEFORE
    //    invoking bin/installdependencies.sh!
    let bad_inst = dir.path().join("bad-runner");
    let bad_state = dir.path().join("bad-state");
    let bad_hooks = dir.path().join("bad-hooks");
    let bad_cfg = dir.path().join("bad-cfg");
    let inst_bad = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "bad-bundle",
            "--service",
            "qeminga-bad-bundle",
            "--install-dir",
            bad_inst.to_str().unwrap(),
            "--state-dir",
            bad_state.to_str().unwrap(),
            "--hook-dir",
            bad_hooks.to_str().unwrap(),
            "--config-dir",
            bad_cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            partial_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", partial_tb.to_str().unwrap()),
            ("FAKE_DEPS_LOG", deps_log.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !inst_bad.status.success(),
        "install MUST reject incomplete runner bundle missing bin/Runner.Listener: {}",
        text(&inst_bad)
    );
    assert!(
        !deps_log.exists(),
        "install MUST NOT execute bin/installdependencies.sh on an incomplete runner bundle"
    );

    // 2. Install valid v1 runner, then attempt `update` with empty tarball and partial tarball:
    //    BOTH MUST fail BEFORE stopping the service and leave v1 bin/ & externals/ untouched!
    let _ = std::fs::remove_file(&user_flag);
    let _ = std::fs::remove_file(&sc_log);
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let inst_ok = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "bundle-box",
            "--service",
            "qeminga-bundle-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            valid_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", valid_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_ok.status.success(), "{}", text(&inst_ok));
    std::fs::write(&active_flag, b"1").unwrap();

    for (label, tb, sha) in [
        ("empty tarball", &empty_tb, empty_sha.as_str()),
        ("partial tarball", &partial_tb, partial_sha.as_str()),
    ] {
        let _ = std::fs::remove_file(&sc_log);
        let upd = run_setup_env(
            &[
                "update",
                "--config-dir",
                cfg.to_str().unwrap(),
                "--runner-sha256",
                sha,
            ],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", tb.to_str().unwrap()),
                ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
                ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ],
            Some(&bin),
        );
        assert!(
            !upd.status.success(),
            "update MUST reject {label} during staging: {}",
            text(&upd)
        );
        let sc_text = std::fs::read_to_string(&sc_log).unwrap_or_default();
        assert!(
            !sc_text.contains("stop "),
            "update MUST NOT stop the live service on {label}: {sc_text}"
        );
        assert!(
            inst.join("bin/v1-sentinel").exists() && inst.join("externals/v1-ext").exists(),
            "existing v1 bin/ and externals/ MUST remain intact when {label} is rejected"
        );
    }
}

#[test]
fn update_keeps_previous_runner_recoverable_across_mid_publish_failure_and_crash() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    let empty_src = dir.path().join("empty-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
        &empty_src,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    // Stateful fake systemctl: tracks active/stopped in FAKE_ACTIVE_FLAG and logs every call.
    let sc_log = dir.path().join("systemctl.log");
    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
case "$1" in
    is-active)
        if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi
        ;;
    stop)
        rm -f "${FAKE_ACTIVE_FLAG:?}"
        exit 0
        ;;
    start)
        touch "${FAKE_ACTIVE_FLAG:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let cfg_sh = runner_registration_config_script("tx-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");
    let empty_tb = dir.path().join("empty.tar.gz");
    assert!(
        Command::new("tar")
            .args(["-czf", empty_tb.to_str().unwrap(), "-C"])
            .arg(&empty_src)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let empty_sha = sha256_of(&std::fs::read(&empty_tb).unwrap());

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "tx-box",
            "--service",
            "qeminga-tx-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Part A: In-process failure AFTER the 1st replacement with v1 initially active.
    std::fs::write(&active_flag, b"1").unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let fail_mid = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_FAIL_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !fail_mid.status.success(),
        "simulated mid-publish I/O failure must fail update"
    );
    assert!(
        inst.join("bin/v1-marker").exists()
            && inst.join("externals/v1-ext").exists()
            && !inst.join("bin/v2-marker").exists()
            && !inst.join("externals/v2-ext").exists(),
        "mid-publish failure MUST restore complete v1 runner without mixing releases"
    );
    assert!(
        active_flag.exists(),
        "mid-publish failure MUST restart the originally active service: {}",
        std::fs::read_to_string(&sc_log).unwrap_or_default()
    );
    let rec_a = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_a.contains("RECORD_STATE=installed\n"),
        "install.env must return to installed after rollback:\n{rec_a}"
    );

    // Part B: Simulated hard crash (SIGKILL) AFTER the 1st replacement with v1 initially active!
    std::fs::write(&active_flag, b"1").unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let crash_mid = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !crash_mid.status.success(),
        "crash test must abort mid-publish"
    );
    assert!(
        !active_flag.exists(),
        "service was stopped before the simulated crash"
    );
    let rec_crashed = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_crashed.contains("RECORD_STATE=updating\n")
            && rec_crashed.contains("UPDATE_PHASE=publishing\n")
            && rec_crashed.contains("UPDATE_WAS_ACTIVE=1\n")
            && rec_crashed.contains("UPDATE_STAGE_DIR=")
            && rec_crashed.contains("UPDATE_STAGE_ID=")
            && rec_crashed.contains("UPDATE_BACKUP_DIR=")
            && rec_crashed.contains("UPDATE_BACKUP_ID="),
        "install.env MUST durably record updating phase, stage+backup paths/identities, and original was_active=1:\n{rec_crashed}"
    );

    // Retry #1 with invalid/empty bundle while service is stopped -> MUST restore v1, reclaim
    // the crashed stage directory, AND restart the originally active service!
    let _ = std::fs::remove_file(&sc_log);
    let retry_bad = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            empty_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", empty_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!retry_bad.status.success());
    assert!(
        inst.join("bin/v1-marker").exists()
            && inst.join("externals/v1-ext").exists()
            && !inst.join("bin/v2-marker").exists(),
        "retry after crash MUST restore previous v1 runner even when new bundle fails validation"
    );
    assert!(
        active_flag.exists(),
        "retry after crash MUST restore originally active service using persisted UPDATE_WAS_ACTIVE=1"
    );

    // Crash once more, then Retry #2 with valid v2 -> MUST complete cleanly to v2, restart
    // service, and leave zero .qeminga-update-backup.* or .qeminga-extract.* siblings!
    let crash_again = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!crash_again.status.success() && !active_flag.exists());

    let retry_ok = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(retry_ok.status.success(), "{}", text(&retry_ok));
    assert!(
        inst.join("bin/v2-marker").exists()
            && inst.join("externals/v2-ext").exists()
            && !inst.join("bin/v1-marker").exists()
            && active_flag.exists(),
        "successful retry after crash must publish v2 cleanly and restart originally active service"
    );
    let rec_done = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_done.contains("RECORD_STATE=installed\n")
            && !rec_done.contains("UPDATE_BACKUP_DIR=")
            && !rec_done.contains("UPDATE_STAGE_DIR=")
            && !rec_done.contains("UPDATE_PHASE="),
        "install.env must clear updating state after commit:\n{rec_done}"
    );
    let leftover_siblings: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".qeminga-update-backup.") || n.starts_with(".qeminga-extract."))
        .collect();
    assert!(
        leftover_siblings.is_empty(),
        "no .qeminga-update-backup.* or .qeminga-extract.* sibling may remain after final retry: {leftover_siblings:?}"
    );

    // Part C: Crash mid-publish, then run `uninstall --purge-user` -> MUST reclaim BOTH the
    // leftover `.qeminga-extract.*` stage directory AND `.qeminga-update-backup.*` backup!
    let crash_before_uninst = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!crash_before_uninst.status.success());
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        uninst.status.success() && !cfg.exists() && !inst.exists(),
        "uninstall after mid-publish crash must succeed cleanly: {}",
        text(&uninst)
    );
    let leftover_after_uninst: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".qeminga-update-backup.") || n.starts_with(".qeminga-extract."))
        .collect();
    assert!(
        leftover_after_uninst.is_empty(),
        "uninstall after mid-publish crash must reclaim both stage and backup siblings: {leftover_after_uninst:?}"
    );
}

#[test]
fn update_protects_custom_jit_workspace_and_allows_hardlinked_job_files() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let bad_v2_src = dir.path().join("bad-v2-src");
    let good_v2_src = dir.path().join("good-v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &bad_v2_src.join("bin"),
        &bad_v2_src.join("externals"),
        &bad_v2_src.join("custom-jit-work"),
        &good_v2_src.join("bin"),
        &good_v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let sc_log = dir.path().join("systemctl.log");
    write_mock_systemctl(
        &bin.join("systemctl"),
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${FAKE_SC_LOG:?}\"\nif [ \"$1\" = \"is-active\" ]; then echo inactive; exit 3; fi\nexit 0\n",
    );

    let make_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        write_exec(&src.join("bin/Runner.Listener"), "#!/bin/sh\nexit 0\n");
        write_exec(&src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
        write_exec(&src.join("run.sh"), "#!/bin/sh\nexit 0\n");
        write_exec(&src.join("env.sh"), "#!/bin/sh\nexit 0\n");
        write_exec(&src.join("config.sh"), "#!/bin/sh\nexit 0\n");
        std::fs::write(src.join(format!("bin/{tag}-tag")), tag.as_bytes()).unwrap();
        let tb = dir.path().join(name);
        let st = Command::new("tar")
            .args(["-czf", tb.to_str().unwrap(), "-C"])
            .arg(src)
            .arg(".")
            .status()
            .unwrap();
        assert!(st.success());
        let sha = sha256_of(&std::fs::read(&tb).unwrap());
        (tb, sha)
    };
    let (v1_tb, v1_sha) = make_pkg(&v1_src, "v1", "v1.tar.gz");
    std::fs::write(bad_v2_src.join("custom-jit-work/clobber.txt"), b"CLOBBER").unwrap();
    let (bad_v2_tb, bad_v2_sha) = make_pkg(&bad_v2_src, "bad-v2", "bad-v2.tar.gz");
    let (good_v2_tb, good_v2_sha) = make_pkg(&good_v2_src, "good-v2", "good-v2.tar.gz");

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let jit_file = dir.path().join("jit-in");
    std::fs::write(&jit_file, make_jit_config(REPO_URL, "custom-jit-work")).unwrap();
    std::fs::set_permissions(&jit_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "jit-ws-box",
            "--service",
            "qeminga-jit-ws",
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
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Create the custom JIT workspace with ordinary hard-linked job files inside it.
    let jit_ws = inst.join("custom-jit-work");
    std::fs::create_dir_all(&jit_ws).unwrap();
    std::fs::write(jit_ws.join("job-file-a"), b"JOB-DATA").unwrap();
    std::fs::hard_link(jit_ws.join("job-file-a"), jit_ws.join("job-file-b")).unwrap();

    // 1. Package colliding with recorded custom JIT workspace name MUST be rejected during staging!
    let _ = std::fs::remove_file(&sc_log);
    let upd_collide = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            bad_v2_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", bad_v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_collide.status.success(),
        "update MUST reject runner archive colliding with recorded custom JIT workspace name: {}",
        text(&upd_collide)
    );
    assert!(
        jit_ws.join("job-file-a").exists() && !jit_ws.join("clobber.txt").exists(),
        "custom JIT workspace MUST survive untouched when colliding package is rejected"
    );

    // 2. Clean v2 package MUST succeed even though custom-jit-work/ contains hard-linked job files!
    let upd_ok = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            good_v2_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", good_v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_ok.status.success(),
        "update MUST succeed when custom JIT workspace contains hard-linked job files: {}",
        text(&upd_ok)
    );
    assert!(
        inst.join("bin/good-v2-tag").exists()
            && jit_ws.join("job-file-a").exists()
            && jit_ws.join("job-file-b").exists(),
        "clean update must install v2 while preserving custom JIT workspace and its files"
    );

    // 3. Hard-linked file outside the JIT workspace (in package root) MUST still be rejected!
    let outside = dir.path().join("outside-file");
    std::fs::write(&outside, b"OUTSIDE").unwrap();
    std::fs::hard_link(&outside, inst.join("pkg-hardlink")).unwrap();
    let chown_reject = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-chown-tree "$2" 0 0 "" "custom-jit-work""#,
            "_",
            script().to_str().unwrap(),
            inst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !chown_reject.status.success(),
        "safe-chown-tree must STILL reject multiply linked package files outside custom-jit-work: {}",
        text(&chown_reject)
    );
}

#[test]
fn error_cleanup_verifies_stage_identity_and_preserves_replacement_mount() {
    let dir = private_tempdir();
    let stage = dir.path().join(".qeminga-extract.idtest1");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(stage.join("orig.txt"), b"ORIG").unwrap();

    // Capture exact stage identity token.
    let id_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            stage.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        id_out.status.success(),
        "fs_ops path-identity must succeed on created stage dir: {}",
        text(&id_out)
    );
    let orig_id = String::from_utf8(id_out.stdout).unwrap().trim().to_string();

    // 1. Replace the directory at the EXACT same pathname with a new inode containing precious data:
    //    fs_ops safe-rmtree-id MUST refuse deletion and leave the replacement intact!
    let moved = dir.path().join("moved-orig");
    std::fs::rename(&stage, &moved).unwrap();
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("precious.txt"), b"REPLACEMENT-DATA").unwrap();

    let reject_ino = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-rmtree-id "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage.to_str().unwrap(),
            orig_id.as_str(),
        ])
        .output()
        .unwrap();
    assert!(
        !reject_ino.status.success(),
        "safe-rmtree-id MUST refuse deleting a replacement directory with a different inode: {}",
        text(&reject_ino)
    );
    assert!(
        stage.join("precious.txt").exists(),
        "replacement directory contents MUST survive untouched when inode identity mismatches"
    );

    // 2. Restore original stage inode, but simulate parent volume change via QEMINGA_MOUNTINFO:
    //    safe-rmtree-id MUST refuse deletion when backing volume identity changed!
    std::fs::remove_dir_all(&stage).unwrap();
    std::fs::rename(&moved, &stage).unwrap();
    let mi_changed = dir.path().join("mi.changed");
    std::fs::write(
        &mi_changed,
        "29 1 8:99 / / rw,relatime shared:1 - ext4 /dev/sdz9 rw\n",
    )
    .unwrap();
    let reject_vol = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-rmtree-id "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage.to_str().unwrap(),
            orig_id.as_str(),
        ])
        .env("QEMINGA_MOUNTINFO", &mi_changed)
        .env(
            "QEMINGA_FS_UUID_MAP",
            "29=99999999-9999-9999-9999-999999999999",
        )
        .output()
        .unwrap();
    assert!(
        !reject_vol.status.success() && stage.join("orig.txt").exists(),
        "safe-rmtree-id MUST refuse deletion when backing volume changed: {}",
        text(&reject_vol)
    );

    // 3. With matching original inode, parent, mount, and volume, safe-rmtree-id removes it cleanly!
    let ok_rm = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-rmtree-id "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage.to_str().unwrap(),
            orig_id.as_str(),
        ])
        .output()
        .unwrap();
    assert!(
        ok_rm.status.success() && !stage.exists(),
        "safe-rmtree-id must remove verified original stage dir: {}",
        text(&ok_rm)
    );

    // 4. End-to-end `cmd_update` exit trap: if the staging directory is swapped for a different
    //    directory with the exact same name after staging (before publish), publication rejects it
    //    AND `cleanup_update_exit` refuses to delete the replacement directory as root!
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [&bin, &units, &rt_root] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let (tb, sha) = build_fake_runner_tarball(dir.path());
    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "trap-id-box",
            "--service",
            "qeminga-trap-id",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Mock systemctl that swaps the sibling `.qeminga-extract.*` dir during `stop`
    // for a brand-new directory with the same name containing precious data.
    let swapped_record = dir.path().join("swapped-stage-path");
    let saved_orig = dir.path().join("saved-orig-stage");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active) if [ -f "${FAKE_SWAPPED_REC:?}" ]; then echo inactive; exit 3; else echo active; exit 0; fi ;;
    stop)
        for cand in "${FAKE_PARENT_DIR:?}"/.qeminga-extract.*; do
            [ -d "$cand" ] || continue
            mv "$cand" "${FAKE_SAVED_ORIG:?}"
            mkdir -m 0700 "$cand"
            printf 'REPLACEMENT-STAGE-DATA\n' > "$cand/precious-replacement.txt"
            printf '%s\n' "$cand" > "${FAKE_SWAPPED_REC:?}"
            break
        done
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let upd_swap = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", tb.to_str().unwrap()),
            ("FAKE_PARENT_DIR", dir.path().to_str().unwrap()),
            ("FAKE_SAVED_ORIG", saved_orig.to_str().unwrap()),
            ("FAKE_SWAPPED_REC", swapped_record.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_swap.status.success(),
        "update MUST fail when stage directory was replaced before publication: {}",
        text(&upd_swap)
    );
    let swapped_path = PathBuf::from(
        std::fs::read_to_string(&swapped_record)
            .unwrap()
            .trim()
            .to_string(),
    );
    assert!(
        swapped_path.join("precious-replacement.txt").exists(),
        "cleanup_update_exit MUST verify stage identity and preserve replacement directory at {}: {}",
        swapped_path.display(),
        text(&upd_swap)
    );
}

#[test]
fn migrate_record_upgrades_root_blkid_uuid_record_to_service_readable_src_fsid() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let empty_by_uuid = dir.path().join("empty-by-uuid");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [
        &bin,
        &units,
        &rt_root,
        &empty_by_uuid,
        &inst,
        &state.join("work"),
        &state.join("images"),
        &hooks,
        &cfg,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let user_flag = dir.path().join("user_gecos");
    std::fs::write(&user_flag, "qeminga-runner-blkidmig0000000001\n").unwrap();

    // Compute the real live service-readable fingerprint of `state` when /dev/disk/by-uuid is empty.
    let live_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            state.to_str().unwrap(),
        ])
        .env("QEMINGA_BY_UUID_DIR", &empty_by_uuid)
        .output()
        .unwrap();
    assert!(live_out.status.success(), "{}", text(&live_out));
    let live_src_fsid = String::from_utf8(live_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(
        live_src_fsid.contains(",src:") && live_src_fsid.contains(",fsid:"),
        "expected src+fsid live volume fingerprint, got '{live_src_fsid}'"
    );

    // Construct the exact Round-13-style blkid UUID fingerprint (same mp, root, fs, fsid, but
    // `uuid:<blkid-uuid>` instead of `src:...`).
    let mut blkid_vol_parts = Vec::new();
    let mut orig_src = String::new();
    for field in live_src_fsid.split(',') {
        if let Some(s) = field.strip_prefix("src:") {
            orig_src = s.to_string();
            blkid_vol_parts.push("uuid:deadbeef-1111-2222-3333-444455556666".to_string());
        } else {
            blkid_vol_parts.push(field.to_string());
        }
    }
    assert!(!orig_src.is_empty());
    let old_blkid_vol = blkid_vol_parts.join(",");

    let unit_file = units.join("qeminga-blkid-mig.service");
    std::fs::write(&unit_file, "[Unit]\n").unwrap();
    let unit_dir = units.to_str().unwrap();

    let render = run_setup(&[
        "render-hooks",
        "--repo",
        REPO_URL,
        "--out",
        hooks.to_str().unwrap(),
    ]);
    assert!(render.status.success(), "{}", text(&render));

    std::fs::write(
        cfg.join("policy.env"),
        format!(
            "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work\nIMAGES_DIR={}/images\nSTATE_VOL={old_blkid_vol}\nINSTALL_VOL={old_blkid_vol}\nLIBVIRT_CONNECT=qemu:///session\n",
            inst.display(),
            state.display(),
            state.display(),
            state.display(),
        ),
    )
    .unwrap();
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=installed\nINSTALL_ID=blkidmig0000000001\nSERVICE=qeminga-blkid-mig\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=blkid-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\nVOL_UNIT={old_blkid_vol}\nVOL_INSTALL_DIR={old_blkid_vol}\nVOL_HOOK_DIR={old_blkid_vol}\nVOL_STATE_DIR={old_blkid_vol}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
        ),
    )
    .unwrap();

    // 0. Real /proc/self/mountinfo (no QEMINGA_MOUNTINFO): an inherited QEMINGA_MIGRATE_BLKID_MAP
    //    MUST be ignored so it can never spoof UUID verification on a real host!
    let mig_real_ignored = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_BY_UUID_DIR", empty_by_uuid.to_str().unwrap()),
            (
                "QEMINGA_MIGRATE_BLKID_MAP",
                &format!("{orig_src}=deadbeef-1111-2222-3333-444455556666"),
            ),
        ],
        Some(&bin),
    );
    assert!(
        !mig_real_ignored.status.success(),
        "migrate-record MUST ignore QEMINGA_MIGRATE_BLKID_MAP when reading real /proc/self/mountinfo: {}",
        text(&mig_real_ignored)
    );

    // 1. With an explicit synthetic QEMINGA_MOUNTINFO fixture for /dev/sdb1 (no QEMINGA_FS_UUID_MAP,
    //    so volume_id_of_fd produces service-readable src+fsid):
    let mi_synth = dir.path().join("mi.synth");
    std::fs::write(
        &mi_synth,
        "29 1 8:17 / / rw,relatime shared:1 - ext4 /dev/sdb1 rw\n",
    )
    .unwrap();
    let synth_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            state.to_str().unwrap(),
        ])
        .env("QEMINGA_MOUNTINFO", &mi_synth)
        .output()
        .unwrap();
    assert!(synth_out.status.success(), "{}", text(&synth_out));
    let synth_src_fsid = String::from_utf8(synth_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(
        synth_src_fsid.contains(",src:/dev/sdb1,fsid:"),
        "expected synthetic src:/dev/sdb1+fsid fingerprint, got '{synth_src_fsid}'"
    );
    let synth_old_blkid = synth_src_fsid.replace(
        ",src:/dev/sdb1,",
        ",uuid:deadbeef-1111-2222-3333-444455556666,",
    );
    let synth_wrong_fsid = format!(
        "{},fsid:ffffffffffffffff",
        synth_old_blkid.split(",fsid:").next().unwrap()
    );

    let write_records_with_vol = |vol: &str| {
        std::fs::write(
            cfg.join("policy.env"),
            format!(
                "ALLOWED_REPOSITORY=vicaya/qeminga-kvm-controller\nINSTALL_DIR={}\nSTATE_DIR={}\nWORK_DIR={}/work\nIMAGES_DIR={}/images\nSTATE_VOL={vol}\nINSTALL_VOL={vol}\nLIBVIRT_CONNECT=qemu:///session\n",
                inst.display(),
                state.display(),
                state.display(),
                state.display(),
            ),
        )
        .unwrap();
        std::fs::write(
            cfg.join("install.env"),
            format!(
                "RECORD_SCHEMA=1\nRECORD_STATE=installed\nINSTALL_ID=blkidmig0000000001\nSERVICE=qeminga-blkid-mig\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=blkid-box\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=1\nOWNED_HOOK_DIR=1\nOWNED_UNIT=1\nVOL_UNIT={vol}\nVOL_INSTALL_DIR={vol}\nVOL_HOOK_DIR={vol}\nVOL_STATE_DIR={vol}\n",
                inst.display(),
                state.display(),
                hooks.display(),
                cfg.display(),
                state.display(),
            ),
        )
        .unwrap();
    };

    // 1a. Mismatched recorded fsid MUST be refused even if UUID matches!
    write_records_with_vol(&synth_wrong_fsid);
    let mig_bad_fsid = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_synth.to_str().unwrap()),
            (
                "QEMINGA_MIGRATE_BLKID_MAP",
                "/dev/sdb1=deadbeef-1111-2222-3333-444455556666",
            ),
        ],
        Some(&bin),
    );
    assert!(
        !mig_bad_fsid.status.success(),
        "migrate-record MUST refuse blkid UUID migration when recorded fsid mismatches: {}",
        text(&mig_bad_fsid)
    );

    // 1b. Mismatched live blkid UUID MUST be refused without modifying install.env or policy.env!
    write_records_with_vol(&synth_old_blkid);
    let mig_wrong = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_synth.to_str().unwrap()),
            (
                "QEMINGA_MIGRATE_BLKID_MAP",
                "/dev/sdb1=00000000-0000-0000-0000-000000000000",
            ),
        ],
        Some(&bin),
    );
    assert!(
        !mig_wrong.status.success(),
        "migrate-record MUST refuse blkid UUID migration when live device UUID mismatches: {}",
        text(&mig_wrong)
    );

    // 2. Matching live blkid UUID + matching mp/root/fs/fsid MUST migrate BOTH install.env and
    //    policy.env to the service-readable src+fsid fingerprint!
    let mig_ok = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_synth.to_str().unwrap()),
            (
                "QEMINGA_MIGRATE_BLKID_MAP",
                "/dev/sdb1=deadbeef-1111-2222-3333-444455556666",
            ),
        ],
        Some(&bin),
    );
    assert!(
        mig_ok.status.success(),
        "migrate-record MUST upgrade verified blkid UUID record to service-readable src+fsid: {}",
        text(&mig_ok)
    );
    let rec_after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let pol_after = std::fs::read_to_string(cfg.join("policy.env")).unwrap();
    assert!(
        rec_after.contains(&format!("VOL_STATE_DIR={synth_src_fsid}\n"))
            && pol_after.contains(&format!("STATE_VOL={synth_src_fsid}\n"))
            && pol_after.contains(&format!("INSTALL_VOL={synth_src_fsid}\n")),
        "both install.env and policy.env must now hold service-readable src+fsid:\nREC:\n{rec_after}\nPOL:\n{pol_after}"
    );

    // 3. Exercise the production probe_blkid_uuid_for_migration branch directly (CUSTOM_MOUNTINFO=False):
    //    verify QEMINGA_MIGRATE_BLKID_MAP is ignored, non-/dev/ and non-block devices are rejected,
    //    mismatched major:minor is rejected without running blkid, matching S_ISBLK + major:minor
    //    (and anonymous 0:* dev) invokes `blkid -c /dev/null -o value -s UUID`, and unsafe UUID
    //    strings are rejected.
    let prod_check = Command::new("python3")
        .args([
            "-I",
            "-c",
            r#"
import os, re, stat, sys, types

script_text = open(sys.argv[1], "r", encoding="utf-8").read()
py_body = script_text.split("fs_ops() {\n", 1)[1].split("<<'PY'\n", 1)[1].split("\nop = sys.argv[1]", 1)[0]
ns = {}
exec(compile(py_body, "fs_ops", "exec"), ns)
probe = ns["probe_blkid_uuid_for_migration"]
ns["CUSTOM_MOUNTINFO"] = False

calls = []
fake_stats = {}
fake_blkid_out = "deadbeef-1111-2222-3333-444455556666\n"

def fake_stat(path):
    if path not in fake_stats:
        raise FileNotFoundError(path)
    return fake_stats[path]

def fake_run(cmd, **kwargs):
    calls.append(cmd)
    return types.SimpleNamespace(returncode=0, stdout=fake_blkid_out)

ns["os"] = types.SimpleNamespace(
    environ={"QEMINGA_MIGRATE_BLKID_MAP": "/dev/sdb1=spoofed-uuid,overlay=spoofed-overlay"},
    stat=fake_stat,
    major=os.major,
    minor=os.minor,
    path=types.SimpleNamespace(isfile=lambda p: p == "/usr/sbin/blkid"),
    access=lambda p, m: p == "/usr/sbin/blkid",
    X_OK=os.X_OK,
)
ns["subprocess"] = types.SimpleNamespace(run=fake_run, PIPE=-1, DEVNULL=-3)

# 1. Non-/dev/ source MUST be rejected even with QEMINGA_MIGRATE_BLKID_MAP set!
assert probe({"source": "overlay", "dev": "0:50"}) == ""
assert calls == []

# 2. Non-block device (char dev) MUST be rejected without invoking blkid!
fake_stats["/dev/null"] = types.SimpleNamespace(st_mode=stat.S_IFCHR | 0o666, st_rdev=os.makedev(1, 3))
assert probe({"source": "/dev/null", "dev": "1:3"}) == ""
assert calls == []

# 3. Block device with mismatched major:minor MUST be rejected without invoking blkid!
fake_stats["/dev/sdb1"] = types.SimpleNamespace(st_mode=stat.S_IFBLK | 0o660, st_rdev=os.makedev(8, 17))
assert probe({"source": "/dev/sdb1", "dev": "8:1"}) == ""
assert calls == []

# 4. Matching S_ISBLK + matching major:minor MUST run blkid -c /dev/null and return UUID (NOT spoofed map)!
assert probe({"source": "/dev/sdb1", "dev": "8:17"}) == "deadbeef-1111-2222-3333-444455556666"
assert calls == [["/usr/sbin/blkid", "-c", "/dev/null", "-o", "value", "-s", "UUID", "/dev/sdb1"]]

# 5. Anonymous 0:* dev (e.g. btrfs) with S_ISBLK MUST also probe live blkid!
calls.clear()
assert probe({"source": "/dev/sdb1", "dev": "0:42"}) == "deadbeef-1111-2222-3333-444455556666"
assert len(calls) == 1

# 6. Unsafe characters in blkid output MUST be rejected!
fake_blkid_out = "bad,fsid:evil\n"
assert probe({"source": "/dev/sdb1", "dev": "8:17"}) == ""
"#,
            script().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        prod_check.status.success(),
        "production probe_blkid_uuid_for_migration device identity checks failed: {}",
        text(&prod_check)
    );
}

#[test]
fn migrate_record_recovers_released_legacy_slot_with_absent_staging_dir() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let runner_vol = dir.path().join("runner-vol");
    let inst = runner_vol.join("runner");
    let absent_stage = runner_vol.join(".qeminga-removing.gone01");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    for d in [
        &bin,
        &units,
        &rt_root,
        &runner_vol,
        &state.join("images"),
        &hooks,
        &cfg,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);
    let user_flag = dir.path().join("user_gecos");
    std::fs::write(&user_flag, "qeminga-runner-absentstage000001\n").unwrap();

    let mi_orig = dir.path().join("mi.orig");
    std::fs::write(
        &mi_orig,
        format!(
            "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             42 29 8:17 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();
    let mi_wrong = dir.path().join("mi.wrong");
    std::fs::write(
        &mi_wrong,
        "29 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n",
    )
    .unwrap();
    let uuid_map =
        "29=00000000-0000-0000-0000-000000000001,42=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    let legacy_vol_root = "mp:/,root:/,fs:ext4,src:/dev/sda1";
    let legacy_vol_runner = format!("mp:{},root:/,fs:ext4,src:/dev/sdb1", runner_vol.display());
    let unit_dir = units.to_str().unwrap();

    // Released legacy slot (OWNED_INSTALL_DIR=0) whose STAGED_INSTALL_DIR was already deleted
    // before a crash stopped uninstall prior to clearing STAGED_INSTALL_DIR!
    assert!(!absent_stage.exists() && !inst.exists());
    std::fs::write(
        cfg.join("install.env"),
        format!(
            "RECORD_SCHEMA=1\nRECORD_STATE=partial-uninstall\nINSTALL_ID=absentstage000001\nSERVICE=qeminga-gone-stage\nUSER=qeminga-runner\nUSER_UID=995\nUSER_GID=995\nUSER_CREATED=1\nINSTALL_DIR={}\nSTATE_DIR={}\nHOOK_DIR={}\nCONFIG_DIR={}\nTARGET_URL={REPO_URL}\nRUNNER_GROUP=\nRUNNER_NAME=gone-stage\nLABELS=qeminga-kvm\nEPHEMERAL=0\nALLOW_AUTO_UPDATE=0\nWORK_DIR={}/work\nOWNED_CONFIG_DIR=1\nOWNED_STATE_DIR=1\nOWNED_INSTALL_DIR=0\nOWNED_HOOK_DIR=1\nOWNED_UNIT=0\nSTAGED_UNIT=\nSTAGED_INSTALL_DIR={}\nSTAGED_HOOK_DIR=\nSTAGED_STATE_DIR=\nVOL_UNIT=\nVOL_INSTALL_DIR={legacy_vol_runner}\nVOL_HOOK_DIR={legacy_vol_root}\nVOL_STATE_DIR={legacy_vol_root}\n",
            inst.display(),
            state.display(),
            hooks.display(),
            cfg.display(),
            state.display(),
            absent_stage.display(),
        ),
    )
    .unwrap();

    // 1. Wrong/offline parent volume MUST be refused!
    let mig_wrong = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_wrong.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        !mig_wrong.status.success(),
        "migrate-record MUST refuse absent staged legacy slot when parent volume is offline/mismatched: {}",
        text(&mig_wrong)
    );

    // 2. Original parent volume MUST verify against trusted parent and upgrade VOL_INSTALL_DIR!
    let mig_ok = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        mig_ok.status.success(),
        "migrate-record MUST upgrade released legacy slot with absent stage against original parent: {}",
        text(&mig_ok)
    );
    let rec_after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after.contains("uuid:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        "VOL_INSTALL_DIR must be upgraded to strong UUID fingerprint:\n{rec_after}"
    );

    // 3. Uninstall retry reconciles the absent STAGED_INSTALL_DIR and completes cleanly!
    let uninst = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_orig.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_map),
        ],
        Some(&bin),
    );
    assert!(
        uninst.status.success() && !cfg.exists() && !user_flag.exists(),
        "uninstall --purge-user must cleanly reconcile absent staged slot after migration: {}",
        text(&uninst)
    );
}

#[test]
fn update_keeps_previous_runner_until_replacement_starts_and_commits_before_pruning() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("start-tx-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let active_flag = dir.path().join("svc.active");
    let reject_v2_start = dir.path().join("reject-v2-start");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active)
        if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi
        ;;
    stop)
        rm -f "${FAKE_ACTIVE_FLAG:?}"
        exit 0
        ;;
    start)
        if [ -f "${FAKE_REJECT_V2:?}" ] && [ -f "${FAKE_INST_DIR:?}/bin/v2-marker" ]; then
            exit 1
        fi
        touch "${FAKE_ACTIVE_FLAG:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "start-tx-box",
            "--service",
            "qeminga-start-tx",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Part A: v1 is active, v2 fails `systemctl start` -> update MUST restore complete v1,
    // restart v1, and return install.env to RECORD_STATE=installed with zero leftover backup/stage!
    std::fs::write(&active_flag, b"1").unwrap();
    std::fs::write(&reject_v2_start, b"1").unwrap();
    let upd_start_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_start_fail.status.success(),
        "update MUST fail when replacement v2 fails to start"
    );
    assert!(
        inst.join("bin/v1-marker").exists()
            && inst.join("externals/v1-ext").exists()
            && !inst.join("bin/v2-marker").exists()
            && active_flag.exists(),
        "failed v2 startup MUST restore v1 and restart the originally active service: {}",
        text(&upd_start_fail)
    );
    let rec_after_fail = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after_fail.contains("RECORD_STATE=installed\n")
            && !rec_after_fail.contains("UPDATE_BACKUP_DIR="),
        "install.env must return to installed after v2 startup rollback:\n{rec_after_fail}"
    );

    // Part B: Crash right after UPDATE_PHASE=committed is persisted (before/during backup pruning)
    // leaves a partially deleted backup while v2 is already committed on disk. Retrying update
    // MUST finish pruning the backup cleanly without rolling back v2 or failing on missing manifest!
    std::fs::remove_file(&reject_v2_start).unwrap();
    let upd_ok_no_start = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_ok_no_start.status.success(),
        "{}",
        text(&upd_ok_no_start)
    );
    assert!(inst.join("bin/v2-marker").exists());

    // Simulate an interruption mid-prune right after commit: partially deleted backup dir (no manifest.json!)
    let partial_backup = dir.path().join(".qeminga-update-backup.prune1");
    std::fs::create_dir_all(partial_backup.join("old")).unwrap();
    std::fs::set_permissions(&partial_backup, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(partial_backup.join("old/leftover"), b"PARTIAL").unwrap();
    let bid_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            partial_backup.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(bid_out.status.success(), "{}", text(&bid_out));
    let partial_bid = String::from_utf8(bid_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let rec_installed = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_committed = rec_installed.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=committed\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={partial_bid}\nUPDATE_WAS_ACTIVE=0\n",
            partial_backup.display()
        ),
    );
    std::fs::write(cfg.join("install.env"), rec_committed).unwrap();

    let retry_after_commit = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        retry_after_commit.status.success(),
        "retry after committed backup-prune interruption must finish pruning and succeed: {}",
        text(&retry_after_commit)
    );
    assert!(
        !partial_backup.exists() && inst.join("bin/v2-marker").exists(),
        "committed backup-prune recovery must remove partial backup while keeping v2"
    );
}

#[test]
fn update_recovery_handles_interrupted_manifest_preparation_and_rejects_corrupt_manifest() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("manifest-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "manifest-box",
            "--service",
            "qeminga-manifest-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Verify setup-kvm-runner.sh publishes manifest.json via temp file + atomic rename.
    let script_text = std::fs::read_to_string(script()).unwrap();
    assert!(
        script_text.contains("manifest.json.tmp")
            && script_text.contains(r#"os.rename("manifest.json.tmp", "manifest.json""#),
        "publish_staged_payload must write/fsync manifest.json.tmp and atomically rename to manifest.json"
    );

    let capture_id = |p: &Path| -> String {
        let out = Command::new("bash")
            .args([
                "-c",
                r#"source "$1"; fs_ops path-identity "$2""#,
                "_",
                script().to_str().unwrap(),
                p.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", text(&out));
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };

    // 1. Interrupted manifest preparation: partial `manifest.json.tmp` with NO `manifest.json`
    //    and intact v1 -> retry MUST recover cleanly, publish v2, and restart originally active service!
    let prep_backup = dir.path().join(".qeminga-update-backup.prep01");
    std::fs::create_dir_all(&prep_backup).unwrap();
    std::fs::set_permissions(&prep_backup, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(prep_backup.join("manifest.json.tmp"), b"{\"displaced\":").unwrap();
    let prep_bid = capture_id(&prep_backup);

    let rec_orig = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_prep = rec_orig.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=publishing\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={prep_bid}\nUPDATE_WAS_ACTIVE=1\n",
            prep_backup.display()
        ),
    );
    std::fs::write(cfg.join("install.env"), rec_prep).unwrap();

    let retry_prep = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        retry_prep.status.success(),
        "interrupted manifest.json.tmp preparation MUST recover cleanly on retry: {}",
        text(&retry_prep)
    );
    assert!(
        !prep_backup.exists() && inst.join("bin/v2-marker").exists() && active_flag.exists(),
        "retry after interrupted manifest prep must remove temp backup, publish v2, and restart service"
    );

    // 2. Truly corrupt published `manifest.json` MUST fail closed cleanly without clearing updating state!
    let bad_backup = dir.path().join(".qeminga-update-backup.corrupt1");
    std::fs::create_dir_all(&bad_backup).unwrap();
    std::fs::set_permissions(&bad_backup, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(bad_backup.join("manifest.json"), b"{corrupt").unwrap();
    let bad_bid = capture_id(&bad_backup);
    let rec_now = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_corrupt = rec_now.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=publishing\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={bad_bid}\nUPDATE_WAS_ACTIVE=1\n",
            bad_backup.display()
        ),
    );
    std::fs::write(cfg.join("install.env"), rec_corrupt).unwrap();
    let retry_corrupt = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !retry_corrupt.status.success(),
        "corrupt published manifest.json MUST fail closed: {}",
        text(&retry_corrupt)
    );
    let rec_still_updating = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_still_updating.contains("RECORD_STATE=updating\n") && bad_backup.exists(),
        "corrupt manifest.json must preserve updating record and backup for manual inspection"
    );
}

#[test]
fn publish_and_restore_enforce_captured_directory_identities_and_phase_presence() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let forged_payload = dir.path().join("forged-payload");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &forged_payload.join("bin"),
        &forged_payload.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let fill_bundle = |src: &Path, tag: &str| {
        write_exec(&src.join("bin/Runner.Listener"), "#!/bin/sh\nexit 0\n");
        write_exec(&src.join("bin/runsvc.sh"), "#!/bin/sh\nexit 0\n");
        write_exec(&src.join("run.sh"), "#!/bin/sh\nexit 0\n");
        write_exec(&src.join("env.sh"), "#!/bin/sh\nexit 0\n");
        write_exec(
            &src.join("config.sh"),
            r#"#!/bin/sh
dir="$(dirname "$0")"
printf '{"gitHubUrl":"https://github.com/vicaya/qeminga-kvm-controller","agentName":"id-bind-box","workFolder":"%s","disableUpdate":true,"ephemeral":false}\n' "${HOME}/work" > "$dir/.runner"
exit 0
"#,
        );
        std::fs::write(src.join(format!("bin/{tag}-marker")), tag.as_bytes()).unwrap();
        std::fs::write(src.join(format!("externals/{tag}-ext")), tag.as_bytes()).unwrap();
    };
    fill_bundle(&v1_src, "v1");
    fill_bundle(&forged_payload, "FORGED");

    let v1_tb = dir.path().join("v1.tar.gz");
    assert!(
        Command::new("tar")
            .args(["-czf", v1_tb.to_str().unwrap(), "-C"])
            .arg(&v1_src)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let v1_sha = sha256_of(&std::fs::read(&v1_tb).unwrap());

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "id-bind-box",
            "--service",
            "qeminga-id-bind",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Part A: Swap `.qeminga-extract.*` during `systemctl stop` with a brand-new 0700 stage dir
    // on the SAME filesystem containing a COMPLETE, VALID forged runner bundle!
    // `publish-runner-stage` MUST reject it via captured stage identity, never publish FORGED,
    // keep v1 intact, and leave the forged stage dir untouched for inspection!
    let active_flag = dir.path().join("svc.active");
    std::fs::write(&active_flag, b"1").unwrap();
    let swapped_stage_rec = dir.path().join("swapped-stage-rec");
    let saved_orig = dir.path().join("saved-orig-stage");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop)
        rm -f "${FAKE_ACTIVE_FLAG:?}"
        for cand in "${FAKE_PARENT_DIR:?}"/.qeminga-extract.*; do
            [ -d "$cand" ] || continue
            mv "$cand" "${FAKE_SAVED_ORIG:?}"
            mkdir -m 0700 "$cand"
            cp -a "${FAKE_FORGED_PAYLOAD:?}" "$cand/payload"
            printf '%s\n' "$cand" > "${FAKE_SWAPPED_REC:?}"
            break
        done
        exit 0
        ;;
    start) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let upd_forged = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_PARENT_DIR", dir.path().to_str().unwrap()),
            ("FAKE_SAVED_ORIG", saved_orig.to_str().unwrap()),
            ("FAKE_FORGED_PAYLOAD", forged_payload.to_str().unwrap()),
            ("FAKE_SWAPPED_REC", swapped_stage_rec.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_forged.status.success(),
        "publish-runner-stage MUST reject a forged replacement stage dir with valid layout but different inode: {}",
        text(&upd_forged)
    );
    assert!(
        inst.join("bin/v1-marker").exists()
            && !inst.join("bin/FORGED-marker").exists()
            && active_flag.exists(),
        "forged stage must never be published and v1 must remain intact and active"
    );
    let swapped_stage = PathBuf::from(
        std::fs::read_to_string(&swapped_stage_rec)
            .unwrap()
            .trim()
            .to_string(),
    );
    assert!(
        swapped_stage.join("payload/bin/FORGED-marker").exists()
            && !swapped_stage.join(".qeminga-tx-id").exists(),
        "swapped forged stage dir must be left unmodified (without stamping .qeminga-tx-id) for inspection"
    );
    std::fs::remove_dir_all(&swapped_stage).unwrap();
    let _ = std::fs::remove_dir_all(&saved_orig);

    // Part B: Missing recorded backup during `UPDATE_PHASE=publishing` MUST fail closed!
    write_mock_systemctl(
        &bin.join("systemctl"),
        "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then echo inactive; exit 3; fi\nexit 0\n",
    );
    let missing_backup = dir.path().join(".qeminga-update-backup.missing1");
    std::fs::create_dir_all(&missing_backup).unwrap();
    std::fs::set_permissions(&missing_backup, std::fs::Permissions::from_mode(0o700)).unwrap();
    let bid_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            missing_backup.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(bid_out.status.success(), "{}", text(&bid_out));
    let missing_bid = String::from_utf8(bid_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    std::fs::remove_dir_all(&missing_backup).unwrap();

    let rec_now = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_missing_bk = rec_now.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=publishing\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={missing_bid}\nUPDATE_WAS_ACTIVE=1\n",
            missing_backup.display()
        ),
    );
    std::fs::write(cfg.join("install.env"), rec_missing_bk).unwrap();

    let retry_missing_bk = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !retry_missing_bk.status.success(),
        "recovery in UPDATE_PHASE=publishing MUST refuse a missing recorded backup directory: {}",
        text(&retry_missing_bk)
    );
    assert!(
        std::fs::read_to_string(cfg.join("install.env"))
            .unwrap()
            .contains("RECORD_STATE=updating\n"),
        "missing backup in publishing phase must leave updating record intact for inspection"
    );

    // Part C: Swapped backup directory (different inode at same path) during restore MUST fail closed!
    std::fs::create_dir_all(&missing_backup).unwrap();
    std::fs::set_permissions(&missing_backup, std::fs::Permissions::from_mode(0o700)).unwrap();
    let retry_swapped_bk = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !retry_swapped_bk.status.success(),
        "recovery MUST reject a replacement backup directory whose inode does not match UPDATE_BACKUP_ID: {}",
        text(&retry_swapped_bk)
    );
}

#[test]
fn reinstall_existing_runner_validates_bundle_before_mutating_and_rolls_back_on_failure() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    let empty_src = dir.path().join("empty-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
        &empty_src,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("reinst-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");
    let empty_tb = dir.path().join("empty.tar.gz");
    assert!(
        Command::new("tar")
            .args(["-czf", empty_tb.to_str().unwrap(), "-C"])
            .arg(&empty_src)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let empty_sha = sha256_of(&std::fs::read(&empty_tb).unwrap());

    let sc_log = dir.path().join("systemctl.log");
    let active_flag = dir.path().join("svc.active");
    let reject_v2_start = dir.path().join("reject-v2-start");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start | enable)
        if [ -f "${FAKE_REJECT_V2:?}" ] && [ -f "${FAKE_INST_DIR:?}/bin/v2-marker" ]; then
            exit 1
        fi
        touch "${FAKE_ACTIVE_FLAG:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let unit_dir = units.to_str().unwrap();

    let base_install_args = |sha: &str, no_start: bool| -> Vec<String> {
        let mut v = vec![
            "install".to_string(),
            "--repo".to_string(),
            REPO_URL.to_string(),
            "--name".to_string(),
            "reinst-box".to_string(),
            "--service".to_string(),
            "qeminga-reinst-box".to_string(),
            "--install-dir".to_string(),
            inst.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state.to_str().unwrap().to_string(),
            "--hook-dir".to_string(),
            hooks.to_str().unwrap().to_string(),
            "--config-dir".to_string(),
            cfg.to_str().unwrap().to_string(),
            "--token-file".to_string(),
            reg_file.to_str().unwrap().to_string(),
            "--runner-sha256".to_string(),
            sha.to_string(),
            "--skip-packages".to_string(),
        ];
        if no_start {
            v.push("--no-start".to_string());
        }
        v
    };

    let init_args = base_install_args(&v1_sha, false);
    let init_refs: Vec<&str> = init_args.iter().map(|s| s.as_str()).collect();
    let inst_v1 = run_setup_env(
        &init_refs,
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_v1.status.success(), "{}", text(&inst_v1));
    assert!(active_flag.exists());

    // Part A: Reinstall active registered runner with EMPTY tarball -> MUST fail BEFORE
    // stopping service or switching install.env out of RECORD_STATE=installed!
    let _ = std::fs::remove_file(&sc_log);
    let empty_args = base_install_args(&empty_sha, false);
    let empty_refs: Vec<&str> = empty_args.iter().map(|s| s.as_str()).collect();
    let reinst_empty = run_setup_env(
        &empty_refs,
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", empty_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !reinst_empty.status.success(),
        "reinstall with empty archive MUST fail: {}",
        text(&reinst_empty)
    );
    let sc_empty = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        !sc_empty.contains("stop ") && active_flag.exists(),
        "reinstall with empty archive MUST NOT stop the running service: {sc_empty}"
    );
    let rec_after_empty = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after_empty.contains("RECORD_STATE=installed\n"),
        "reinstall with empty archive MUST leave install.env in RECORD_STATE=installed:\n{rec_after_empty}"
    );
    assert!(
        inst.join("bin/v1-marker").exists() && inst.join("externals/v1-ext").exists(),
        "reinstall with empty archive MUST keep v1 binaries untouched"
    );

    // Part B: Reinstall active registered runner with valid v2 where mid-publish fails ->
    // MUST restore v1, restart service, and return install.env to RECORD_STATE=installed!
    let v2_args = base_install_args(&v2_sha, false);
    let v2_refs: Vec<&str> = v2_args.iter().map(|s| s.as_str()).collect();
    let reinst_mid_fail = run_setup_env(
        &v2_refs,
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_TEST_FAIL_PUBLISH_AFTER", "1"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(!reinst_mid_fail.status.success());
    assert!(
        inst.join("bin/v1-marker").exists()
            && inst.join("externals/v1-ext").exists()
            && !inst.join("bin/v2-marker").exists()
            && active_flag.exists(),
        "mid-publish failure on reinstall MUST restore v1 and restart service: {}",
        text(&reinst_mid_fail)
    );

    // Part C: Reinstall active registered runner with valid v2 AND changed policy/unit options
    // (`--cpu-quota 75%`, `--allow-event push`, `--no-lan-deny`) where v2 fails startup ->
    // MUST restore v1 binaries, pre-reinstall policy.env, hooks, launcher, AND systemd unit
    // (including file modes), run `systemctl daemon-reload` BEFORE restarting v1, and return
    // install.env to RECORD_STATE=installed!
    let unit_file = units.join("qeminga-reinst-box.service");
    let orig_unit = std::fs::read(&unit_file).unwrap();
    let orig_policy = std::fs::read(cfg.join("policy.env")).unwrap();
    let orig_hook = std::fs::read(hooks.join("hook-job-started.sh")).unwrap();
    let orig_launcher = std::fs::read(hooks.join("run-runner.sh")).unwrap();
    let orig_unit_mode = std::fs::metadata(&unit_file).unwrap().permissions().mode() & 0o777;
    let orig_policy_mode = std::fs::metadata(cfg.join("policy.env"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let orig_hook_mode = std::fs::metadata(hooks.join("hook-job-started.sh"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    let mut v2_changed_args = base_install_args(&v2_sha, false);
    v2_changed_args.extend([
        "--cpu-quota".to_string(),
        "75%".to_string(),
        "--allow-event".to_string(),
        "push".to_string(),
        "--no-lan-deny".to_string(),
    ]);
    let v2_changed_refs: Vec<&str> = v2_changed_args.iter().map(|s| s.as_str()).collect();
    let _ = std::fs::remove_file(&sc_log);
    std::fs::write(&reject_v2_start, b"1").unwrap();
    let reinst_start_fail = run_setup_env(
        &v2_changed_refs,
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(!reinst_start_fail.status.success());
    assert!(
        inst.join("bin/v1-marker").exists()
            && inst.join("externals/v1-ext").exists()
            && !inst.join("bin/v2-marker").exists()
            && active_flag.exists(),
        "startup failure on reinstall MUST restore v1 and restart service: {}",
        text(&reinst_start_fail)
    );
    assert_eq!(
        std::fs::read(&unit_file).unwrap(),
        orig_unit,
        "failed reinstall MUST restore pre-reinstall systemd unit (no leaked CPUQuota=75%)"
    );
    assert_eq!(
        std::fs::read(cfg.join("policy.env")).unwrap(),
        orig_policy,
        "failed reinstall MUST restore pre-reinstall policy.env (no leaked allowlist/DENY_LAN)"
    );
    assert_eq!(
        std::fs::read(hooks.join("hook-job-started.sh")).unwrap(),
        orig_hook,
        "failed reinstall MUST restore pre-reinstall hooks"
    );
    assert_eq!(
        std::fs::read(hooks.join("run-runner.sh")).unwrap(),
        orig_launcher,
        "failed reinstall MUST restore pre-reinstall launcher"
    );
    assert_eq!(
        std::fs::metadata(&unit_file).unwrap().permissions().mode() & 0o777,
        orig_unit_mode,
        "restored unit file must preserve its mode"
    );
    assert_eq!(
        std::fs::metadata(cfg.join("policy.env"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        orig_policy_mode,
        "restored policy.env must preserve its mode"
    );
    assert_eq!(
        std::fs::metadata(hooks.join("hook-job-started.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        orig_hook_mode,
        "restored hook must preserve its mode"
    );
    let sc_part_c = std::fs::read_to_string(&sc_log).unwrap_or_default();
    let sc_lines: Vec<&str> = sc_part_c.lines().collect();
    let last_enable_idx = sc_lines
        .iter()
        .rposition(|l| l.starts_with("enable --now "))
        .expect("reinstall must have attempted enable --now");
    let last_reload_idx = sc_lines
        .iter()
        .rposition(|l| *l == "daemon-reload")
        .expect("rollback must call systemctl daemon-reload");
    let last_start_idx = sc_lines
        .iter()
        .rposition(|l| l.starts_with("start "))
        .expect("rollback must restart v1 service");
    assert!(
        last_reload_idx > last_enable_idx && last_start_idx > last_reload_idx,
        "rollback MUST run daemon-reload AFTER failed replacement start and BEFORE restarting v1:\n{sc_part_c}"
    );
    let rec_after_rollback = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after_rollback.contains("RECORD_STATE=installed\n")
            && !rec_after_rollback.contains("UPDATE_BACKUP_DIR="),
        "install.env must return to installed after reinstall rollback:\n{rec_after_rollback}"
    );

    // Part D: Failed reinstall attempting to switch to a JIT credential (`--jitconfig-file`
    // + `--ephemeral`, after removing `.runner`) MUST remove the newly written `jitconfig`
    // and `run-jit.sh` and restore `run-runner.sh` + original unit/policy!
    std::fs::remove_file(inst.join(".runner")).unwrap();
    let jit_blob = make_jit_config(REPO_URL, &format!("{}/work", state.display()));
    let jit_in = dir.path().join("jit-in");
    std::fs::write(&jit_in, format!("{jit_blob}\n")).unwrap();
    std::fs::set_permissions(&jit_in, std::fs::Permissions::from_mode(0o600)).unwrap();
    let reinst_jit_fail = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "reinst-box",
            "--service",
            "qeminga-reinst-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--jitconfig-file",
            jit_in.to_str().unwrap(),
            "--ephemeral",
            "--cpu-quota",
            "50%",
            "--runner-sha256",
            v2_sha.as_str(),
            "--skip-packages",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_REJECT_V2", reject_v2_start.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(!reinst_jit_fail.status.success());
    assert!(
        !cfg.join("jitconfig").exists()
            && !hooks.join("run-jit.sh").exists()
            && hooks.join("run-runner.sh").exists()
            && std::fs::read(&unit_file).unwrap() == orig_unit
            && std::fs::read(cfg.join("policy.env")).unwrap() == orig_policy,
        "failed JIT reinstall rollback MUST remove newly created jitconfig/run-jit.sh and restore run-runner.sh, policy, and unit"
    );
}

#[test]
fn restore_runner_backup_is_idempotent_and_retains_verified_container_until_restored_record_is_saved()
 {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("idemp-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start | enable) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "idemp-box",
            "--service",
            "qeminga-idemp-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // 1. Direct idempotence test: call `fs_ops restore-runner-backup` TWICE on the same
    //    empty verified backup directory -> BOTH calls MUST succeed and keep the verified
    //    backup directory intact until the caller prunes it after saving `UPDATE_PHASE=restored`!
    let vol_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops volume-id "$2""#,
            "_",
            script().to_str().unwrap(),
            inst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(vol_out.status.success());
    let inst_vol = String::from_utf8(vol_out.stdout)
        .unwrap()
        .trim()
        .to_string();

    let empty_bk = dir.path().join(".qeminga-update-backup.idemp1");
    std::fs::create_dir_all(&empty_bk).unwrap();
    std::fs::set_permissions(&empty_bk, std::fs::Permissions::from_mode(0o700)).unwrap();
    let id_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            empty_bk.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(id_out.status.success(), "{}", text(&id_out));
    let bk_id = String::from_utf8(id_out.stdout).unwrap().trim().to_string();

    for attempt in 1..=2 {
        let rest = Command::new("bash")
            .args([
                "-c",
                r#"source "$1"; fs_ops restore-runner-backup "$2" "$3" "$4" "$5" "" "0""#,
                "_",
                script().to_str().unwrap(),
                inst.to_str().unwrap(),
                inst_vol.as_str(),
                empty_bk.to_str().unwrap(),
                bk_id.as_str(),
            ])
            .output()
            .unwrap();
        assert!(
            rest.status.success(),
            "restore-runner-backup attempt #{attempt} MUST succeed idempotently: {}",
            text(&rest)
        );
        assert!(
            empty_bk.exists(),
            "restore-runner-backup attempt #{attempt} MUST retain verified backup container until record write completes"
        );
    }
    std::fs::remove_dir_all(&empty_bk).unwrap();

    // 2. End-to-end failed record write during crash recovery:
    //    Crash mid-publish, then make `cfg` read-only (0500) so saving `UPDATE_PHASE=restored`
    //    fails AFTER restore-runner-backup runs -> backup container MUST stay on disk while
    //    `install.env` remains `publishing`, and once `cfg` is writable again, retrying `update`
    //    MUST succeed cleanly and prune the backup!
    std::fs::write(&active_flag, b"1").unwrap();
    let crash = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!crash.status.success());

    let rec_crashed = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let bk_path = rec_crashed
        .lines()
        .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
        .expect("UPDATE_BACKUP_DIR must be recorded")
        .to_string();
    assert!(Path::new(&bk_path).exists());

    // Make cfg read-only so writing `UPDATE_PHASE=restored` fails (when running non-root).
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o500)).unwrap();
    let retry_ro = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(
        !retry_ro.status.success(),
        "update recovery MUST fail when saving UPDATE_PHASE=restored fails"
    );
    assert!(
        Path::new(&bk_path).exists(),
        "verified backup container MUST remain on disk when saving UPDATE_PHASE=restored fails"
    );
    assert!(
        std::fs::read_to_string(cfg.join("install.env"))
            .unwrap()
            .contains("UPDATE_PHASE=publishing\n"),
        "install.env remains publishing after failed record write"
    );

    // Now that cfg is writable again, retrying `update` MUST succeed cleanly!
    let retry_ok = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        retry_ok.status.success(),
        "retry after interrupted restore record write MUST succeed cleanly: {}",
        text(&retry_ok)
    );
    assert!(
        !Path::new(&bk_path).exists()
            && inst.join("bin/v2-marker").exists()
            && active_flag.exists(),
        "successful retry must prune backup container, publish v2, and restart active service"
    );
}

#[test]
fn publishing_recovery_and_uninstall_stop_active_replacement_service_before_restoring() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("stop-first-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let sc_log = dir.path().join("sc.log");
    let active_flag = dir.path().join("svc.active");
    let fail_stop = dir.path().join("fail.stop");
    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_SC_LOG:?}"
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop)
        if [ -f "${FAKE_FAIL_STOP:?}" ]; then
            exit 1
        fi
        if [ -f "${FAKE_INST_DIR:?}/bin/v2-marker" ]; then
            printf 'STOP_SAW_V2_INTACT\n' >> "${FAKE_SC_LOG:?}"
        fi
        rm -f "${FAKE_ACTIVE_FLAG:?}"
        exit 0
        ;;
    start | enable) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "stop-first-box",
            "--service",
            "qeminga-stop-first",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_FAIL_STOP", fail_stop.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Simulate a process crash right AFTER v2 was published and started (service ACTIVE!),
    // BEFORE `UPDATE_PHASE=committed` was written: crash mid-publish after placing v2's `bin`,
    // then mark the service ACTIVE!
    let crash = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_FAIL_STOP", fail_stop.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!crash.status.success());
    assert!(inst.join("bin/v2-marker").exists());
    // Service is active (as if crash occurred after `systemctl start` before `committed`).
    std::fs::write(&active_flag, b"1").unwrap();

    // Subcase A: If `systemctl stop` FAILS, BOTH `update` and `uninstall` MUST fail closed,
    // leave the running v2 binaries untouched, and preserve `UPDATE_PHASE=publishing`!
    std::fs::write(&fail_stop, b"1").unwrap();
    let upd_stop_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_FAIL_STOP", fail_stop.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_stop_fail.status.success(),
        "update recovery MUST fail closed when stopping active replacement service fails: {}",
        text(&upd_stop_fail)
    );
    assert!(
        inst.join("bin/v2-marker").exists()
            && !inst.join("bin/v1-marker").exists()
            && std::fs::read_to_string(cfg.join("install.env"))
                .unwrap()
                .contains("UPDATE_PHASE=publishing\n"),
        "failed stop on update recovery must not touch live v2 tree or clear publishing phase"
    );

    let uninst_stop_fail = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_FAIL_STOP", fail_stop.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_stop_fail.status.success(),
        "uninstall recovery MUST fail closed when stopping active replacement service fails: {}",
        text(&uninst_stop_fail)
    );
    assert!(
        inst.join("bin/v2-marker").exists()
            && std::fs::read_to_string(cfg.join("install.env"))
                .unwrap()
                .contains("UPDATE_PHASE=publishing\n"),
        "failed stop on uninstall recovery must not touch live v2 tree or clear publishing phase"
    );

    // Subcase B: Allow `systemctl stop` to succeed -> `update` recovery MUST stop the active
    // service WHILE v2 is still intact (STOP_SAW_V2_INTACT) BEFORE restoring v1!
    std::fs::remove_file(&fail_stop).unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let upd_recover = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_FAIL_STOP", fail_stop.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(upd_recover.status.success(), "{}", text(&upd_recover));
    let sc_upd = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        sc_upd.contains("STOP_SAW_V2_INTACT"),
        "update recovery MUST stop active replacement service BEFORE restoring backup:\n{sc_upd}"
    );

    // Subcase C: Crash again leaving v2 + active service, then run `uninstall --purge-user` ->
    // MUST stop active service BEFORE restoring v1 (STOP_SAW_V2_INTACT)!
    let crash2 = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_FAIL_STOP", fail_stop.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!crash2.status.success());
    std::fs::write(&active_flag, b"1").unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let uninst_ok = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--purge-user",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_FAIL_STOP", fail_stop.to_str().unwrap()),
            ("FAKE_INST_DIR", inst.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(uninst_ok.status.success(), "{}", text(&uninst_ok));
    let sc_uninst = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        sc_uninst.contains("STOP_SAW_V2_INTACT"),
        "uninstall recovery MUST stop active replacement service BEFORE restoring backup:\n{sc_uninst}"
    );
}

#[test]
fn interrupted_update_recovers_across_remount_with_tx_marker_and_volume() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let runner_vol = dir.path().join("runner-vol");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &runner_vol,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("remount-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start | enable) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let dev_out = Command::new("/usr/bin/stat")
        .args(["-c", "%Hr:%Lr", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let root_dev = String::from_utf8(dev_out.stdout).unwrap();
    let root_dev = root_dev.trim();

    // Boot 1 mountinfo: runner_vol is mount_id 41 on /dev/sdb1 (8:20) with persistent UUID.
    let mi_boot1 = dir.path().join("mountinfo.boot1");
    std::fs::write(
        &mi_boot1,
        format!(
            "29 1 {root_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             41 29 8:20 / {} rw,relatime shared:2 - ext4 /dev/sdb1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();
    // Boot 2 mountinfo: same filesystem remounted with DIFFERENT mount_id (209),
    // DIFFERENT major:minor (8:50), and DIFFERENT block device path (/dev/sde1),
    // but identical persistent filesystem UUID.
    let mi_boot2 = dir.path().join("mountinfo.boot2");
    std::fs::write(
        &mi_boot2,
        format!(
            "29 1 {root_dev} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             209 29 8:50 / {} rw,relatime shared:7 - ext4 /dev/sde1 rw\n",
            runner_vol.display()
        ),
    )
    .unwrap();
    let uuid_boot1 =
        "29=11111111-1111-1111-1111-111111111111,41=aaaaaaaa-1111-2222-3333-444444444444";
    let uuid_boot2 =
        "29=11111111-1111-1111-1111-111111111111,209=aaaaaaaa-1111-2222-3333-444444444444";
    let uuid_wrong =
        "29=11111111-1111-1111-1111-111111111111,209=bbbbbbbb-2222-3333-4444-555555555555";

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = runner_vol.join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    // 1. Install v1 and crash update mid-publish under Boot 1 mountinfo.
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "remount-box",
            "--service",
            "qeminga-remount-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("QEMINGA_MOUNTINFO", mi_boot1.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_boot1),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    std::fs::write(&active_flag, b"").unwrap();

    let crash_out = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_boot1.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_boot1),
        ],
        Some(&bin),
    );
    assert_eq!(
        crash_out.status.code(),
        Some(99),
        "expected simulated publish crash exit 99: {}",
        text(&crash_out)
    );

    let rec_crashed = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_crashed.contains("UPDATE_PHASE=publishing\n")
            && rec_crashed.contains("tx:")
            && !rec_crashed.contains("p_mnt:")
            && !rec_crashed.contains("t_mnt:")
            && !rec_crashed.contains("p_dev:")
            && !rec_crashed.contains("t_dev:"),
        "saved cross-invocation stage/backup identity MUST bind inodes+tx marker+vol (never ephemeral mnt_id/dev):\n{rec_crashed}"
    );
    let bk_path = PathBuf::from(
        rec_crashed
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    let bk_tx_marker = bk_path.join(".qeminga-tx-id");
    assert!(
        bk_tx_marker.is_file()
            && (std::fs::metadata(&bk_tx_marker)
                .unwrap()
                .permissions()
                .mode()
                & 0o777)
                == 0o600,
        "backup container must contain a 0600 .qeminga-tx-id marker surviving remount"
    );
    let saved_tx = std::fs::read_to_string(&bk_tx_marker).unwrap();

    // 2. Wrong-volume remount (different persistent UUID) MUST fail closed.
    let wrong_vol_out = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_boot2.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_wrong),
        ],
        Some(&bin),
    );
    assert!(
        !wrong_vol_out.status.success(),
        "recovery on a different persistent volume UUID must fail closed: {}",
        text(&wrong_vol_out)
    );

    // 3. Tampering `.qeminga-tx-id` on the same volume MUST fail closed and preserve the backup.
    std::fs::write(&bk_tx_marker, "00000000000000000000000000000000\n").unwrap();
    let bad_tx_out = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_boot2.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_boot2),
        ],
        Some(&bin),
    );
    assert!(
        !bad_tx_out.status.success(),
        "recovery with mismatched .qeminga-tx-id must fail closed: {}",
        text(&bad_tx_out)
    );
    assert!(
        text(&bad_tx_out).contains("transaction identity marker mismatch"),
        "expected tx marker mismatch error: {}",
        text(&bad_tx_out)
    );
    assert!(
        std::fs::read_to_string(cfg.join("install.env"))
            .unwrap()
            .contains("UPDATE_PHASE=publishing\n"),
        "failed tx verification must keep UPDATE_PHASE=publishing for inspection"
    );
    std::fs::write(&bk_tx_marker, &saved_tx).unwrap();

    // 4. Resuming update under Boot 2 mountinfo (new mount_id 209, new dev 8:50, new /dev/sde1,
    //    same persistent UUID and valid `.qeminga-tx-id`) MUST recover cleanly and publish v2.
    let resume_out = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_MOUNTINFO", mi_boot2.to_str().unwrap()),
            ("QEMINGA_FS_UUID_MAP", uuid_boot2),
        ],
        Some(&bin),
    );
    assert!(
        resume_out.status.success(),
        "interrupted update MUST recover cleanly across remount with new mount_id/device and same UUID: {}",
        text(&resume_out)
    );
    assert!(
        inst.join("bin/v2-marker").exists()
            && !inst.join("bin/v1-marker").exists()
            && inst.join(".runner").exists()
            && active_flag.exists(),
        "remount recovery must publish v2 cleanly, preserve .runner, and restart originally active service"
    );
    let leftover: Vec<String> = std::fs::read_dir(&runner_vol)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".qeminga-update-backup.") || n.starts_with(".qeminga-extract."))
        .collect();
    assert!(
        leftover.is_empty(),
        "remount recovery must reclaim both stage and backup siblings: {leftover:?}"
    );

    // 5. Direct fs_ops check: verify changed fd_mnt_id across invocations (101 -> 999) succeeds
    //    on the same persistent volume while same-operation parent/child mnt_id mismatch (999 vs 777)
    //    still fails closed with EXDEV.
    let py_root = dir.path().join("py-mnt-check");
    std::fs::create_dir_all(&py_root).unwrap();
    let py_check = Command::new("python3")
        .args([
            "-I",
            "-c",
            r##"
import errno, os, sys

script_text = open(sys.argv[1], "r", encoding="utf-8").read()
fs_section = script_text.split("fs_ops() {\n", 1)[1].split("\nPY\n", 1)[0]
py_body = fs_section.split("<<'PY'\n", 1)[1].split("\nop = sys.argv[1]", 1)[0]
op_body = fs_section.split("\nop = sys.argv[1]", 1)[1]

root = sys.argv[2]
bk = os.path.join(root, ".qeminga-update-backup.demo")
os.makedirs(os.path.join(bk, "old"), mode=0o700)
os.chmod(bk, 0o700)
open(os.path.join(bk, "old", "marker"), "wb").write(b"v1")

def run_op(argv_args, mnt_id_val, mi_path, uuid_map):
    ns = {"__name__": "__main__"}
    old_argv = sys.argv[:]
    old_env = dict(os.environ)
    try:
        os.environ["QEMINGA_MOUNTINFO"] = mi_path
        os.environ["QEMINGA_TEST_MNT_ID"] = str(mnt_id_val)
        os.environ["QEMINGA_FS_UUID_MAP"] = uuid_map
        exec(py_body, ns)
        ns["fd_mnt_id"] = lambda fd: mnt_id_val
        sys.argv = ["fs_ops"] + argv_args
        import io
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            exec("op = sys.argv[1]" + op_body, ns)
        finally:
            sys.stdout = old_stdout
        return buf.getvalue().strip(), ns
    finally:
        sys.argv = old_argv
        os.environ.clear()
        os.environ.update(old_env)

mi1 = os.path.join(root, "mi1")
mi2 = os.path.join(root, "mi2")
open(mi1, "w").write(f"101 1 8:20 / {root} rw - ext4 /dev/sdb1 rw\n")
open(mi2, "w").write(f"999 1 8:50 / {root} rw - ext4 /dev/sde1 rw\n")

ident, _ = run_op(["path-identity", bk], 101, mi1, "101=cccccccc-1111-2222-3333-444444444444")
assert "tx:" in ident and "p_mnt:" not in ident and "t_mnt:" not in ident, ident

# Same-operation mismatch: parent mnt_id=999 vs child mnt_id=777 MUST raise EXDEV.
ns = {"__name__": "__main__"}
os.environ["QEMINGA_MOUNTINFO"] = mi2
os.environ["QEMINGA_TEST_MNT_ID"] = "999"
os.environ["QEMINGA_FS_UUID_MAP"] = "999=cccccccc-1111-2222-3333-444444444444"
exec(py_body, ns)
pfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
dfd = os.open(bk, os.O_RDONLY | os.O_DIRECTORY)
try:
    entries = ns["parse_mountinfo"]()
    parsed = ns["parse_path_identity"](ident, bk)
    try:
        ns["verify_dir_identity"](pfd, os.fstat(pfd), 999, root, dfd, os.fstat(dfd), 777, bk, parsed, entries, "test")
        raise AssertionError("same-operation parent/child mnt_id mismatch must raise EXDEV")
    except OSError as exc:
        assert exc.errno == errno.EXDEV, exc
finally:
    os.close(dfd)
    os.close(pfd)

# Cross-invocation changed mnt_id (101 -> 999) on same persistent UUID MUST succeed for safe-rmtree-id.
run_op(["safe-rmtree-id", bk, ident], 999, mi2, "999=cccccccc-1111-2222-3333-444444444444")
assert not os.path.exists(bk), "safe-rmtree-id must remove backup across changed mnt_id on same persistent volume"
"##,
            script().to_str().unwrap(),
            py_root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        py_check.status.success(),
        "direct fs_ops remount identity verification failed: {}",
        text(&py_check)
    );
}

#[test]
#[ignore = "needs root (CAP_SYS_ADMIN) for real private mount-namespace remount"]
fn privileged_interrupted_update_recovers_across_remount_in_fresh_mount_namespace() {
    let caller_user_num = String::from_utf8(
        Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    assert_eq!(
        caller_user_num, "0",
        "privileged remount test must run as root (CAP_SYS_ADMIN)"
    );

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let backing = dir.path().join("backing");
    let mount_pt = dir.path().join("mnt");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [&bin, &units, &rt_root, &backing, &mount_pt] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("remount-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);
    let (v2_tb, v2_sha) =
        build_versioned_runner_pkg(dir.path(), &v2_src, "v2", "v2.tar.gz", &cfg_sh);

    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start | enable) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();
    let path_env = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // Keep ns1 (and its bind mount M1) pinned alive until ns2 has mounted the same
    // backing directory and captured M2, so Linux cannot reuse M1's released mount ID.
    struct ChildGuard(Option<std::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                drop(child.stdin.take());
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    // Namespace 1 (real root mount namespace, private propagation — no userns needed):
    // mount backing -> mount_pt, record kernel mnt_id M1, install v1, crash update mid-publish,
    // signal readiness, and keep the bind mount pinned until stdin closes.
    let m1_file = dir.path().join("mnt_id_1");
    let ns1_ready = dir.path().join("ns1.ready");
    let ns1_log_path = dir.path().join("ns1.log");
    let ns1_stdout = std::fs::File::create(&ns1_log_path).unwrap();
    let ns1_stderr = ns1_stdout.try_clone().unwrap();
    let ns1_child = Command::new("unshare")
        .args([
            "-m",
            "--propagation",
            "private",
            "bash",
            "-c",
            &format!(
                r#"set -euo pipefail
mount --bind "$1" "$2"
python3 -c 'import os, sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY); print([l.split(":")[1].strip() for l in open(f"/proc/self/fdinfo/{{fd}}") if l.startswith("mnt_id:")][0])' "$2" > "$3"
bash "$4" install \
  --repo "{REPO_URL}" \
  --name remount-box \
  --service qeminga-remount-box \
  --install-dir "$2/runner" \
  --state-dir "$5" \
  --hook-dir "$6" \
  --config-dir "$7" \
  --token-file "$8" \
  --runner-sha256 "$9" \
  --skip-packages --no-start
: > "$FAKE_ACTIVE_FLAG"
set +e
FAKE_GOOD_TARBALL="${{10}}" QEMINGA_TEST_CRASH_PUBLISH_AFTER=1 bash "$4" update \
  --config-dir "$7" \
  --runner-sha256 "${{11}}"
rc=$?
set -e
[ "$rc" -eq 99 ]
: > "${{12}}.tmp"
mv "${{12}}.tmp" "${{12}}"
IFS= read -r _ || true
"#
            ),
            "_",
            backing.to_str().unwrap(),
            mount_pt.to_str().unwrap(),
            m1_file.to_str().unwrap(),
            script().to_str().unwrap(),
            state.to_str().unwrap(),
            hooks.to_str().unwrap(),
            cfg.to_str().unwrap(),
            reg_file.to_str().unwrap(),
            v1_sha.as_str(),
            v2_tb.to_str().unwrap(),
            v2_sha.as_str(),
            ns1_ready.to_str().unwrap(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_USER_FLAG", &user_flag)
        .env("FAKE_GOOD_TARBALL", &v1_tb)
        .env("FAKE_ACTIVE_FLAG", &active_flag)
        .env("QEMINGA_KVM_DEVICE", "/dev/null")
        .env("QEMINGA_CGROUP_CONTROLLERS", &cg_ctrls)
        .env("QEMINGA_RUNTIME_ROOT", &rt_root)
        .env("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir)
        .env("QEMINGA_AAVMF_CODE", &aavmf_code)
        .env("QEMINGA_AAVMF_VARS", &aavmf_vars)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(ns1_stdout))
        .stderr(std::process::Stdio::from(ns1_stderr))
        .spawn()
        .unwrap();
    let mut ns1_guard = ChildGuard(Some(ns1_child));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !ns1_ready.exists() {
        if let Some(status) = ns1_guard.0.as_mut().unwrap().try_wait().unwrap() {
            let _ = ns1_guard.0.take();
            let log = std::fs::read_to_string(&ns1_log_path).unwrap_or_default();
            panic!("Namespace 1 exited ({status}) before signalling readiness:\n{log}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for Namespace 1 setup+crash:\n{}",
            std::fs::read_to_string(&ns1_log_path).unwrap_or_default()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let m1 = std::fs::read_to_string(&m1_file)
        .unwrap()
        .trim()
        .to_string();

    let rec_crashed = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_crashed.contains("UPDATE_PHASE=publishing\n")
            && rec_crashed.contains("tx:")
            && !rec_crashed.contains("p_mnt:")
            && !rec_crashed.contains("t_mnt:"),
        "saved cross-invocation stage/backup identity MUST bind inodes+tx marker+vol (never ephemeral mnt_id):\n{rec_crashed}"
    );
    let bk_name = Path::new(
        rec_crashed
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    )
    .file_name()
    .unwrap()
    .to_owned();
    let bk_tx_marker = backing.join(&bk_name).join(".qeminga-tx-id");
    assert!(
        bk_tx_marker.is_file()
            && (std::fs::metadata(&bk_tx_marker)
                .unwrap()
                .permissions()
                .mode()
                & 0o777)
                == 0o600,
        "backup container must contain a 0600 .qeminga-tx-id marker surviving remount"
    );

    // Namespace 2: while ns1 still holds M1 live in the kernel, bind-mount the SAME
    // backing directory at mount_pt (guaranteed distinct kernel mnt_id M2 != M1)
    // and resume `update` -> MUST succeed cleanly!
    let m2_file = dir.path().join("mnt_id_2");
    let ns2 = Command::new("unshare")
        .args([
            "-m",
            "--propagation",
            "private",
            "bash",
            "-c",
            r#"set -euo pipefail
mount --bind "$1" "$2"
python3 -c 'import os, sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY); print([l.split(":")[1].strip() for l in open(f"/proc/self/fdinfo/{fd}") if l.startswith("mnt_id:")][0])' "$2" > "$3"
bash "$4" update \
  --config-dir "$5" \
  --runner-sha256 "$6"
"#,
            "_",
            backing.to_str().unwrap(),
            mount_pt.to_str().unwrap(),
            m2_file.to_str().unwrap(),
            script().to_str().unwrap(),
            cfg.to_str().unwrap(),
            v2_sha.as_str(),
        ])
        .env("PATH", &path_env)
        .env("FAKE_USER_FLAG", &user_flag)
        .env("FAKE_GOOD_TARBALL", &v2_tb)
        .env("FAKE_ACTIVE_FLAG", &active_flag)
        .env("QEMINGA_RUNTIME_ROOT", &rt_root)
        .env("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir)
        .env("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir)
        .output()
        .unwrap();
    assert!(
        ns2.status.success(),
        "interrupted update MUST recover cleanly across remount in fresh mount namespace: {}",
        text(&ns2)
    );
    let m2 = std::fs::read_to_string(&m2_file)
        .unwrap()
        .trim()
        .to_string();
    assert_ne!(
        m1, m2,
        "fresh mount namespace remount while M1 is pinned must produce a distinct kernel mnt_id (m1={m1}, m2={m2})"
    );
    // Release ns1's mount namespace now that M2 has been verified distinct from M1.
    let mut ns1_live = ns1_guard.0.take().unwrap();
    drop(ns1_live.stdin.take());
    let ns1_status = ns1_live.wait().unwrap();
    assert!(
        ns1_status.success(),
        "Namespace 1 failed on clean release ({ns1_status}):\n{}",
        std::fs::read_to_string(&ns1_log_path).unwrap_or_default()
    );
    assert!(
        backing.join("runner/bin/v2-marker").exists()
            && !backing.join("runner/bin/v1-marker").exists()
            && backing.join("runner/.runner").exists()
            && active_flag.exists(),
        "remount recovery must publish v2 cleanly, preserve .runner, and restart originally active service"
    );
    let leftover: Vec<String> = std::fs::read_dir(&backing)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".qeminga-update-backup.") || n.starts_with(".qeminga-extract."))
        .collect();
    assert!(
        leftover.is_empty(),
        "remount recovery must reclaim both stage and backup siblings: {leftover:?}"
    );
}

#[test]
fn fs_ops_syncs_published_package_and_records_and_propagates_fsync_errors() {
    let dir = private_tempdir();
    let py_check = Command::new("python3")
        .args([
            "-I",
            "-c",
            r##"
import errno, os, stat, sys, tempfile

script_text = open(sys.argv[1], "r", encoding="utf-8").read()
fs_section = script_text.split("fs_ops() {\n", 1)[1].split("\nPY\n", 1)[0]
py_body = fs_section.split("<<'PY'\n", 1)[1].split("\nop = sys.argv[1]", 1)[0]
op_body = fs_section.split("\nop = sys.argv[1]", 1)[1]

# 1. Verify replace-file calls os.fsync on staged file BEFORE rename and on parent dir AFTER rename,
#    and propagates OSError(EIO) from either fsync!
root = sys.argv[2]
src = os.path.join(root, ".install.env.tmp1")
dst = os.path.join(root, "install.env")
open(src, "wb").write(b"RECORD_STATE=updating\nUPDATE_PHASE=committed\n")
os.chmod(src, 0o600)

events = []
real_fsync = os.fsync
real_rename = os.rename
fail_on_sync_count = [0]
sync_calls = [0]

def spy_fsync(fd):
    sync_calls[0] += 1
    st = os.fstat(fd)
    kind = "dir" if stat.S_ISDIR(st.st_mode) else "reg"
    events.append(("fsync", kind, st.st_ino))
    if fail_on_sync_count[0] > 0 and sync_calls[0] == fail_on_sync_count[0]:
        raise OSError(errno.EIO, "simulated fsync failure")
    return real_fsync(fd)

def spy_rename(s, d, **kwargs):
    events.append(("rename", s, d))
    return real_rename(s, d, **kwargs)

def run_replace(argv, fail_at=0):
    events.clear()
    sync_calls[0] = 0
    fail_on_sync_count[0] = fail_at
    ns = {"__name__": "__main__"}
    old_argv = sys.argv
    sys.argv = ["fs_ops"] + argv
    try:
        exec(compile(py_body, "fs_ops_defs", "exec"), ns)
        ns["os"].fsync = spy_fsync
        ns["os"].rename = spy_rename
        try:
            exec(compile("op = sys.argv[1]" + op_body, "fs_ops_main", "exec"), ns)
            return 0
        except SystemExit as se:
            return se.code if isinstance(se.code, int) else 1
    finally:
        ns["os"].fsync = real_fsync
        ns["os"].rename = real_rename
        sys.argv = old_argv

rc = run_replace(["replace-file", src, dst], fail_at=0)
assert rc == 0, f"replace-file failed: {rc}"
rename_idx = [i for i, e in enumerate(events) if e[0] == "rename"]
assert len(rename_idx) == 1, f"expected 1 rename, got {events}"
reg_syncs_before = [e for e in events[:rename_idx[0]] if e[0] == "fsync" and e[1] == "reg"]
dir_syncs_after = [e for e in events[rename_idx[0]+1:] if e[0] == "fsync" and e[1] == "dir"]
assert reg_syncs_before, f"replace-file MUST fsync staged regular file BEFORE rename: {events}"
assert dir_syncs_after, f"replace-file MUST fsync parent directory AFTER rename: {events}"

# Fail on staged-file fsync -> MUST exit non-zero BEFORE rename!
src2 = os.path.join(root, ".install.env.tmp2")
open(src2, "wb").write(b"SHOULD_NOT_REPLACE\n")
os.chmod(src2, 0o600)
rc_fail1 = run_replace(["replace-file", src2, dst], fail_at=1)
assert rc_fail1 != 0, "replace-file MUST propagate file fsync failure"
assert b"SHOULD_NOT_REPLACE" not in open(dst, "rb").read(), "rename must not run when file fsync fails"
os.unlink(src2)

# Fail on parent-dir fsync -> MUST exit non-zero!
src3 = os.path.join(root, ".install.env.tmp3")
open(src3, "wb").write(b"AFTER_DIR_FSYNC_FAIL\n")
os.chmod(src3, 0o600)
rc_fail2 = run_replace(["replace-file", src3, dst], fail_at=2)
assert rc_fail2 != 0, "replace-file MUST propagate parent directory fsync failure"

# 2. Verify publish_staged_payload fsyncs published package files AND target/backup directories!
rdir = os.path.join(root, "runner")
sdir = os.path.join(root, ".qeminga-extract.sync01")
bdir = os.path.join(root, ".qeminga-update-backup.sync01")
for p in [
    os.path.join(rdir, "bin"),
    os.path.join(rdir, "externals"),
    os.path.join(sdir, "payload", "bin"),
    os.path.join(sdir, "payload", "externals"),
    bdir,
]:
    os.makedirs(p, exist_ok=True)
os.chmod(sdir, 0o700)
os.chmod(bdir, 0o700)
for base in [rdir, os.path.join(sdir, "payload")]:
    for rel in ["bin/Runner.Listener", "bin/runsvc.sh", "run.sh", "config.sh", "env.sh"]:
        fp = os.path.join(base, rel)
        open(fp, "wb").write(b"#!/bin/sh\nexit 0\n")
        os.chmod(fp, 0o755)

ns = {}
exec(compile(py_body, "fs_ops_defs", "exec"), ns)
entries = ns["parse_mountinfo"]()
mountpoints = ns["visible_mountpoints"](entries)
rfd = os.open(rdir, ns["READ_DIR_FLAGS"])
psfd = os.open(os.path.join(sdir, "payload"), ns["READ_DIR_FLAGS"])
bfd = os.open(bdir, ns["READ_DIR_FLAGS"])
pub_sync_inos = set()
def pub_spy_fsync(fd):
    pub_sync_inos.add(os.fstat(fd).st_ino)
    return real_fsync(fd)
ns["os"].fsync = pub_spy_fsync
try:
    rst = os.fstat(rfd)
    r_mnt = ns["fd_mnt_id"](rfd)
    ns["publish_staged_payload"](rfd, rst, r_mnt, rdir, psfd, sdir, mountpoints, set(), bfd=bfd)
    rdir_ino = rst.st_ino
    bin_file_ino = os.stat(os.path.join(rdir, "bin/Runner.Listener")).st_ino
    bin_dir_ino = os.stat(os.path.join(rdir, "bin")).st_ino
    assert bin_file_ino in pub_sync_inos, "publish_staged_payload MUST fsync published package files"
    assert bin_dir_ino in pub_sync_inos, "publish_staged_payload MUST fsync published subdirectories"
    assert rdir_ino in pub_sync_inos, "publish_staged_payload MUST fsync runner root directory"
finally:
    ns["os"].fsync = real_fsync
    os.close(bfd)
    os.close(psfd)
    os.close(rfd)

# 3. Verify publish_staged_payload propagates an fsync failure on published files and rolls back to v1!
rdir2 = os.path.join(root, "runner2")
sdir2 = os.path.join(root, ".qeminga-extract.sync02")
bdir2 = os.path.join(root, ".qeminga-update-backup.sync02")
for p in [
    os.path.join(rdir2, "bin"),
    os.path.join(rdir2, "externals"),
    os.path.join(sdir2, "payload", "bin"),
    os.path.join(sdir2, "payload", "externals"),
    bdir2,
]:
    os.makedirs(p, exist_ok=True)
os.chmod(sdir2, 0o700)
os.chmod(bdir2, 0o700)
for base, tag in [(rdir2, b"v1"), (os.path.join(sdir2, "payload"), b"v2")]:
    for rel in ["bin/Runner.Listener", "bin/runsvc.sh", "run.sh", "config.sh", "env.sh"]:
        fp = os.path.join(base, rel)
        open(fp, "wb").write(b"#!/bin/sh\n# " + tag + b"\nexit 0\n")
        os.chmod(fp, 0o755)
    open(os.path.join(base, "bin", "tag.txt"), "wb").write(tag)

rfd2 = os.open(rdir2, ns["READ_DIR_FLAGS"])
psfd2 = os.open(os.path.join(sdir2, "payload"), ns["READ_DIR_FLAGS"])
bfd2 = os.open(bdir2, ns["READ_DIR_FLAGS"])
rdir2_ino = os.fstat(rfd2).st_ino
def fail_rdir_fsync(fd):
    if os.fstat(fd).st_ino == rdir2_ino:
        raise OSError(errno.EIO, "simulated runner dir fsync failure")
    return real_fsync(fd)
ns["os"].fsync = fail_rdir_fsync
try:
    rst2 = os.fstat(rfd2)
    r_mnt2 = ns["fd_mnt_id"](rfd2)
    failed = False
    try:
        ns["publish_staged_payload"](rfd2, rst2, r_mnt2, rdir2, psfd2, sdir2, mountpoints, set(), bfd=bfd2)
    except OSError:
        failed = True
    assert failed, "publish_staged_payload MUST propagate fsync OSError"
    assert open(os.path.join(rdir2, "bin", "tag.txt"), "rb").read() == b"v1", "fsync failure during publish MUST restore v1 files"
finally:
    ns["os"].fsync = real_fsync
    os.close(bfd2)
    os.close(psfd2)
    os.close(rfd2)
"##,
            script().to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        py_check.status.success(),
        "fsync durability checks failed: {}",
        text(&py_check)
    );
}

#[test]
fn legacy_updating_record_without_phase_provides_actionable_diagnostic_and_guarded_migration() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("leg-upd-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active) if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo active; exit 0; else echo inactive; exit 3; fi ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start | enable) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "leg-upd-box",
            "--service",
            "qeminga-leg-upd",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            v1_sha.as_str(),
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    let rec_installed = std::fs::read_to_string(cfg.join("install.env")).unwrap();

    // Case A: Preceding schema-1 `updating` record with ONLY UPDATE_BACKUP_DIR + UPDATE_WAS_ACTIVE
    // (no UPDATE_PHASE, no UPDATE_BACKUP_ID).
    let legacy_bk = dir.path().join(".qeminga-update-backup.legacy1");
    std::fs::create_dir_all(&legacy_bk).unwrap();
    std::fs::set_permissions(&legacy_bk, std::fs::Permissions::from_mode(0o700)).unwrap();
    let rec_legacy_bk = rec_installed.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_BACKUP_DIR={}\nUPDATE_WAS_ACTIVE=1\n",
            legacy_bk.display()
        ),
    );
    std::fs::write(cfg.join("install.env"), &rec_legacy_bk).unwrap();

    // 1. `update` and `uninstall` must emit an actionable diagnostic pointing to
    //    `migrate-record --confirm-volumes` (NOT reject with `invalid UPDATE_PHASE`).
    let upd_diag = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    let upd_diag_msg = text(&upd_diag);
    assert!(
        !upd_diag.status.success()
            && upd_diag_msg.contains("migrate-record")
            && upd_diag_msg.contains("--confirm-volumes")
            && !upd_diag_msg.contains("invalid UPDATE_PHASE"),
        "update on legacy updating record must emit actionable migration diagnostic: {upd_diag_msg}"
    );
    let uninst_diag = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    let uninst_diag_msg = text(&uninst_diag);
    assert!(
        !uninst_diag.status.success()
            && uninst_diag_msg.contains("migrate-record")
            && uninst_diag_msg.contains("--confirm-volumes")
            && !uninst_diag_msg.contains("invalid UPDATE_PHASE"),
        "uninstall on legacy updating record must emit actionable migration diagnostic: {uninst_diag_msg}"
    );

    // 2. Guarded migration via `migrate-record --confirm-volumes` must refuse wrong mode (0755),
    //    and once mode is 0700 must stamp `.qeminga-tx-id` and upgrade to `UPDATE_PHASE=publishing`!
    std::fs::set_permissions(&legacy_bk, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mig_bad_mode = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !mig_bad_mode.status.success(),
        "migrate-record must refuse legacy backup directory with unsafe mode 0755: {}",
        text(&mig_bad_mode)
    );

    std::fs::set_permissions(&legacy_bk, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mig_ok = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        mig_ok.status.success(),
        "migrate-record --confirm-volumes must upgrade verified legacy updating record: {}",
        text(&mig_ok)
    );
    let rec_migrated = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_migrated.contains("UPDATE_PHASE=publishing\n")
            && rec_migrated.contains("UPDATE_BACKUP_ID=p_ino:")
            && legacy_bk.join(".qeminga-tx-id").is_file(),
        "migrated legacy updating record must carry UPDATE_PHASE=publishing, UPDATE_BACKUP_ID, and .qeminga-tx-id:\n{rec_migrated}"
    );

    let upd_after_mig = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            v2_sha.as_str(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_after_mig.status.success(),
        "update after migrating legacy updating record must succeed: {}",
        text(&upd_after_mig)
    );
    assert!(
        !legacy_bk.exists() && inst.join("bin/v2-marker").exists() && active_flag.exists(),
        "post-migration update must clean legacy backup, publish v2, and restart active service"
    );

    // Case B: Preceding schema-1 `updating` record with EMPTY `UPDATE_BACKUP_DIR=` + `UPDATE_WAS_ACTIVE=1`
    // (post-restore) -> `migrate-record --confirm-volumes` upgrades to `UPDATE_PHASE=restored`!
    let rec_now = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_legacy_empty = rec_now.replace(
        "RECORD_STATE=installed\n",
        "RECORD_STATE=updating\nUPDATE_BACKUP_DIR=\nUPDATE_WAS_ACTIVE=1\n",
    );
    std::fs::write(cfg.join("install.env"), &rec_legacy_empty).unwrap();
    let mig_empty = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        mig_empty.status.success(),
        "migrate-record must upgrade legacy post-restore empty-backup updating record: {}",
        text(&mig_empty)
    );
    let rec_empty_after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_empty_after.contains("UPDATE_PHASE=restored\n")
            && rec_empty_after.contains("UPDATE_WAS_ACTIVE=1\n"),
        "migrated empty-backup legacy updating record must be UPDATE_PHASE=restored:\n{rec_empty_after}"
    );

    // Case C: Modern `UPDATE_PHASE=publishing` record MISSING `UPDATE_BACKUP_ID` MUST STILL be
    // rejected outright (preserving strict identity enforcement for journals written by this version)!
    let rec_modern_missing_id = rec_now.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=publishing\nUPDATE_BACKUP_DIR={}\nUPDATE_WAS_ACTIVE=1\n",
            legacy_bk.display()
        ),
    );
    std::fs::write(cfg.join("install.env"), &rec_modern_missing_id).unwrap();
    let mig_modern_bad = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !mig_modern_bad.status.success(),
        "modern UPDATE_PHASE=publishing record missing UPDATE_BACKUP_ID MUST still be rejected: {}",
        text(&mig_modern_bad)
    );
}

#[test]
fn safe_rmtree_id_deletes_tx_marker_last_and_retries_after_post_marker_unlink_crash() {
    let dir = private_tempdir();
    let py_root = dir.path().join("py-rmtree");
    std::fs::create_dir_all(&py_root).unwrap();

    // Part 1: Direct fs_ops Python harness verifying deletion ordering, post-marker-unlink
    // retryability, and fail-closed substitution checks.
    let py_out = Command::new("python3")
        .args([
            "-I",
            "-c",
            r##"
import errno, io, os, sys

script_text = open(sys.argv[1], "r", encoding="utf-8").read()
fs_section = script_text.split("fs_ops() {\n", 1)[1].split("\nPY\n", 1)[0]
py_body = fs_section.split("<<'PY'\n", 1)[1].split("\nop = sys.argv[1]", 1)[0]
op_body = fs_section.split("\nop = sys.argv[1]", 1)[1]

root = sys.argv[2]

def exec_fs_op(argv_args, hook=None):
    ns = {"__name__": "__main__"}
    old_argv = sys.argv[:]
    buf = io.StringIO()
    err_buf = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        exec(py_body, ns)
        if hook is not None:
            hook(ns)
        sys.argv = ["fs_ops"] + argv_args
        sys.stdout = buf
        sys.stderr = err_buf
        rc = 0
        try:
            exec("op = sys.argv[1]" + op_body, ns)
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        return rc, buf.getvalue().strip(), err_buf.getvalue().strip()
    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout
        sys.stderr = old_stderr

# 1a. Build a private container with payload files, nested subdirs, and a nested file also
#     named `.qeminga-tx-id` inside a subdir (which must be removed with the payload while
#     the top-level `.qeminga-tx-id` is unlinked LAST).
c1 = os.path.join(root, ".qeminga-update-backup.case1")
os.makedirs(os.path.join(c1, "old", "bin"), mode=0o700)
os.makedirs(os.path.join(c1, "nested"), mode=0o700)
os.chmod(c1, 0o700)
open(os.path.join(c1, "old", "bin", "Runner.Listener"), "wb").write(b"bin")
open(os.path.join(c1, "nested", ".qeminga-tx-id"), "wb").write(b"nested-payload")
open(os.path.join(c1, "z_file"), "wb").write(b"z")
open(os.path.join(c1, "a_file"), "wb").write(b"a")

rc, ident1, err = exec_fs_op(["path-identity", c1])
assert rc == 0 and ident1, f"path-identity failed: rc={rc} err={err}"
c1_ino = os.lstat(c1).st_ino

# Simulate fsync(tfd) failure BEFORE top-level `.qeminga-tx-id` unlink, then normal ordering
# (payload deletes -> fsync(tfd) -> top-level `.qeminga-tx-id` unlink -> crash before rmdir).
events = []
real_unlink = os.unlink
real_rmdir = os.rmdir
real_fsync = os.fsync
real_fstat = os.fstat

class SimulatedCrash(BaseException):
    pass

def make_spy_hook(fail_top_fsync=False, crash_after_top_tx=False, fake_uid_ino=None):
    def spy_hook(ns):
        orig_os = ns["os"]
        class SpyOs:
            def __getattr__(self, name):
                return getattr(orig_os, name)
            def fsync(self, fd):
                st = real_fstat(fd)
                if st.st_ino == c1_ino:
                    events.append(("fsync_top_dir", st.st_ino))
                    if fail_top_fsync:
                        raise OSError(errno.EIO, "simulated dir fsync failure")
                else:
                    events.append(("fsync", st.st_ino))
                return real_fsync(fd)
            def unlink(self, path, *args, **kwargs):
                dfd = kwargs.get("dir_fd")
                is_top_tx = (
                    path == ".qeminga-tx-id"
                    and dfd is not None
                    and real_fstat(dfd).st_ino == c1_ino
                )
                events.append(("unlink_top_tx" if is_top_tx else "unlink", path))
                real_unlink(path, *args, **kwargs)
                if crash_after_top_tx and is_top_tx:
                    raise SimulatedCrash("crash right after top-level tx marker unlink")
            def rmdir(self, path, *args, **kwargs):
                events.append(("rmdir", path))
                return real_rmdir(path, *args, **kwargs)
            def fstat(self, fd):
                st = real_fstat(fd)
                if fake_uid_ino is not None and st.st_ino == fake_uid_ino:
                    vals = list(st)
                    vals[4] = os.geteuid() + 1  # st_uid mismatch
                    return os.stat_result(vals)
                return st
        ns["os"] = SpyOs()
    return spy_hook

# 1a-i. Persistence boundary: failing os.fsync(tfd) after payload cleanup MUST propagate EIO
#       while `.qeminga-tx-id` is STILL present on disk!
rc_sync_fail, _, err_sync_fail = exec_fs_op(
    ["safe-rmtree-id", c1, ident1],
    hook=make_spy_hook(fail_top_fsync=True, crash_after_top_tx=False),
)
assert rc_sync_fail != 0, f"fsync(tfd) failure MUST propagate non-zero exit: events={events}"
assert "simulated dir fsync failure" in err_sync_fail, err_sync_fail
assert os.path.isdir(c1) and os.listdir(c1) == [".qeminga-tx-id"], (
    f"marker MUST remain intact when dir fsync fails after payload clearing: {os.listdir(c1) if os.path.isdir(c1) else 'missing'}"
)
assert ("fsync_top_dir", c1_ino) in events, f"expected fsync(tfd) after payload removal: {events}"
assert ("unlink_top_tx", ".qeminga-tx-id") not in events, (
    f"marker must NOT be unlinked when fsync(tfd) fails: {events}"
)

# Re-add payload and verify full ordering: payload unlinks -> fsync(tfd) -> unlink(.qeminga-tx-id).
open(os.path.join(c1, "retry_payload"), "wb").write(b"p")
events.clear()
crashed = False
try:
    exec_fs_op(
        ["safe-rmtree-id", c1, ident1],
        hook=make_spy_hook(fail_top_fsync=False, crash_after_top_tx=True),
    )
except SimulatedCrash:
    crashed = True
assert crashed, f"expected SimulatedCrash right after top-level .qeminga-tx-id unlink; events={events}"
assert events[-1] == ("unlink_top_tx", ".qeminga-tx-id"), (
    f"top-level .qeminga-tx-id MUST be unlinked LAST after all payload deletions: {events}"
)
payload_idx = events.index(("unlink", "retry_payload"))
fsync_idx = events.index(("fsync_top_dir", c1_ino))
tx_idx = events.index(("unlink_top_tx", ".qeminga-tx-id"))
assert payload_idx < fsync_idx < tx_idx, (
    f"expected payload unlink < fsync(tfd) < marker unlink, got {events}"
)
assert os.path.isdir(c1) and os.listdir(c1) == [], (
    f"after post-marker-unlink crash, container must be empty and still exist: {os.listdir(c1) if os.path.isdir(c1) else 'missing'}"
)

# Retry safe-rmtree-id on the exact same empty container -> MUST succeed!
rc_retry, _, err_retry = exec_fs_op(["safe-rmtree-id", c1, ident1])
assert rc_retry == 0, f"retry after post-marker-unlink crash MUST succeed: rc={rc_retry} err={err_retry}"
assert not os.path.exists(c1), "container must be removed after retry"

# 1b. Security: missing `.qeminga-tx-id` on a NON-EMPTY directory (same inode, 0700) MUST fail closed!
c2 = os.path.join(root, ".qeminga-update-backup.case2")
os.makedirs(c2, mode=0o700)
os.chmod(c2, 0o700)
open(os.path.join(c2, "important.dat"), "wb").write(b"keep-me")
rc, ident2, err = exec_fs_op(["path-identity", c2])
assert rc == 0, err
os.unlink(os.path.join(c2, ".qeminga-tx-id"))
rc_nonempty, _, err_nonempty = exec_fs_op(["safe-rmtree-id", c2, ident2])
assert rc_nonempty != 0, "missing .qeminga-tx-id on non-empty dir MUST fail closed"
assert "missing transaction identity marker" in err_nonempty, err_nonempty
assert os.path.isfile(os.path.join(c2, "important.dat")), "payload must remain untouched"

# 1c. Security: tampered `.qeminga-tx-id` MUST fail closed!
open(os.path.join(c2, ".qeminga-tx-id"), "wb").write(b"00000000000000000000000000000000\n")
os.chmod(os.path.join(c2, ".qeminga-tx-id"), 0o600)
rc_tamper, _, err_tamper = exec_fs_op(["safe-rmtree-id", c2, ident2])
assert rc_tamper != 0 and "transaction identity marker mismatch" in err_tamper, err_tamper

# 1d. Security: substituted EMPTY directory with DIFFERENT inode MUST fail closed!
c3 = os.path.join(root, ".qeminga-update-backup.case3")
os.makedirs(c3, mode=0o700)
os.chmod(c3, 0o700)
rc, ident3, err = exec_fs_op(["path-identity", c3])
assert rc == 0, err
os.unlink(os.path.join(c3, ".qeminga-tx-id"))
# Hold old inode alive via a renamed sibling so new directory gets a strictly distinct inode.
c3_old = os.path.join(root, ".qeminga-hold-old-inode")
os.rename(c3, c3_old)
os.makedirs(c3, mode=0o700)
os.chmod(c3, 0o700)
assert os.lstat(c3).st_ino != os.lstat(c3_old).st_ino
rc_diff_ino, _, err_diff_ino = exec_fs_op(["safe-rmtree-id", c3, ident3])
assert rc_diff_ino != 0 and "directory inode changed" in err_diff_ino, err_diff_ino
assert os.path.isdir(c3), "substituted empty dir with different inode must not be removed"

# 1e. Security: relaxed mode (0750 / 0770) OR wrong owner MUST fail closed EVEN WHEN
#     a genuine `.qeminga-tx-id` marker is present, preserving ALL payload files!
c4_marked = os.path.join(root, ".qeminga-update-backup.case4-marked")
os.makedirs(os.path.join(c4_marked, "sub"), mode=0o700)
os.chmod(c4_marked, 0o700)
open(os.path.join(c4_marked, "keep.txt"), "wb").write(b"precious")
open(os.path.join(c4_marked, "sub", "nested.txt"), "wb").write(b"nested-precious")
rc, ident4m, err = exec_fs_op(["path-identity", c4_marked])
assert rc == 0, err
for bad_mode in (0o750, 0o770, 0o755):
    os.chmod(c4_marked, bad_mode)
    rc_bad_m, _, err_bad_m = exec_fs_op(["safe-rmtree-id", c4_marked, ident4m])
    assert rc_bad_m != 0, f"safe-rmtree-id MUST reject marked dir with mode {oct(bad_mode)}"
    assert "must be owned by current user with mode 0700" in err_bad_m, err_bad_m
    assert os.path.isfile(os.path.join(c4_marked, "keep.txt")), "payload must remain untouched on relaxed mode"
    assert os.path.isfile(os.path.join(c4_marked, "sub", "nested.txt")), "nested payload must remain untouched"
    assert os.path.isfile(os.path.join(c4_marked, ".qeminga-tx-id")), "marker must remain untouched"

# Owner mismatch with mode 0700 and genuine marker MUST also fail closed and preserve payload!
os.chmod(c4_marked, 0o700)
c4m_ino = os.lstat(c4_marked).st_ino
rc_bad_owner, _, err_bad_owner = exec_fs_op(
    ["safe-rmtree-id", c4_marked, ident4m],
    hook=make_spy_hook(fake_uid_ino=c4m_ino),
)
assert rc_bad_owner != 0, "safe-rmtree-id MUST reject marked dir owned by another user"
assert "must be owned by current user with mode 0700" in err_bad_owner, err_bad_owner
assert os.path.isfile(os.path.join(c4_marked, "keep.txt")), "payload must remain untouched on owner mismatch"

# Empty directory with SAME inode, missing marker, and relaxed mode (0755) MUST also fail closed!
c4 = os.path.join(root, ".qeminga-update-backup.case4")
os.makedirs(c4, mode=0o700)
os.chmod(c4, 0o700)
rc, ident4, err = exec_fs_op(["path-identity", c4])
assert rc == 0, err
os.unlink(os.path.join(c4, ".qeminga-tx-id"))
os.chmod(c4, 0o755)
rc_mode, _, err_mode = exec_fs_op(["safe-rmtree-id", c4, ident4])
assert rc_mode != 0 and "must be owned by current user with mode 0700" in err_mode, err_mode
assert os.path.isdir(c4), "non-0700 empty dir without marker must not be removed"

# 1f. Security: non-delete op (`restore-runner-backup`) on an empty 0700 dir missing `.qeminga-tx-id`
#     MUST STILL fail closed (allow_empty_missing_tx is strictly limited to safe-rmtree-id).
os.chmod(c4, 0o700)
fake_runner = os.path.join(root, "runner")
os.makedirs(fake_runner, mode=0o755)
rc_vol, vol_id, err_vol = exec_fs_op(["volume-id", fake_runner])
assert rc_vol == 0 and vol_id, err_vol
rc_restore, _, err_restore = exec_fs_op(["restore-runner-backup", fake_runner, vol_id, c4, ident4, "", "0"])
assert rc_restore != 0 and "missing transaction identity marker" in err_restore, err_restore

# 1g. Stage retirement persistence boundary (`publish-runner-stage`): must fsync(sfd) after
#     rmdir("payload") and BEFORE unlinking `.qeminga-tx-id`, propagating EIO with marker intact!
def make_stage_payload(stage_path, tag):
    os.makedirs(os.path.join(stage_path, "payload", "bin"), mode=0o700)
    os.makedirs(os.path.join(stage_path, "payload", "externals"), mode=0o700)
    os.chmod(stage_path, 0o700)
    for rel in ("bin/Runner.Listener", "bin/runsvc.sh", "config.sh", "run.sh", "env.sh"):
        p = os.path.join(stage_path, "payload", rel)
        open(p, "wb").write(b"#!/bin/sh\nexit 0\n")
        os.chmod(p, 0o755)
    open(os.path.join(stage_path, "payload", "bin", f"{tag}-bin"), "wb").write(tag.encode())

st_dir = os.path.join(root, ".qeminga-extract.stage-sync")
make_stage_payload(st_dir, "v2")
bk_dir = os.path.join(root, ".qeminga-update-backup.stage-sync")
os.makedirs(bk_dir, mode=0o700)
os.chmod(bk_dir, 0o700)
rc_si, st_ident, err_si = exec_fs_op(["path-identity", st_dir])
assert rc_si == 0, err_si
rc_bi, bk_ident, err_bi = exec_fs_op(["path-identity", bk_dir])
assert rc_bi == 0, err_bi
st_ino = os.lstat(st_dir).st_ino
st_events = []

def stage_sync_hook(target_ino, fail_stage_sync):
    def hook(ns):
        orig_os = ns["os"]
        class StageSpyOs:
            def __getattr__(self, name):
                return getattr(orig_os, name)
            def rmdir(self, path, *args, **kwargs):
                dfd = kwargs.get("dir_fd")
                if path == "payload" and dfd is not None and real_fstat(dfd).st_ino == target_ino:
                    st_events.append("rmdir_payload")
                return real_rmdir(path, *args, **kwargs)
            def fsync(self, fd):
                if real_fstat(fd).st_ino == target_ino:
                    st_events.append("fsync_stage_dir")
                    if fail_stage_sync:
                        raise OSError(errno.EIO, "simulated stage dir fsync failure")
                return real_fsync(fd)
            def unlink(self, path, *args, **kwargs):
                dfd = kwargs.get("dir_fd")
                if path == ".qeminga-tx-id" and dfd is not None and real_fstat(dfd).st_ino == target_ino:
                    st_events.append("unlink_stage_tx")
                return real_unlink(path, *args, **kwargs)
        ns["os"] = StageSpyOs()
    return hook

rc_sw_fail, _, err_sw_fail = exec_fs_op(
    ["publish-runner-stage", fake_runner, vol_id, st_dir, st_ident, bk_dir, bk_ident, ""],
    hook=stage_sync_hook(st_ino, fail_stage_sync=True),
)
assert rc_sw_fail != 0 and "simulated stage dir fsync failure" in err_sw_fail, (
    f"publish-runner-stage MUST propagate stage dir fsync error: rc={rc_sw_fail} err={err_sw_fail} events={st_events}"
)
assert st_events == ["rmdir_payload", "fsync_stage_dir"], f"unexpected stage sync events: {st_events}"
assert os.path.isdir(st_dir) and os.listdir(st_dir) == [".qeminga-tx-id"], (
    f"stage marker must stay intact when stage dir fsync fails: {os.listdir(st_dir) if os.path.isdir(st_dir) else 'missing'}"
)
# And verify normal publish-runner-stage ordering: rmdir_payload -> fsync_stage_dir -> unlink_stage_tx!
st_dir2 = os.path.join(root, ".qeminga-extract.stage-sync-ok")
make_stage_payload(st_dir2, "v3")
bk_dir2 = os.path.join(root, ".qeminga-update-backup.stage-sync-ok")
os.makedirs(bk_dir2, mode=0o700)
os.chmod(bk_dir2, 0o700)
rc_si2, st_ident2, err_si2 = exec_fs_op(["path-identity", st_dir2])
assert rc_si2 == 0, err_si2
rc_bi2, bk_ident2, err_bi2 = exec_fs_op(["path-identity", bk_dir2])
assert rc_bi2 == 0, err_bi2
st_ino2 = os.lstat(st_dir2).st_ino
st_events.clear()
rc_sw_ok, _, err_sw_ok = exec_fs_op(
    ["publish-runner-stage", fake_runner, vol_id, st_dir2, st_ident2, bk_dir2, bk_ident2, ""],
    hook=stage_sync_hook(st_ino2, fail_stage_sync=False),
)
assert rc_sw_ok == 0, f"publish-runner-stage normal sync failed: {err_sw_ok}"
assert st_events == ["rmdir_payload", "fsync_stage_dir", "unlink_stage_tx"], (
    f"expected rmdir_payload -> fsync_stage_dir -> unlink_stage_tx, got {st_events}"
)
assert not os.path.exists(st_dir2), "stage dir must be removed after normal retirement"
"##,
            script().to_str().unwrap(),
            py_root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        py_out.status.success(),
        "safe-rmtree-id post-marker-unlink retry/security harness failed: {}",
        text(&py_out)
    );

    // Part 2: End-to-end `setup-kvm-runner.sh` committed-update recovery AND uninstall recovery
    // when the recorded backup container was left empty right after `.qeminga-tx-id` unlink.
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("prune-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "prune-box",
            "--service",
            "qeminga-prune-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Create a genuine backup container stamped with path-identity, then simulate interruption
    // right after `.qeminga-tx-id` unlink (empty 0700 dir with matching inode) in `committed` phase.
    let bk_upd = dir.path().join(".qeminga-update-backup.posttx1");
    std::fs::create_dir(&bk_upd).unwrap();
    std::fs::set_permissions(&bk_upd, std::fs::Permissions::from_mode(0o700)).unwrap();
    let id_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            bk_upd.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(id_out.status.success(), "{}", text(&id_out));
    let bk_upd_id = String::from_utf8(id_out.stdout).unwrap().trim().to_string();
    std::fs::remove_file(bk_upd.join(".qeminga-tx-id")).unwrap();

    let rec_orig = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_committed = rec_orig.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=committed\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={}\nUPDATE_WAS_ACTIVE=0\n",
            bk_upd.display(),
            bk_upd_id
        ),
    );
    std::fs::write(cfg.join("install.env"), &rec_committed).unwrap();

    let upd_out = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_out.status.success(),
        "committed-update recovery must finish pruning an empty post-marker-unlink backup container: {}",
        text(&upd_out)
    );
    assert!(
        !bk_upd.exists(),
        "post-marker-unlink backup must be removed"
    );
    assert!(inst.join("bin/v2-marker").exists());

    // Now test `uninstall` against an empty post-marker-unlink backup container in `committed` phase.
    let bk_uninst = dir.path().join(".qeminga-update-backup.posttx2");
    std::fs::create_dir(&bk_uninst).unwrap();
    std::fs::set_permissions(&bk_uninst, std::fs::Permissions::from_mode(0o700)).unwrap();
    let id_out2 = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            bk_uninst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(id_out2.status.success(), "{}", text(&id_out2));
    let bk_uninst_id = String::from_utf8(id_out2.stdout)
        .unwrap()
        .trim()
        .to_string();
    std::fs::remove_file(bk_uninst.join(".qeminga-tx-id")).unwrap();

    let rec_after_upd = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_uninst = rec_after_upd.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=committed\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={}\nUPDATE_WAS_ACTIVE=0\n",
            bk_uninst.display(),
            bk_uninst_id
        ),
    );
    std::fs::write(cfg.join("install.env"), &rec_uninst).unwrap();

    let uninst_out = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        uninst_out.status.success(),
        "uninstall must finish pruning an empty post-marker-unlink backup container: {}",
        text(&uninst_out)
    );
    assert!(
        !bk_uninst.exists(),
        "uninstall must remove empty post-marker-unlink backup container"
    );

    // Part 3: Stage retirement after publication (`publish-runner-stage` interrupted right after
    // unlinking `.qeminga-tx-id` inside `sfd` and before `os.rmdir(stage_base)`): the now-empty
    // 0700 stage container with matching recorded identity MUST also be reclaimed cleanly by
    // `safe-rmtree-id` during recovery.
    let stg_empty = dir.path().join(".qeminga-extract.posttx3");
    std::fs::create_dir(&stg_empty).unwrap();
    std::fs::set_permissions(&stg_empty, std::fs::Permissions::from_mode(0o700)).unwrap();
    let stg_id_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            stg_empty.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(stg_id_out.status.success(), "{}", text(&stg_id_out));
    let stg_id = String::from_utf8(stg_id_out.stdout)
        .unwrap()
        .trim()
        .to_string();
    std::fs::remove_file(stg_empty.join(".qeminga-tx-id")).unwrap();
    let stg_prune = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-rmtree-id "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stg_empty.to_str().unwrap(),
            &stg_id,
        ])
        .output()
        .unwrap();
    assert!(
        stg_prune.status.success() && !stg_empty.exists(),
        "empty post-marker-unlink stage dir left by interrupted stage retirement must be reclaimed: {}",
        text(&stg_prune)
    );
}

#[test]
fn reinstall_refuses_in_place_re_enrollment_when_runner_registration_missing() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_invoked = dir.path().join("config_sh.invoked");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        let cfg_sh = format!(
            r#"#!/bin/sh
dir="$(dirname "$0")"
if [ -n "${{FAKE_CFG_LOG:-}}" ]; then printf '{tag}\n' >> "$FAKE_CFG_LOG"; fi
printf '{{"gitHubUrl":"{REPO_URL}","agentName":"reg-box","workFolder":"%s","disableUpdate":true,"ephemeral":false}}\n' "${{HOME}}/work" > "$dir/.runner"
printf 'creds-{tag}\n' > "$dir/.credentials"
exit 0
"#
        );
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let active_flag = dir.path().join("svc.active");
    let sc_log = dir.path().join("sc.log");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ -n "${FAKE_SC_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_SC_LOG"; fi
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active)
        if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo "active"; exit 0; else echo "inactive"; exit 3; fi
        ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start | enable) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "reg-box",
            "--service",
            "qeminga-reg-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_CFG_LOG", cfg_invoked.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    std::fs::write(&active_flag, b"").unwrap();
    let _ = std::fs::remove_file(&cfg_invoked);
    let _ = std::fs::remove_file(&sc_log);

    // Simulate missing `.runner` (while leaving `.credentials` behind first, then removing both).
    std::fs::remove_file(inst.join(".runner")).unwrap();

    // 1. Switching to --jitconfig-file while stray `.credentials` remains MUST be refused.
    let jit_file = dir.path().join("jit-in");
    std::fs::write(&jit_file, make_jit_config(REPO_URL, "_work")).unwrap();
    std::fs::set_permissions(&jit_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let jit_stray_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "reg-box",
            "--service",
            "qeminga-reg-box",
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
            &v2_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !jit_stray_out.status.success(),
        "provisioning JIT runner while persistent .credentials remains must be refused: {}",
        text(&jit_stray_out)
    );

    // 2. Remove `.credentials` too -> no pre-existing registration files. Attempting in-place
    //    reinstall with `--token-file` MUST fail closed before invoking config.sh --replace or
    //    stopping the service, directing the operator to uninstall before re-enrolling.
    std::fs::remove_file(inst.join(".credentials")).unwrap();
    let reinst_no_reg = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "reg-box",
            "--service",
            "qeminga-reg-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--skip-packages",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_CFG_LOG", cfg_invoked.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    let out_msg = text(&reinst_no_reg);
    assert!(
        !reinst_no_reg.status.success(),
        "in-place reinstall without matching .runner must refuse remote re-registration: {out_msg}"
    );
    assert!(
        out_msg.contains("uninstall") && out_msg.contains(".runner"),
        "refusal must explain why in-place re-registration is refused and direct to uninstall: {out_msg}"
    );
    assert!(
        !cfg_invoked.exists()
            && !inst.join(".runner").exists()
            && !inst.join(".credentials").exists(),
        "refused reinstall must NEVER invoke config.sh or create new registration files"
    );
    assert!(
        inst.join("bin/v1-marker").exists()
            && !inst.join("bin/v2-marker").exists()
            && active_flag.exists()
            && !std::fs::read_to_string(&sc_log)
                .unwrap_or_default()
                .contains("stop "),
        "refused reinstall must leave v1 binaries and running service completely untouched"
    );

    // 3. Remove the ENTIRE runner directory on the same backing volume while `install.env`
    //    still records `RECORD_STATE=installed` and `OWNED_INSTALL_DIR=1`. Attempting
    //    in-place reinstall with `--token-file` MUST STILL fail closed without recreating
    //    the directory, mutating `install.env`, or invoking `config.sh --replace`.
    let orig_record = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    std::fs::remove_dir_all(&inst).unwrap();
    assert!(!inst.exists());
    let reinst_missing_dir = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "reg-box",
            "--service",
            "qeminga-reg-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--skip-packages",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_CFG_LOG", cfg_invoked.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    let missing_dir_msg = text(&reinst_missing_dir);
    assert!(
        !reinst_missing_dir.status.success(),
        "in-place reinstall when entire owned runner directory is missing must refuse re-enrollment: {missing_dir_msg}"
    );
    assert!(
        missing_dir_msg.contains("uninstall")
            && missing_dir_msg.contains(".runner")
            && missing_dir_msg.contains("Settings -> Actions -> Runners")
            && missing_dir_msg.contains("reg-box")
            && missing_dir_msg.contains(REPO_URL),
        "refusal on missing runner dir must direct operator to uninstall local state and remove runner in GitHub Settings -> Actions -> Runners: {missing_dir_msg}"
    );
    assert!(
        !cfg_invoked.exists() && !inst.exists(),
        "refused reinstall on missing runner dir must NEVER recreate dir or invoke config.sh"
    );
    assert_eq!(
        std::fs::read_to_string(cfg.join("install.env")).unwrap(),
        orig_record,
        "original install.env record must survive intact when re-enrollment is refused on missing dir"
    );

    // 4. Following the instruction with `uninstall --token-file` while the owned runner directory
    //    is gone cannot run local `config.sh remove`; it MUST warn with the recorded runner name,
    //    recorded target URL, and manual GitHub Settings -> Actions -> Runners instructions
    //    before discarding the local record.
    let uninst_missing_dir = run_setup_env(
        &[
            "uninstall",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    let uninst_missing_msg = text(&uninst_missing_dir);
    assert!(
        uninst_missing_dir.status.success(),
        "uninstall with missing runner dir should clear local state: {uninst_missing_msg}"
    );
    assert!(
        uninst_missing_msg.contains("Settings -> Actions -> Runners")
            && uninst_missing_msg.contains("reg-box")
            && uninst_missing_msg.contains(REPO_URL),
        "uninstall --token-file without executable config.sh MUST direct operator to remove recorded runner 'reg-box' for '{REPO_URL}' in GitHub Settings -> Actions -> Runners: {uninst_missing_msg}"
    );
    let post_uninst_rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        !units.join("qeminga-reg-box.service").exists()
            && post_uninst_rec.contains("RECORD_STATE=user-only\n")
            && !post_uninst_rec.contains("RUNNER_NAME="),
        "uninstall with missing runner dir should remove local unit and clear runner record after warning:\n{post_uninst_rec}"
    );
}

#[test]
fn update_and_reinstall_preserve_backup_when_publishing_record_dir_fsync_fails_after_rename() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    // 1. Direct `fs_ops replace-file` check: post-rename parent dir fsync failure MUST return
    //    distinct exit code 86 while leaving destination published with the new bytes.
    let rf_dir = dir.path().join("rf");
    std::fs::create_dir_all(&rf_dir).unwrap();
    let rf_src = rf_dir.join(".install.env.tmp");
    let rf_dst = rf_dir.join("install.env");
    std::fs::write(&rf_dst, b"OLD\n").unwrap();
    std::fs::write(&rf_src, b"NEW\n").unwrap();
    let rf_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops replace-file "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            rf_src.to_str().unwrap(),
            rf_dst.to_str().unwrap(),
        ])
        .env("QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC", "install.env")
        .output()
        .unwrap();
    assert_eq!(
        rf_out.status.code(),
        Some(86),
        "replace-file post-rename parent dir fsync failure must exit 86: {}",
        text(&rf_out)
    );
    assert_eq!(std::fs::read(&rf_dst).unwrap(), b"NEW\n");
    assert!(!rf_src.exists());

    let cfg_sh = runner_registration_config_script("fsync-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let active_flag = dir.path().join("svc.active");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active)
        if [ -f "${FAKE_ACTIVE_FLAG:?}" ]; then echo "active"; exit 0; else echo "inactive"; exit 3; fi
        ;;
    stop) rm -f "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    start | enable) touch "${FAKE_ACTIVE_FLAG:?}"; exit 0 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "fsync-box",
            "--service",
            "qeminga-fsync-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    std::fs::write(&active_flag, b"").unwrap();

    // 2. Lifecycle `update`: inject parent-dir fsync EIO AFTER rename on the first `publishing`
    //    record write -> exit trap MUST retain the recorded backup so normal retry succeeds!
    let upd_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC", "install.env"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_fail.status.success(),
        "update must fail when parent dir fsync fails: {}",
        text(&upd_fail)
    );
    let rec_after_upd_fail = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after_upd_fail.contains("RECORD_STATE=updating\n")
            && rec_after_upd_fail.contains("UPDATE_PHASE=publishing\n"),
        "published record should remain visible:\n{rec_after_upd_fail}"
    );
    let bk_upd = PathBuf::from(
        rec_after_upd_fail
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    assert!(
        bk_upd.is_dir() && bk_upd.join(".qeminga-tx-id").is_file(),
        "exit trap MUST preserve recorded backup container when publishing record rename already succeeded: {}",
        bk_upd.display()
    );

    // Normal retry without fault injection MUST recover cleanly and publish v2!
    let upd_retry = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_retry.status.success(),
        "normal retry after post-rename fsync failure must succeed: {}",
        text(&upd_retry)
    );
    assert!(inst.join("bin/v2-marker").exists() && !bk_upd.exists());

    // 3. Lifecycle `install` (reinstall): inject parent-dir fsync EIO AFTER rename on the first
    //    `updating` record write -> exit trap MUST preserve the recorded backup so retry succeeds!
    let reinst_fail = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "fsync-box",
            "--service",
            "qeminga-fsync-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC", "install.env"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(!reinst_fail.status.success());
    let rec_after_reinst_fail = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after_reinst_fail.contains("RECORD_STATE=updating\n"),
        "reinstall record should be visible:\n{rec_after_reinst_fail}"
    );
    let bk_reinst = PathBuf::from(
        rec_after_reinst_fail
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    assert!(
        bk_reinst.is_dir() && bk_reinst.join(".qeminga-tx-id").is_file(),
        "reinstall exit trap MUST preserve recorded backup when record rename already succeeded"
    );

    let reinst_retry = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "fsync-box",
            "--service",
            "qeminga-fsync-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        reinst_retry.status.success(),
        "retrying reinstall after post-rename fsync failure must recover cleanly: {}",
        text(&reinst_retry)
    );
    assert!(inst.join("bin/v1-marker").exists() && !bk_reinst.exists());

    // 3. Read-error preservation during exit traps (three-outcome journal check):
    //    Wrap `grep` so reads of `install.env` exit 2 when `FAKE_GREP_READ_ERROR=1`.
    //    (a) Publishing journal + post-rename dir fsync failure + grep exit 2:
    //        `cleanup_update_exit` MUST preserve BOTH backup and stage rather than pruning them!
    write_exec(
        &bin.join("grep"),
        r#"#!/bin/sh
if [ "${FAKE_GREP_READ_ERROR:-0}" = "1" ]; then
    for a in "$@"; do
        case "$a" in
            */install.env) exit 2 ;;
        esac
    done
fi
exec /usr/bin/grep "$@"
"#,
    );
    let upd_grep_err = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_GREP_READ_ERROR", "1"),
            ("QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC", "install.env"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!upd_grep_err.status.success());
    let rec_grep_pub = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_grep_pub.contains("UPDATE_PHASE=publishing\n"),
        "expected publishing journal on disk:\n{rec_grep_pub}"
    );
    let bk_grep_pub = PathBuf::from(
        rec_grep_pub
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    let st_grep_pub = PathBuf::from(
        rec_grep_pub
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_STAGE_DIR="))
            .unwrap(),
    );
    assert!(
        bk_grep_pub.is_dir() && bk_grep_pub.join(".qeminga-tx-id").is_file(),
        "cleanup_update_exit MUST preserve recorded backup when journal read fails (grep exit 2): {}",
        text(&upd_grep_err)
    );
    assert!(
        st_grep_pub.is_dir() && st_grep_pub.join(".qeminga-tx-id").is_file(),
        "cleanup_update_exit MUST preserve recorded stage when journal read fails (grep exit 2): {}",
        text(&upd_grep_err)
    );

    // Recover from that publishing journal cleanly before testing the committed-phase read error.
    let recov_after_grep = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        recov_after_grep.status.success() && inst.join("bin/v2-marker").exists(),
        "recovery after grep read-error preservation must succeed: {}",
        text(&recov_after_grep)
    );

    // (b) Committed journal + post-rename dir fsync failure on `UPDATE_PHASE=committed`
    //     + grep exit 2 while `_UPDATE_ROLLBACK_ACTIVE=1`:
    //     `cleanup_update_exit` MUST NOT roll back the already-committed v1 replacement
    //     and MUST preserve the backup container for retry!
    let upd_comm_grep_err = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_GREP_READ_ERROR", "1"),
            (
                "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                "install.env:UPDATE_PHASE=committed",
            ),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!upd_comm_grep_err.status.success());
    let rec_comm_err = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_comm_err.contains("UPDATE_PHASE=committed\n"),
        "committed journal must remain intact when exit trap cannot read install.env:\n{rec_comm_err}"
    );
    let bk_comm_err = PathBuf::from(
        rec_comm_err
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    assert!(
        inst.join("bin/v1-marker").exists()
            && !inst.join("bin/v2-marker").exists()
            && bk_comm_err.is_dir(),
        "cleanup_update_exit MUST NOT roll back a committed replacement or delete its backup when journal read fails: {}",
        text(&upd_comm_grep_err)
    );

    // (b1) Keep the config-directory fsync failure active across BOTH `update` and `uninstall`
    //      retries while `UPDATE_PHASE=committed` is in memory: a persistent config-dir sync error
    //      MUST preserve the backup on EVERY retry (never pruning before the phase is durably synced)!
    let comm_retry_sync_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            (
                "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                "install.env:UPDATE_PHASE=committed",
            ),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !comm_retry_sync_fail.status.success() && bk_comm_err.is_dir(),
        "retry update on UPDATE_PHASE=committed MUST preserve backup while config-dir fsync still fails: {}",
        text(&comm_retry_sync_fail)
    );
    let comm_uninst_sync_fail = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            (
                "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                "install.env:UPDATE_PHASE=committed",
            ),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !comm_uninst_sync_fail.status.success() && bk_comm_err.is_dir(),
        "retry uninstall on UPDATE_PHASE=committed MUST preserve backup while config-dir fsync still fails: {}",
        text(&comm_uninst_sync_fail)
    );

    // Retry update once config-dir fsync succeeds cleans up the committed backup cleanly.
    let comm_retry = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        comm_retry.status.success() && !bk_comm_err.exists() && inst.join("bin/v1-marker").exists(),
        "retry after committed journal read-error preservation must succeed: {}",
        text(&comm_retry)
    );

    // (b2) `UPDATE_PHASE=restored` with a post-rename config-dir fsync failure:
    //      Crash mid-publish, then run `update` with `QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC`
    //      matching `UPDATE_PHASE=restored` -> restores live files and retains backup.
    //      Keeping the config-dir sync error active across BOTH `update` and `uninstall` retries
    //      MUST preserve the backup on EVERY retry until config-dir sync succeeds!
    let crash_for_rest = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert_eq!(
        crash_for_rest.status.code(),
        Some(99),
        "{}",
        text(&crash_for_rest)
    );

    let rest_sync_fail_1 = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            (
                "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                "install.env:UPDATE_PHASE=restored",
            ),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(!rest_sync_fail_1.status.success());
    let rec_rest_err = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_rest_err.contains("UPDATE_PHASE=restored\n"),
        "expected restored journal on disk:\n{rec_rest_err}"
    );
    let bk_rest_err = PathBuf::from(
        rec_rest_err
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    assert!(
        bk_rest_err.is_dir(),
        "restored backup must be retained on first sync failure"
    );

    let rest_retry_upd_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            (
                "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                "install.env:UPDATE_PHASE=restored",
            ),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !rest_retry_upd_fail.status.success() && bk_rest_err.is_dir(),
        "retry update on UPDATE_PHASE=restored MUST preserve backup while config-dir fsync still fails: {}",
        text(&rest_retry_upd_fail)
    );
    let rest_retry_uninst_fail = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            (
                "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                "install.env:UPDATE_PHASE=restored",
            ),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !rest_retry_uninst_fail.status.success() && bk_rest_err.is_dir(),
        "retry uninstall on UPDATE_PHASE=restored MUST preserve backup while config-dir fsync still fails: {}",
        text(&rest_retry_uninst_fail)
    );

    let rest_retry_ok = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        rest_retry_ok.status.success()
            && !bk_rest_err.exists()
            && inst.join("bin/v1-marker").exists(),
        "retry update on UPDATE_PHASE=restored must succeed once config-dir fsync recovers: {}",
        text(&rest_retry_ok)
    );

    // (c) Reinstall preparing/publishing journal + post-rename dir fsync failure + grep exit 2:
    //     `cleanup_install_exit` MUST preserve BOTH stage and backup without overwriting install.env!
    let reinst_grep_err = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "fsync-box",
            "--service",
            "qeminga-fsync-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_ACTIVE_FLAG", active_flag.to_str().unwrap()),
            ("FAKE_GREP_READ_ERROR", "1"),
            ("QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC", "install.env"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(!reinst_grep_err.status.success());
    let rec_reinst_err = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_reinst_err.contains("RECORD_STATE=updating\n"),
        "reinstall journal must remain intact on grep read error:\n{rec_reinst_err}"
    );
    let bk_reinst_err = PathBuf::from(
        rec_reinst_err
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    assert!(
        bk_reinst_err.is_dir() && bk_reinst_err.join(".qeminga-tx-id").is_file(),
        "cleanup_install_exit MUST preserve recorded backup when journal read fails (grep exit 2): {}",
        text(&reinst_grep_err)
    );
}

#[test]
fn restore_managed_config_retains_blobs_and_manifest_until_recorded_pruning_phase() {
    let dir = private_tempdir();
    let runner_dir = dir.path().join("runner");
    let cfg_dir = dir.path().join("cfg");
    let hook_dir = dir.path().join("hooks");
    let unit_dir = dir.path().join("units");
    let bk_dir = dir.path().join(".qeminga-update-backup.cfgretain");
    for d in [&runner_dir, &cfg_dir, &hook_dir, &unit_dir, &bk_dir] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::set_permissions(&bk_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let policy_path = cfg_dir.join("policy.env");
    let hook_path = hook_dir.join("hook-job-started.sh");
    let unit_path = unit_dir.join("qeminga-cfg-retain.service");
    std::fs::write(&policy_path, b"ORIGINAL_POLICY=1\n").unwrap();
    std::fs::write(&hook_path, b"#!/bin/sh\necho orig-hook\n").unwrap();
    std::fs::write(&unit_path, b"[Unit]\nDescription=orig\n").unwrap();

    let vol_inst = live_volume_id(&runner_dir);
    let vol_hook = live_volume_id(&hook_dir);
    let vol_unit = live_volume_id(&unit_path);

    let id_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            bk_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(id_out.status.success(), "{}", text(&id_out));
    let bk_id = String::from_utf8(id_out.stdout).unwrap().trim().to_string();

    let snap_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops snapshot-managed-config "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}""#,
            "_",
            script().to_str().unwrap(),
            runner_dir.to_str().unwrap(),
            &vol_inst,
            bk_dir.to_str().unwrap(),
            &bk_id,
            cfg_dir.to_str().unwrap(),
            hook_dir.to_str().unwrap(),
            &vol_hook,
            unit_path.to_str().unwrap(),
            &vol_unit,
        ])
        .output()
        .unwrap();
    assert!(snap_out.status.success(), "{}", text(&snap_out));

    // Mutate live managed files as a reinstall would.
    std::fs::write(&policy_path, b"MUTATED_POLICY=2\n").unwrap();
    std::fs::write(&hook_path, b"#!/bin/sh\necho mutated-hook\n").unwrap();
    std::fs::write(&unit_path, b"[Unit]\nDescription=mutated\n").unwrap();

    // First restore MUST restore original files AND retain BOTH cfg_old/ and config-manifest.json.
    let run_restore = || {
        Command::new("bash")
            .args([
                "-c",
                r#"source "$1"; fs_ops restore-runner-backup "$2" "$3" "$4" "$5" "" "0" "$6" "$7" "$8" "$9" "${10}""#,
                "_",
                script().to_str().unwrap(),
                runner_dir.to_str().unwrap(),
                &vol_inst,
                bk_dir.to_str().unwrap(),
                &bk_id,
                cfg_dir.to_str().unwrap(),
                hook_dir.to_str().unwrap(),
                &vol_hook,
                unit_path.to_str().unwrap(),
                &vol_unit,
            ])
            .output()
            .unwrap()
    };

    let r1 = run_restore();
    assert!(r1.status.success(), "first restore failed: {}", text(&r1));
    assert_eq!(std::fs::read(&policy_path).unwrap(), b"ORIGINAL_POLICY=1\n");
    assert_eq!(
        std::fs::read(&hook_path).unwrap(),
        b"#!/bin/sh\necho orig-hook\n"
    );
    assert_eq!(
        std::fs::read(&unit_path).unwrap(),
        b"[Unit]\nDescription=orig\n"
    );
    assert!(
        bk_dir.join("cfg_old").is_dir()
            && bk_dir.join("cfg_old/cfg__policy.env").is_file()
            && bk_dir.join("config-manifest.json").is_file(),
        "restore-runner-backup MUST retain cfg_old blobs and config-manifest.json until recorded pruning phase"
    );

    // Mutate again and invoke restore a SECOND time (simulating crash before UPDATE_PHASE=restored
    // was saved) -> MUST remain completely idempotent!
    std::fs::write(&policy_path, b"PARTIAL_RETRY=3\n").unwrap();
    let r2 = run_restore();
    assert!(
        r2.status.success(),
        "second idempotent restore must succeed with blobs+manifest retained: {}",
        text(&r2)
    );
    assert_eq!(std::fs::read(&policy_path).unwrap(), b"ORIGINAL_POLICY=1\n");

    // Recorded pruning phase (`safe-rmtree-id`) reclaims everything cleanly.
    let prune = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops safe-rmtree-id "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            bk_dir.to_str().unwrap(),
            &bk_id,
        ])
        .output()
        .unwrap();
    assert!(
        prune.status.success() && !bk_dir.exists(),
        "{}",
        text(&prune)
    );
}

#[test]
fn service_state_checks_fail_closed_on_manager_error_unknown_state_and_stop_activating_units() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("svcstate-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    let state_file = dir.path().join("svc.state");
    let sc_log = dir.path().join("sc.log");
    std::fs::write(&state_file, "inactive\n").unwrap();
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ -n "${FAKE_SC_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_SC_LOG"; fi
st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active)
        case "$st" in
            bus-error)
                echo "Failed to connect to bus: No such file or directory" >&2
                exit 1
                ;;
            active | reloading)
                echo "$st"
                exit 0
                ;;
            activating | deactivating | inactive | failed | maintenance)
                echo "$st"
                exit 3
                ;;
            *)
                echo "$st"
                exit 3
                ;;
        esac
        ;;
    stop)
        if [ -f "${FAKE_STOP_STUCK:-}" ]; then exit 0; fi
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    start | enable)
        echo "active" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "svcstate-box",
            "--service",
            "qeminga-svcstate-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // 1. Forward `update` under systemd manager error (empty stdout, exit 1) MUST fail closed
    //    without mutating live files or install.env.
    std::fs::write(&state_file, "bus-error\n").unwrap();
    let upd_bus = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_bus.status.success()
            && inst.join("bin/v1-marker").exists()
            && !inst.join("bin/v2-marker").exists(),
        "forward update MUST fail closed on systemd connection failure: {}",
        text(&upd_bus)
    );

    // 2. Forward `update` under unrecognized state (`maintenance`) MUST also fail closed!
    std::fs::write(&state_file, "maintenance\n").unwrap();
    let upd_unk = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !upd_unk.status.success() && inst.join("bin/v1-marker").exists(),
        "forward update MUST fail closed on unrecognized systemd state: {}",
        text(&upd_unk)
    );

    // 3. Forward `update` while Type=notify unit is `activating` MUST stop it first, confirm
    //    stopped, publish v2, and restart it (`active`)!
    std::fs::write(&state_file, "activating\n").unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let upd_act = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_act.status.success(),
        "forward update must stop an activating Type=notify unit and restart after publish: {}",
        text(&upd_act)
    );
    let sc_act = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        sc_act.contains("stop qeminga-svcstate-box.service")
            && sc_act.contains("start qeminga-svcstate-box.service")
            && std::fs::read_to_string(&state_file).unwrap().trim() == "active",
        "update must stop activating unit and restart it afterwards:\n{sc_act}"
    );

    // 4. Forward `reinstall` while unit is `activating` MUST also stop it before publishing,
    //    and MUST fail closed under systemd connection failure (`bus-error`)!
    std::fs::write(&state_file, "bus-error\n").unwrap();
    let reinst_bus = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "svcstate-box",
            "--service",
            "qeminga-svcstate-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !reinst_bus.status.success() && inst.join("bin/v2-marker").exists(),
        "forward reinstall MUST fail closed on systemd connection failure: {}",
        text(&reinst_bus)
    );

    // 5. Recovery (`UPDATE_PHASE=publishing`) under systemd connection failure (`bus-error`):
    //    Crash an update mid-publish while inactive, then set `bus-error` and verify BOTH
    //    `update` recovery AND `uninstall` recovery refuse to restore underneath an indeterminate
    //    service state and preserve the journal + backup intact!
    std::fs::write(&state_file, "inactive\n").unwrap();
    let crash = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert_eq!(crash.status.code(), Some(99), "{}", text(&crash));
    let rec_pub = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let bk_pub = PathBuf::from(
        rec_pub
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );

    std::fs::write(&state_file, "bus-error\n").unwrap();
    let recov_upd_bus = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !recov_upd_bus.status.success() && bk_pub.is_dir(),
        "update recovery MUST fail closed and retain backup/journal when systemd connection fails: {}",
        text(&recov_upd_bus)
    );
    assert!(
        std::fs::read_to_string(cfg.join("install.env"))
            .unwrap()
            .contains("UPDATE_PHASE=publishing\n"),
        "journal must remain in UPDATE_PHASE=publishing on indeterminate service state"
    );

    let recov_uninst_bus = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !recov_uninst_bus.status.success() && bk_pub.is_dir(),
        "uninstall recovery MUST fail closed and retain backup/journal when systemd connection fails: {}",
        text(&recov_uninst_bus)
    );

    // 6. Missing `systemctl` client while unit is owned (`REC_OWNED_UNIT=1`):
    //    Build a PATH directory mirroring `/usr/bin` and `/bin` WITHOUT `systemctl`, plus
    //    all non-systemctl mocks from `bin`. BOTH recovery paths AND forward update/reinstall/uninstall
    //    MUST fail closed (indeterminate state) rather than assuming the owned service is stopped!
    let no_sc_bin = dir.path().join("bin-no-systemctl");
    std::fs::create_dir_all(&no_sc_bin).unwrap();
    for entry in std::fs::read_dir(&bin).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "systemctl" {
            continue;
        }
        std::os::unix::fs::symlink(entry.path(), no_sc_bin.join(&name)).unwrap();
    }
    let sys_no_sc = dir.path().join("sys-no-systemctl");
    std::fs::create_dir_all(&sys_no_sc).unwrap();
    for sys_dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        if let Ok(rd) = std::fs::read_dir(sys_dir) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                if name == "systemctl" {
                    continue;
                }
                let dst = sys_no_sc.join(&name);
                if !dst.exists() && dst.symlink_metadata().is_err() {
                    let _ = std::os::unix::fs::symlink(entry.path(), &dst);
                }
            }
        }
    }
    let no_sc_path = format!("{}:{}", no_sc_bin.display(), sys_no_sc.display());
    let run_no_sc = |args: &[&str], extra_env: &[(&str, &str)]| -> Output {
        let mut cmd = Command::new("bash");
        cmd.arg(script()).args(args);
        cmd.env("PATH", &no_sc_path);
        cmd.env("FAKE_USER_FLAG", &user_flag);
        cmd.env("QEMINGA_RUNTIME_ROOT", &rt_root);
        cmd.env("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir);
        cmd.env("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    // 6a. Interrupted-update recovery (`publishing`) with no `systemctl` -> MUST fail closed!
    let recov_upd_nosc = run_no_sc(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap())],
    );
    assert!(
        !recov_upd_nosc.status.success() && bk_pub.is_dir(),
        "update recovery MUST fail closed when systemctl is unavailable for owned unit: {}",
        text(&recov_upd_nosc)
    );
    let recov_uninst_nosc = run_no_sc(&["uninstall", "--config-dir", cfg.to_str().unwrap()], &[]);
    assert!(
        !recov_uninst_nosc.status.success() && bk_pub.is_dir(),
        "uninstall recovery MUST fail closed when systemctl is unavailable for owned unit: {}",
        text(&recov_uninst_nosc)
    );

    // Recover cleanly back to `installed` (v1) using the real mock `systemctl`.
    std::fs::write(&state_file, "inactive\n").unwrap();
    let recov_ok = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        recov_ok.status.success() && inst.join("bin/v1-marker").exists(),
        "recovery to v1 must succeed: {}",
        text(&recov_ok)
    );

    // 6b. Forward `update`, `install` (reinstall), and ordinary `uninstall` on `installed`
    //     runner with NO `systemctl` on PATH -> ALL MUST fail closed leaving v1 untouched!
    let upd_nosc = run_no_sc(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap())],
    );
    assert!(
        !upd_nosc.status.success()
            && inst.join("bin/v1-marker").exists()
            && !inst.join("bin/v2-marker").exists(),
        "forward update MUST fail closed when systemctl is missing for owned unit: {}",
        text(&upd_nosc)
    );
    let reinst_nosc = run_no_sc(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "svcstate-box",
            "--service",
            "qeminga-svcstate-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
    );
    assert!(
        !reinst_nosc.status.success()
            && inst.join("bin/v1-marker").exists()
            && !inst.join("bin/v2-marker").exists(),
        "forward reinstall MUST fail closed when systemctl is missing for owned unit: {}",
        text(&reinst_nosc)
    );
    let uninst_nosc = run_no_sc(&["uninstall", "--config-dir", cfg.to_str().unwrap()], &[]);
    assert!(
        !uninst_nosc.status.success()
            && inst.join("bin/v1-marker").exists()
            && cfg.join("install.env").is_file(),
        "ordinary uninstall MUST fail closed when systemctl is missing for owned unit: {}",
        text(&uninst_nosc)
    );

    // 6c. `UPDATE_PHASE=restored` recovery MUST verify/stop the owned service BEFORE calling
    //     `lock_runner_permissions` (never changing live dir permissions under a missing client or
    //     already-running restored listener) and MUST retain restart intent!
    let rec_before_rest = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_restored_active = rec_before_rest.replace(
        "RECORD_STATE=installed\n",
        "RECORD_STATE=updating\nUPDATE_PHASE=restored\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR=\nUPDATE_BACKUP_ID=\nUPDATE_WAS_ACTIVE=1\n",
    );
    std::fs::write(cfg.join("install.env"), &rec_restored_active).unwrap();
    std::fs::set_permissions(&inst, std::fs::Permissions::from_mode(0o700)).unwrap();

    // 6c-i. Missing `systemctl` client during `UPDATE_PHASE=restored`: MUST fail closed AND leave
    //       live runner directory permissions untouched (still 0700, NOT changed to 0755)!
    let rest_nosc = run_no_sc(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap())],
    );
    let inst_mode_after_nosc = std::fs::metadata(&inst).unwrap().permissions().mode() & 0o777;
    assert!(
        !rest_nosc.status.success(),
        "restored recovery MUST fail closed when systemctl is unavailable: {}",
        text(&rest_nosc)
    );
    assert_eq!(
        inst_mode_after_nosc,
        0o700,
        "restored recovery with missing systemctl MUST NOT mutate live runner dir mode before checking systemctl (got {:o}): {}",
        inst_mode_after_nosc,
        text(&rest_nosc)
    );

    // 6c-ii. Already-running restored service (`state_file=active`, e.g. rollback restarted the
    //        old runner before failing its final `installed` write): `update` MUST stop the
    //        service BEFORE `lock_runner_permissions` changes `inst` from 0700 to 0755, complete
    //        the update, and restart the service (`active`) retaining restart intent!
    let stop_seen_mode = dir.path().join("stop-seen-inst-mode");
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ -n "${FAKE_SC_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_SC_LOG"; fi
st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active)
        case "$st" in
            active | reloading) echo "$st"; exit 0 ;;
            activating | deactivating | inactive | failed) echo "$st"; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        if [ -n "${FAKE_CHECK_INST_DIR:-}" ] && [ -n "${FAKE_STOP_MODE_OUT:-}" ] && [ ! -e "$FAKE_STOP_MODE_OUT" ]; then
            stat -c '%a' "$FAKE_CHECK_INST_DIR" > "$FAKE_STOP_MODE_OUT"
        fi
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    start | enable)
        echo "active" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );
    std::fs::write(&state_file, "active\n").unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let rest_running_upd = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_CHECK_INST_DIR", inst.to_str().unwrap()),
            ("FAKE_STOP_MODE_OUT", stop_seen_mode.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        rest_running_upd.status.success(),
        "restored recovery on an already-running unit must stop, update, and restart cleanly: {}",
        text(&rest_running_upd)
    );
    assert_eq!(
        std::fs::read_to_string(&stop_seen_mode)
            .unwrap_or_default()
            .trim(),
        "700",
        "restored recovery MUST stop the already-running owned service BEFORE lock_runner_permissions changes mode from 700 to 755 (sc_log:\n{})",
        std::fs::read_to_string(&sc_log).unwrap_or_default()
    );
    assert_eq!(
        std::fs::read_to_string(&state_file).unwrap().trim(),
        "active",
        "restored recovery MUST retain restart intent and restart the owned service"
    );

    // 7. Ordinary `uninstall` MUST confirm the owned service actually stopped AND disabled BEFORE
    //    running domain cleanup (`virsh`) or removing binaries/state/unit/install.env!
    let wants_dir = units.join("multi-user.target.wants");
    std::fs::create_dir_all(&wants_dir).unwrap();
    let wants_link = wants_dir.join("qeminga-svcstate-box.service");
    std::os::unix::fs::symlink(units.join("qeminga-svcstate-box.service"), &wants_link).unwrap();

    let virsh_log = dir.path().join("uninstall-virsh.log");
    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
printf '%s\n' "$*" >> "${FAKE_VIRSH_LOG:?}"
shift
case "$1" in
    list) exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#,
    );
    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    is-active)
        st="$(cat "${FAKE_STATE_FILE:?}")"
        case "$st" in
            active) echo active; exit 0 ;;
            inactive) echo inactive; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        if [ "${FAKE_STOP_FAIL:-0}" = "1" ]; then
            echo "Failed to stop service" >&2
            exit 1
        fi
        if [ "${FAKE_STOP_STAYS_ACTIVE:-0}" != "1" ]; then
            echo inactive > "${FAKE_STATE_FILE:?}"
        fi
        exit 0
        ;;
    disable)
        if [ "${FAKE_DISABLE_FAIL:-0}" = "1" ]; then
            echo "Failed to disable unit: Read-only file system" >&2
            exit 1
        fi
        if [ "${FAKE_DISABLE_NOOP:-0}" != "1" ] && [ -n "${FAKE_WANTS_LINK:-}" ]; then
            rm -f "$FAKE_WANTS_LINK"
        fi
        exit 0
        ;;
    is-enabled)
        if [ -n "${FAKE_WANTS_LINK:-}" ] && { [ -e "$FAKE_WANTS_LINK" ] || [ -L "$FAKE_WANTS_LINK" ]; }; then
            echo "enabled"
            exit 0
        fi
        echo "disabled"
        exit 1
        ;;
    *) exit 0 ;;
esac
"#,
    );
    // 7a. `systemctl stop` fails (exit 1) while service is active -> preserve entire install!
    std::fs::write(&state_file, "active\n").unwrap();
    let uninst_stop_fail = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_WANTS_LINK", wants_link.to_str().unwrap()),
            ("FAKE_STOP_FAIL", "1"),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_stop_fail.status.success(),
        "ordinary uninstall MUST fail closed when systemctl stop fails: {}",
        text(&uninst_stop_fail)
    );
    assert!(
        !virsh_log.exists()
            && inst.join("bin/v1-marker").exists()
            && cfg.join("install.env").is_file()
            && units.join("qeminga-svcstate-box.service").is_file(),
        "failed stop during uninstall must NOT run virsh cleanup or delete binaries/unit/record"
    );

    // 7b. `systemctl stop` returns 0 but service stays `active` -> STILL fail closed!
    let uninst_still_active = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_WANTS_LINK", wants_link.to_str().unwrap()),
            ("FAKE_STOP_STAYS_ACTIVE", "1"),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_still_active.status.success()
            && !virsh_log.exists()
            && inst.join("bin/v1-marker").exists()
            && cfg.join("install.env").is_file(),
        "ordinary uninstall MUST fail closed if unit does not reach stopped state after stop: {}",
        text(&uninst_still_active)
    );

    // 7c. `systemctl stop` succeeds, but `systemctl disable` fails leaving
    //     `multi-user.target.wants/<unit>.service`: MUST fail closed, preserving unit file,
    //     enablement link, and `install.env` (`OWNED_UNIT=1`) for retry!
    let uninst_disable_fail = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_WANTS_LINK", wants_link.to_str().unwrap()),
            ("FAKE_DISABLE_FAIL", "1"),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_disable_fail.status.success(),
        "uninstall MUST fail closed when systemctl disable fails on enabled unit: {}",
        text(&uninst_disable_fail)
    );
    assert!(
        !virsh_log.exists()
            && units.join("qeminga-svcstate-box.service").is_file()
            && wants_link.symlink_metadata().is_ok()
            && std::fs::read_to_string(cfg.join("install.env"))
                .unwrap()
                .contains("OWNED_UNIT=1\n"),
        "failed disable MUST retain OWNED_UNIT=1, unit file, and install.env without leaving a dangling wants link"
    );

    // 7d. Even if `systemctl disable` exits 0 without removing the `.wants` symlink, uninstall
    //     MUST still fail closed and retain ownership!
    let uninst_disable_noop = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_WANTS_LINK", wants_link.to_str().unwrap()),
            ("FAKE_DISABLE_NOOP", "1"),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_disable_noop.status.success()
            && !virsh_log.exists()
            && units.join("qeminga-svcstate-box.service").is_file()
            && wants_link.symlink_metadata().is_ok()
            && cfg.join("install.env").is_file(),
        "uninstall MUST fail closed if enablement symlink still exists after systemctl disable: {}",
        text(&uninst_disable_noop)
    );

    // 7e. Once `systemctl disable` removes the enablement link and confirms disabled, retry
    //     `uninstall` succeeds cleanly!
    let uninst_ok = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_WANTS_LINK", wants_link.to_str().unwrap()),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        uninst_ok.status.success()
            && !inst.exists()
            && !units.join("qeminga-svcstate-box.service").exists()
            && wants_link.symlink_metadata().is_err(),
        "uninstall retry after service stops and disables must succeed cleanly: {}",
        text(&uninst_ok)
    );
}

#[test]
fn reinstall_records_preparing_phase_before_copying_jit_credential_and_recovers_on_interruption() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, "#!/bin/sh\nexit 0\n")
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active) echo "inactive"; exit 3 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let jit1 = dir.path().join("jit1");
    let jit2 = dir.path().join("jit2");
    let jit1_blob = make_jit_config(REPO_URL, "_work");
    let jit2_blob = make_jit_config(REPO_URL, "_work");
    std::fs::write(&jit1, format!("{jit1_blob}\n")).unwrap();
    std::fs::write(&jit2, format!("{jit2_blob}\n")).unwrap();
    std::fs::set_permissions(&jit1, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&jit2, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    // Install v1 JIT runner with sensitive `cfg/jitconfig`.
    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "jitprep-box",
            "--service",
            "qeminga-jitprep-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--jitconfig-file",
            jit1.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    let orig_policy = std::fs::read(cfg.join("policy.env")).unwrap();
    let orig_jit = std::fs::read(cfg.join("jitconfig")).unwrap();

    let crash_reinstall_mid_snapshot = || -> PathBuf {
        let out = run_setup_env(
            &[
                "install",
                "--repo",
                REPO_URL,
                "--name",
                "jitprep-box",
                "--service",
                "qeminga-jitprep-box",
                "--install-dir",
                inst.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
                "--hook-dir",
                hooks.to_str().unwrap(),
                "--config-dir",
                cfg.to_str().unwrap(),
                "--jitconfig-file",
                jit2.to_str().unwrap(),
                "--runner-sha256",
                &v2_sha,
                "--skip-packages",
                "--no-start",
            ],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
                ("QEMINGA_TEST_CRASH_SNAPSHOT_AFTER", "2"),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ],
            Some(&bin),
        );
        assert_eq!(
            out.status.code(),
            Some(98),
            "expected simulated mid-snapshot crash exit 98: {}",
            text(&out)
        );
        let rec = std::fs::read_to_string(cfg.join("install.env")).unwrap();
        assert!(
            rec.contains("RECORD_STATE=updating\n") && rec.contains("UPDATE_PHASE=preparing\n"),
            "backup identity MUST already be recorded under UPDATE_PHASE=preparing before copying jitconfig:\n{rec}"
        );
        let bk = PathBuf::from(
            rec.lines()
                .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
                .unwrap(),
        );
        assert!(
            bk.join("cfg_old/cfg__jitconfig").is_file()
                && !bk.join("config-manifest.json").exists(),
            "crash should happen AFTER copying cfg_old/cfg__jitconfig and BEFORE config-manifest.json"
        );
        assert_eq!(std::fs::read(cfg.join("policy.env")).unwrap(), orig_policy);
        assert_eq!(std::fs::read(cfg.join("jitconfig")).unwrap(), orig_jit);
        bk
    };

    // Case 1: Crash after copying jitconfig -> retry `install` locates and prunes the incomplete
    // snapshot (eliminating stray cfg__jitconfig) and completes cleanly.
    let bk1 = crash_reinstall_mid_snapshot();
    let retry_inst = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "jitprep-box",
            "--service",
            "qeminga-jitprep-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--jitconfig-file",
            jit2.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        retry_inst.status.success(),
        "retrying install after mid-snapshot crash must prune incomplete snapshot and succeed: {}",
        text(&retry_inst)
    );
    assert!(
        !bk1.exists(),
        "retry install must delete incomplete snapshot with copied jitconfig"
    );

    // Case 2: Crash again mid-snapshot -> `update` prunes incomplete snapshot without modifying
    // original config/jitconfig files!
    let bk2 = crash_reinstall_mid_snapshot();
    let recov_upd = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        recov_upd.status.success(),
        "update after mid-snapshot preparing crash must prune stray jitconfig snapshot: {}",
        text(&recov_upd)
    );
    assert!(!bk2.exists() && std::fs::read(cfg.join("jitconfig")).unwrap() == orig_jit);

    // Case 3: Crash again mid-snapshot -> `uninstall` locates and prunes the incomplete snapshot
    // containing the copied jitconfig!
    let bk3 = crash_reinstall_mid_snapshot();
    let recov_uninst = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        recov_uninst.status.success(),
        "uninstall after mid-snapshot preparing crash must prune stray jitconfig snapshot: {}",
        text(&recov_uninst)
    );
    assert!(
        !bk3.exists(),
        "uninstall must remove incomplete snapshot containing copied jitconfig"
    );
}

#[test]
fn migrate_record_recognizes_and_validates_preceding_376eed2_phased_journals() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("prev-box");
    let build_pkg = |src: &Path, tag: &str, name: &str| -> (PathBuf, String) {
        build_versioned_runner_pkg(dir.path(), src, tag, name, &cfg_sh)
    };
    let (v1_tb, v1_sha) = build_pkg(&v1_src, "v1", "v1.tar.gz");
    let (v2_tb, v2_sha) = build_pkg(&v2_src, "v2", "v2.tar.gz");

    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active) echo "inactive"; exit 3 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "prev-box",
            "--service",
            "qeminga-prev-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Helper generating the EXACT `376eed2` identity token format:
    // `p_dev:<dev>;p_ino:<ino>;p_mnt:<mnt>;t_dev:<dev>;t_ino:<ino>;t_mnt:<mnt>;vol:<vol>`
    let make_376eed2_id = |target: &Path| -> String {
        let vol = live_volume_id(target);
        let py = Command::new("python3")
            .args([
                "-I",
                "-c",
                r#"
import os, sys
target = os.path.normpath(sys.argv[1])
vol = sys.argv[2]
parent = os.path.dirname(target) or "/"
def mnt(fd):
    for line in open(f"/proc/self/fdinfo/{fd}"):
        if line.startswith("mnt_id:"):
            return line.split(":", 1)[1].strip()
    raise RuntimeError("no mnt_id")
pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
tfd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
try:
    pst = os.fstat(pfd)
    tst = os.fstat(tfd)
    print(f"p_dev:{pst.st_dev};p_ino:{pst.st_ino};p_mnt:{mnt(pfd)};t_dev:{tst.st_dev};t_ino:{tst.st_ino};t_mnt:{mnt(tfd)};vol:{vol}")
finally:
    os.close(tfd)
    os.close(pfd)
"#,
                target.to_str().unwrap(),
                &vol,
            ])
            .output()
            .unwrap();
        assert!(py.status.success(), "{}", text(&py));
        String::from_utf8(py.stdout).unwrap().trim().to_string()
    };

    // Fixture A: `376eed2` `UPDATE_PHASE=publishing` record with stage + backup (no `.qeminga-tx-id`).
    let prev_stage = dir.path().join(".qeminga-extract.prev376");
    let prev_bk = dir.path().join(".qeminga-update-backup.prev376");
    std::fs::create_dir(&prev_stage).unwrap();
    std::fs::create_dir(&prev_bk).unwrap();
    std::fs::set_permissions(&prev_stage, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&prev_bk, std::fs::Permissions::from_mode(0o700)).unwrap();
    let prev_stage_id = make_376eed2_id(&prev_stage);
    let prev_bk_id = make_376eed2_id(&prev_bk);

    let rec_base = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_376_pub = rec_base.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=publishing\nUPDATE_STAGE_DIR={}\nUPDATE_STAGE_ID={}\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={}\nUPDATE_WAS_ACTIVE=0\n",
            prev_stage.display(),
            prev_stage_id,
            prev_bk.display(),
            prev_bk_id
        ),
    );
    std::fs::write(cfg.join("install.env"), &rec_376_pub).unwrap();

    // 1. `update` and `uninstall` MUST recognize the 376eed2 phased record (NOT crash with
    //    cryptic `invalid UPDATE_BACKUP_ID`) and direct operator to `migrate-record --confirm-volumes`.
    let upd_376 = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    let upd_376_msg = text(&upd_376);
    assert!(
        !upd_376.status.success()
            && upd_376_msg.contains("migrate-record")
            && !upd_376_msg.contains("invalid UPDATE_BACKUP_ID"),
        "update must recognize preceding 376eed2 phased record and direct to migrate-record: {upd_376_msg}"
    );

    // 2. Substituted backup directory (different inode, still 0700) MUST be rejected by migrate-record!
    let prev_bk_held = dir.path().join(".qeminga-hold-prev-bk");
    std::fs::rename(&prev_bk, &prev_bk_held).unwrap();
    std::fs::create_dir(&prev_bk).unwrap();
    std::fs::set_permissions(&prev_bk, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mig_bad_ino = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !mig_bad_ino.status.success(),
        "migrate-record MUST reject 376eed2 backup whose inode changed: {}",
        text(&mig_bad_ino)
    );
    std::fs::remove_dir(&prev_bk).unwrap();
    std::fs::rename(&prev_bk_held, &prev_bk).unwrap();

    // 3. Genuine 376eed2 `publishing` record migrates cleanly, preserves UPDATE_PHASE=publishing,
    //    stamps .qeminga-tx-id in both stage & backup, upgrades tokens, and allows `update` to recover!
    let mig_pub = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        mig_pub.status.success(),
        "migrate-record must upgrade verified 376eed2 publishing journal: {}",
        text(&mig_pub)
    );
    let rec_pub_after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_pub_after.contains("UPDATE_PHASE=publishing\n")
            && rec_pub_after.contains("tx:")
            && !rec_pub_after.contains("p_dev:")
            && prev_bk.join(".qeminga-tx-id").is_file()
            && prev_stage.join(".qeminga-tx-id").is_file(),
        "migrated 376eed2 publishing record must preserve phase and carry tx tokens:\n{rec_pub_after}"
    );
    let upd_after_mig = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_after_mig.status.success()
            && !prev_bk.exists()
            && !prev_stage.exists()
            && inst.join("bin/v2-marker").exists(),
        "update after migrating 376eed2 publishing record must recover cleanly: {}",
        text(&upd_after_mig)
    );

    // Fixture B: `376eed2` `UPDATE_PHASE=committed` record with backup dir only -> migrates preserving
    // `UPDATE_PHASE=committed` (never downgrading to `publishing`!) and `update` prunes backup cleanly!
    let prev_bk_comm = dir.path().join(".qeminga-update-backup.prev376comm");
    std::fs::create_dir(&prev_bk_comm).unwrap();
    std::fs::set_permissions(&prev_bk_comm, std::fs::Permissions::from_mode(0o700)).unwrap();
    let prev_bk_comm_id = make_376eed2_id(&prev_bk_comm);
    let rec_now = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    let rec_376_comm = rec_now.replace(
        "RECORD_STATE=installed\n",
        &format!(
            "RECORD_STATE=updating\nUPDATE_PHASE=committed\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={}\nUPDATE_WAS_ACTIVE=0\n",
            prev_bk_comm.display(),
            prev_bk_comm_id
        ),
    );
    std::fs::write(cfg.join("install.env"), &rec_376_comm).unwrap();

    let mig_comm = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        mig_comm.status.success(),
        "migrate-record must upgrade verified 376eed2 committed journal: {}",
        text(&mig_comm)
    );
    let rec_comm_after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_comm_after.contains("UPDATE_PHASE=committed\n")
            && rec_comm_after.contains("tx:")
            && !rec_comm_after.contains("p_dev:"),
        "migrated 376eed2 committed record must preserve UPDATE_PHASE=committed:\n{rec_comm_after}"
    );
    // And subsequent update prunes the still-present migrated committed backup cleanly.
    let upd_comm_present = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_comm_present.status.success() && !prev_bk_comm.exists(),
        "update after migrating still-present committed backup must prune it cleanly: {}",
        text(&upd_comm_present)
    );

    // Fixture C: `376eed2` `UPDATE_PHASE=committed` journal where backup pruning ALREADY
    // finished before `RECORD_STATE=installed` was written (backup directory absent on disk,
    // parent inode and backing volume still match).
    let pruned_bk = dir.path().join(".qeminga-update-backup.prev376pruned");
    std::fs::create_dir(&pruned_bk).unwrap();
    std::fs::set_permissions(&pruned_bk, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pruned_bk_id = make_376eed2_id(&pruned_bk);
    std::fs::remove_dir(&pruned_bk).unwrap();
    assert!(!pruned_bk.exists());

    // C1. Negative check: mismatched parent inode when committed backup is absent MUST fail closed!
    let bad_parent_id = pruned_bk_id
        .split(';')
        .map(|part| {
            if part.starts_with("p_ino:") {
                "p_ino:999999999999".to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(";");
    let rec_base_c = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    std::fs::write(
        cfg.join("install.env"),
        rec_base_c.replace(
            "RECORD_STATE=installed\n",
            &format!(
                "RECORD_STATE=updating\nUPDATE_PHASE=committed\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={}\nUPDATE_WAS_ACTIVE=0\n",
                pruned_bk.display(),
                bad_parent_id
            ),
        ),
    )
    .unwrap();
    let mig_bad_parent = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !mig_bad_parent.status.success(),
        "migrate-record MUST reject already-pruned committed journal when parent inode mismatches: {}",
        text(&mig_bad_parent)
    );

    // C2. Genuine parent inode + volume with absent committed backup -> finalize cleanly to `installed`!
    std::fs::write(
        cfg.join("install.env"),
        rec_base_c.replace(
            "RECORD_STATE=installed\n",
            &format!(
                "RECORD_STATE=updating\nUPDATE_PHASE=committed\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR={}\nUPDATE_BACKUP_ID={}\nUPDATE_WAS_ACTIVE=0\n",
                pruned_bk.display(),
                pruned_bk_id
            ),
        ),
    )
    .unwrap();
    let mig_pruned_comm = run_setup_env(
        &[
            "migrate-record",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--confirm-volumes",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        mig_pruned_comm.status.success(),
        "migrate-record MUST finalize already-pruned 376eed2 committed journal after verifying parent+volume: {}",
        text(&mig_pruned_comm)
    );
    let rec_pruned_after = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_pruned_after.contains("RECORD_STATE=installed\n")
            && !rec_pruned_after.contains("UPDATE_PHASE=")
            && !rec_pruned_after.contains("UPDATE_BACKUP_DIR=")
            && !rec_pruned_after.contains("p_dev:"),
        "finalized already-pruned committed journal must become a clean installed record:\n{rec_pruned_after}"
    );
    // Subsequent update and uninstall both accept the finalized record cleanly.
    let upd_after_pruned = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        upd_after_pruned.status.success() && inst.join("bin/v1-marker").exists(),
        "update after finalizing pruned 376eed2 committed journal must succeed: {}",
        text(&upd_after_pruned)
    );

    // Fixture D: Atomic single-open legacy identity verification + stamping (`upgrade-legacy-path-identity`):
    // verify that stamping derives the new token from the SAME open verified directory descriptor
    // (opening the target basename exactly once, rejecting substituted 0700 dirs without stamping).
    let py_root = dir.path().join("py-upgrade-legacy");
    std::fs::create_dir_all(&py_root).unwrap();
    let py_check = Command::new("python3")
        .args([
            "-I",
            "-c",
            r##"
import io, os, sys

script_text = open(sys.argv[1], "r", encoding="utf-8").read()
fs_section = script_text.split("fs_ops() {\n", 1)[1].split("\nPY\n", 1)[0]
py_body = fs_section.split("<<'PY'\n", 1)[1].split("\nop = sys.argv[1]", 1)[0]
op_body = fs_section.split("\nop = sys.argv[1]", 1)[1]

# Ensure cmd_migrate_record upgrades legacy phased stage/backup via upgrade-legacy-path-identity
# rather than closing descriptors and calling bare path-identity.
mig_fn = script_text.split("cmd_migrate_record() {\n", 1)[1].split("\n# ---- uninstall", 1)[0]
assert "upgrade-legacy-path-identity" in mig_fn, "cmd_migrate_record must use upgrade-legacy-path-identity"
legacy_branch = mig_fn.split('elif [ "$OPT_CONFIRM_VOLUMES" -eq 1 ] && [ "${REC_LEGACY_PHASED_IDS:-0}" -eq 1 ]; then', 1)[1]
assert 'fs_ops path-identity "' not in legacy_branch, (
    "legacy phased upgrade must NOT re-open path via bare fs_ops path-identity"
)

root = sys.argv[2]
target = os.path.join(root, ".qeminga-update-backup.atomic")
os.makedirs(target, mode=0o700)
os.chmod(target, 0o700)

def exec_fs_op(argv_args, hook=None):
    ns = {"__name__": "__main__"}
    old_argv = sys.argv[:]
    buf = io.StringIO()
    err_buf = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        exec(py_body, ns)
        if hook is not None:
            hook(ns)
        sys.argv = ["fs_ops"] + argv_args
        sys.stdout = buf
        sys.stderr = err_buf
        rc = 0
        try:
            exec("op = sys.argv[1]" + op_body, ns)
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        return rc, buf.getvalue().strip(), err_buf.getvalue().strip()
    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout
        sys.stderr = old_stderr

rc_v, vol, err_v = exec_fs_op(["volume-id", target])
assert rc_v == 0 and vol, err_v
pst = os.lstat(root)
tst = os.lstat(target)
legacy_id = f"p_dev:{pst.st_dev};p_ino:{pst.st_ino};p_mnt:1;t_dev:{tst.st_dev};t_ino:{tst.st_ino};t_mnt:1;vol:{vol}"

# 1. Genuine target: opens target basename EXACTLY ONCE and stamps `.qeminga-tx-id` on that same FD!
target_opens = []
real_open = os.open
def count_opens_hook(ns):
    orig_os = ns["os"]
    class SpyOs:
        def __getattr__(self, name):
            return getattr(orig_os, name)
        def open(self, path, *args, **kwargs):
            if path == os.path.basename(target):
                target_opens.append(path)
            return real_open(path, *args, **kwargs)
    ns["os"] = SpyOs()

rc_u, new_id, err_u = exec_fs_op(
    ["upgrade-legacy-path-identity", target, legacy_id, vol, "0"],
    hook=count_opens_hook,
)
assert rc_u == 0, f"upgrade-legacy-path-identity failed: rc={rc_u} err={err_u}"
assert len(target_opens) == 1, f"must open target dir exactly once to verify+stamp atomically, got {len(target_opens)}"
assert f"p_ino:{pst.st_ino};t_ino:{tst.st_ino};tx:" in new_id and new_id.endswith(f";vol:{vol}"), new_id
assert os.path.isfile(os.path.join(target, ".qeminga-tx-id")), "marker must be stamped in verified dir"

# 2. Substituted 0700 directory at same pathname -> MUST fail closed and NOT stamp `.qeminga-tx-id`!
held = os.path.join(root, ".qeminga-held-orig")
os.rename(target, held)
os.makedirs(target, mode=0o700)
os.chmod(target, 0o700)
rc_sub, _, err_sub = exec_fs_op(["upgrade-legacy-path-identity", target, legacy_id, vol, "0"])
assert rc_sub != 0, "substituted 0700 directory with different inode must be rejected"
assert not os.path.exists(os.path.join(target, ".qeminga-tx-id")), "substituted directory must NOT be stamped"

# 3. Interrupted marker creation before first write (simulating SIGKILL/power loss where cleanup
#    does not run): final `.qeminga-tx-id` MUST NEVER be created empty before writing, and retry
#    MUST clean any leftover private temp marker and succeed!
target_w = os.path.join(root, ".qeminga-update-backup.writecrash")
os.makedirs(target_w, mode=0o700)
os.chmod(target_w, 0o700)
tst_w = os.lstat(target_w)
legacy_id_w = f"p_dev:{pst.st_dev};p_ino:{pst.st_ino};p_mnt:1;t_dev:{tst_w.st_dev};t_ino:{tst_w.st_ino};t_mnt:1;vol:{vol}"
def fail_first_write_sigkill_hook(ns):
    orig_os = ns["os"]
    class SpyOs:
        def __getattr__(self, name):
            return getattr(orig_os, name)
        def write(self, fd, data):
            raise OSError(5, "simulated crash before first marker write")
        def unlink(self, path, *args, **kwargs):
            # Simulate abrupt SIGKILL where finally-block unlink never executes.
            return None
    ns["os"] = SpyOs()

rc_wc, _, err_wc = exec_fs_op(
    ["upgrade-legacy-path-identity", target_w, legacy_id_w, vol, "0"],
    hook=fail_first_write_sigkill_hook,
)
assert rc_wc != 0, "interrupted write must fail"
assert not os.path.exists(os.path.join(target_w, ".qeminga-tx-id")), (
    f"final .qeminga-tx-id must NEVER be created empty before writing; entries={os.listdir(target_w)}"
)
rc_wretry, new_id_w, err_wretry = exec_fs_op(
    ["upgrade-legacy-path-identity", target_w, legacy_id_w, vol, "0"]
)
assert rc_wretry == 0, f"retry after interrupted marker write must succeed: rc={rc_wretry} err={err_wretry}"
assert os.listdir(target_w) == [".qeminga-tx-id"], (
    f"retry must leave only .qeminga-tx-id with no stale temp markers: {os.listdir(target_w)}"
)
assert f"p_ino:{pst.st_ino};t_ino:{tst_w.st_ino};tx:" in new_id_w, new_id_w

# 4. Interrupted marker creation right after os.link before unlinking the temp sibling
#    (leaving `.qeminga-tx-id` and `.qeminga-tx-id.tmp.*` hardlinked with st_nlink == 2):
#    retry MUST unlink the verified stale temp sibling, restore st_nlink == 1, and return the
#    exact same token!
target_l = os.path.join(root, ".qeminga-update-backup.linkcrash")
os.makedirs(target_l, mode=0o700)
os.chmod(target_l, 0o700)
tst_l = os.lstat(target_l)
legacy_id_l = f"p_dev:{pst.st_dev};p_ino:{pst.st_ino};p_mnt:1;t_dev:{tst_l.st_dev};t_ino:{tst_l.st_ino};t_mnt:1;vol:{vol}"
def fail_temp_unlink_hook(ns):
    orig_os = ns["os"]
    class SpyOs:
        def __getattr__(self, name):
            return getattr(orig_os, name)
        def unlink(self, path, *args, **kwargs):
            if str(path).startswith(".qeminga-tx-id.tmp."):
                raise OSError(5, "simulated crash before temp marker unlink")
            return orig_os.unlink(path, *args, **kwargs)
    ns["os"] = SpyOs()

rc_lc, _, _ = exec_fs_op(
    ["upgrade-legacy-path-identity", target_l, legacy_id_l, vol, "0"],
    hook=fail_temp_unlink_hook,
)
assert rc_lc != 0, "simulated post-link unlink crash must fail"
assert os.path.isfile(os.path.join(target_l, ".qeminga-tx-id")), "linked marker should be present"
published_tok_l = open(os.path.join(target_l, ".qeminga-tx-id"), encoding="ascii").read().strip()
assert os.lstat(os.path.join(target_l, ".qeminga-tx-id")).st_nlink == 2, (
    f"expected st_nlink==2 before recovery, entries={os.listdir(target_l)}"
)
rc_lretry, new_id_l, err_lretry = exec_fs_op(
    ["upgrade-legacy-path-identity", target_l, legacy_id_l, vol, "0"]
)
assert rc_lretry == 0, f"retry after post-link crash must succeed: rc={rc_lretry} err={err_lretry}"
assert os.listdir(target_l) == [".qeminga-tx-id"], f"stale temp must be cleaned: {os.listdir(target_l)}"
assert os.lstat(os.path.join(target_l, ".qeminga-tx-id")).st_nlink == 1
assert f";tx:{published_tok_l};" in new_id_l, f"retry must return the published token {published_tok_l}, got {new_id_l}"

# 5. Failed container-directory `os.fsync(tfd)` after complete marker publication:
#    retry on the reuse path MUST sync `tfd` (and marker `mfd`) again rather than silently
#    returning an unsynced token!
target_f = os.path.join(root, ".qeminga-update-backup.fsyncfail")
os.makedirs(target_f, mode=0o700)
os.chmod(target_f, 0o700)
tst_f = os.lstat(target_f)
legacy_id_f = f"p_dev:{pst.st_dev};p_ino:{pst.st_ino};p_mnt:1;t_dev:{tst_f.st_dev};t_ino:{tst_f.st_ino};t_mnt:1;vol:{vol}"
fail_container_fsync = [True]
container_fsync_attempts = [0]
synced_inos_on_ok = []
def container_fsync_hook(ns):
    orig_os = ns["os"]
    class SpyOs:
        def __getattr__(self, name):
            return getattr(orig_os, name)
        def fsync(self, fd):
            st = orig_os.fstat(fd)
            if st.st_ino == tst_f.st_ino:
                container_fsync_attempts[0] += 1
                if fail_container_fsync[0]:
                    raise OSError(5, "simulated container dir fsync failure")
            synced_inos_on_ok.append(st.st_ino)
            return orig_os.fsync(fd)
    ns["os"] = SpyOs()

rc_f1, _, _ = exec_fs_op(
    ["upgrade-legacy-path-identity", target_f, legacy_id_f, vol, "0"],
    hook=container_fsync_hook,
)
assert rc_f1 != 0, "first call must fail when container-dir fsync fails"
assert os.path.isfile(os.path.join(target_f, ".qeminga-tx-id")), "marker was published before container fsync"
assert container_fsync_attempts[0] == 1

# Second call (reuse path) with container-dir fsync STILL failing -> MUST STILL fail!
rc_f2, out_f2, _ = exec_fs_op(
    ["upgrade-legacy-path-identity", target_f, legacy_id_f, vol, "0"],
    hook=container_fsync_hook,
)
assert rc_f2 != 0 and not out_f2, (
    f"reuse path MUST propagate persistent container-dir fsync failure instead of returning '{out_f2}'"
)
assert container_fsync_attempts[0] >= 2, "reuse path must attempt container-dir fsync"

# Third call (reuse path) once container-dir fsync succeeds -> MUST sync both marker and container!
fail_container_fsync[0] = False
synced_inos_on_ok.clear()
mst_f = os.lstat(os.path.join(target_f, ".qeminga-tx-id"))
rc_f3, new_id_f, err_f3 = exec_fs_op(
    ["upgrade-legacy-path-identity", target_f, legacy_id_f, vol, "0"],
    hook=container_fsync_hook,
)
assert rc_f3 == 0, f"retry once container fsync recovers must succeed: rc={rc_f3} err={err_f3}"
assert tst_f.st_ino in synced_inos_on_ok, "reuse path MUST fsync verified container directory tfd"
assert mst_f.st_ino in synced_inos_on_ok, "reuse path MUST fsync verified marker file mfd"
tok_f = open(os.path.join(target_f, ".qeminga-tx-id"), encoding="ascii").read().strip()
assert f";tx:{tok_f};" in new_id_f, new_id_f
"##,
            script().to_str().unwrap(),
            py_root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        py_check.status.success(),
        "atomic upgrade-legacy-path-identity verification failed: {}",
        text(&py_check)
    );
}

#[test]
fn uninstall_publishing_with_missing_live_dir_preserves_backup_on_journal_write_failure() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("pubmiss-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);
    let (v2_tb, v2_sha) =
        build_versioned_runner_pkg(dir.path(), &v2_src, "v2", "v2.tar.gz", &cfg_sh);

    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active) echo "inactive"; exit 3 ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "pubmiss-box",
            "--service",
            "qeminga-pubmiss-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // Crash an update mid-publish -> `UPDATE_PHASE=publishing` + verified backup container.
    let crash = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert_eq!(crash.status.code(), Some(99), "{}", text(&crash));
    let rec_pub = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(rec_pub.contains("UPDATE_PHASE=publishing\n"), "{rec_pub}");
    let bk_pub = PathBuf::from(
        rec_pub
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );
    assert!(bk_pub.is_dir() && bk_pub.join(".qeminga-tx-id").is_file());

    // Move live runner directory aside so it is absent on the recorded volume.
    let inst_aside = dir.path().join("opt-runner-aside");
    std::fs::rename(&inst, &inst_aside).unwrap();
    assert!(!inst.exists());

    // 1. Fail the next journal write BEFORE rename (by making `cfg` read-only 0500):
    //    `uninstall` MUST fail closed while leaving `install.env` at `UPDATE_PHASE=publishing`
    //    AND keeping `bk_pub` completely intact on disk!
    struct RestoreDirMode(PathBuf);
    impl Drop for RestoreDirMode {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        }
    }
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o500)).unwrap();
    let cfg_guard = RestoreDirMode(cfg.clone());

    let uninst_ro_fail = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_ro_fail.status.success(),
        "uninstall must fail when journal write fails before rename: {}",
        text(&uninst_ro_fail)
    );
    let rec_after_ro = std::fs::read_to_string(cfg.join("install.env")).unwrap();
    assert!(
        rec_after_ro.contains("UPDATE_PHASE=publishing\n"),
        "journal should still show publishing after pre-rename write failure:\n{rec_after_ro}"
    );
    assert!(
        bk_pub.is_dir() && bk_pub.join(".qeminga-tx-id").is_file(),
        "uninstall MUST preserve publishing backup when journal write fails before rename: {}",
        text(&uninst_ro_fail)
    );

    drop(cfg_guard);

    // 2. Fail the pre-prune journal write AFTER rename on parent-dir fsync:
    //    `uninstall` MUST ALSO preserve `bk_pub` on disk!
    let uninst_sync_fail = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            (
                "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                "install.env:UPDATE_PHASE=restored",
            ),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !uninst_sync_fail.status.success() && bk_pub.is_dir(),
        "uninstall MUST preserve backup while post-rename config-dir fsync fails: {}",
        text(&uninst_sync_fail)
    );

    // 3. Normal retry with writable cfg and working fsync succeeds cleanly and prunes backup!
    let uninst_ok = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        uninst_ok.status.success() && !bk_pub.exists(),
        "normal uninstall retry must cleanly discard backup and finish uninstall: {}",
        text(&uninst_ok)
    );
}

#[test]
fn recovery_persists_newly_observed_running_state_before_stopping_service() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("intent-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);
    let (v2_tb, v2_sha) =
        build_versioned_runner_pkg(dir.path(), &v2_src, "v2", "v2.tar.gz", &cfg_sh);

    let state_file = dir.path().join("svc.state");
    let post_stop_fail_flag = dir.path().join("fail-after-stop.flag");
    let rec_seen_at_stop = dir.path().join("rec-seen-at-stop.txt");
    std::fs::write(&state_file, "inactive\n").unwrap();

    write_mock_systemctl(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show) echo "not-found"; exit 0 ;;
    is-active)
        if [ -f "${FAKE_POST_STOP_ARMED:-}" ]; then
            rm -f "$FAKE_POST_STOP_ARMED"
            echo "Failed to connect to bus: simulated post-stop status error" >&2
            exit 1
        fi
        st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
        case "$st" in
            active) echo active; exit 0 ;;
            inactive) echo inactive; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        if [ -n "${FAKE_REC_PATH:-}" ] && [ -n "${FAKE_REC_AT_STOP_OUT:-}" ] && [ -f "$FAKE_REC_PATH" ]; then
            grep -E '^UPDATE_WAS_ACTIVE=' "$FAKE_REC_PATH" > "$FAKE_REC_AT_STOP_OUT" || true
        fi
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        if [ "${FAKE_FAIL_NEXT_IS_ACTIVE_AFTER_STOP:-0}" = "1" ] && [ -n "${FAKE_POST_STOP_ARMED:-}" ]; then
            : > "$FAKE_POST_STOP_ARMED"
        fi
        exit 0
        ;;
    start | enable)
        echo "active" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let rec_path = cfg.join("install.env");
    let unit_dir = units.to_str().unwrap();

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "intent-box",
            "--service",
            "qeminga-intent-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // 1. `UPDATE_PHASE=restored` with `UPDATE_WAS_ACTIVE=0` while service IS `active`:
    //    Fail ONLY the status query immediately after `systemctl stop`.
    //    `UPDATE_WAS_ACTIVE=1` MUST already be persisted BEFORE `systemctl stop` runs, so the
    //    retry (which sees `inactive`) remembers restart intent and leaves the runner `active`!
    let base_rec = std::fs::read_to_string(&rec_path).unwrap();
    std::fs::write(
        &rec_path,
        base_rec.replace(
            "RECORD_STATE=installed\n",
            "RECORD_STATE=updating\nUPDATE_PHASE=restored\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR=\nUPDATE_BACKUP_ID=\nUPDATE_WAS_ACTIVE=0\n",
        ),
    )
    .unwrap();
    std::fs::write(&state_file, "active\n").unwrap();
    let _ = std::fs::remove_file(&rec_seen_at_stop);
    let _ = std::fs::remove_file(&post_stop_fail_flag);

    let rest_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_REC_PATH", rec_path.to_str().unwrap()),
            ("FAKE_REC_AT_STOP_OUT", rec_seen_at_stop.to_str().unwrap()),
            (
                "FAKE_POST_STOP_ARMED",
                post_stop_fail_flag.to_str().unwrap(),
            ),
            ("FAKE_FAIL_NEXT_IS_ACTIVE_AFTER_STOP", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !rest_fail.status.success(),
        "restored recovery must fail when post-stop status check fails: {}",
        text(&rest_fail)
    );
    assert_eq!(
        std::fs::read_to_string(&state_file).unwrap().trim(),
        "inactive"
    );
    assert_eq!(
        std::fs::read_to_string(&rec_seen_at_stop)
            .unwrap_or_default()
            .trim(),
        "UPDATE_WAS_ACTIVE=1",
        "restored recovery MUST persist UPDATE_WAS_ACTIVE=1 BEFORE invoking systemctl stop"
    );
    assert!(
        std::fs::read_to_string(&rec_path)
            .unwrap()
            .contains("UPDATE_WAS_ACTIVE=1\n"),
        "install.env must retain UPDATE_WAS_ACTIVE=1 after post-stop failure"
    );

    let rest_retry = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        rest_retry.status.success(),
        "restored retry must succeed: {}",
        text(&rest_retry)
    );
    assert_eq!(
        std::fs::read_to_string(&state_file).unwrap().trim(),
        "active",
        "restored retry must restart runner based on persisted UPDATE_WAS_ACTIVE=1"
    );

    // 2. `UPDATE_PHASE=publishing` with `UPDATE_WAS_ACTIVE=0` while service IS `active`:
    //    Crash update while `inactive` (`UPDATE_WAS_ACTIVE=0`), then set service `active`,
    //    fail post-stop status check -> `UPDATE_WAS_ACTIVE=1` MUST be persisted BEFORE `stop`
    //    (keeping `UPDATE_PHASE=publishing` and backup intact), and retry MUST restart service!
    std::fs::write(&state_file, "inactive\n").unwrap();
    let crash = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_TEST_CRASH_PUBLISH_AFTER", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert_eq!(crash.status.code(), Some(99), "{}", text(&crash));
    let pub_rec_initial = std::fs::read_to_string(&rec_path).unwrap();
    assert!(
        pub_rec_initial.contains("UPDATE_PHASE=publishing\n")
            && pub_rec_initial.contains("UPDATE_WAS_ACTIVE=0\n"),
        "expected publishing journal with UPDATE_WAS_ACTIVE=0:\n{pub_rec_initial}"
    );
    let bk_pub = PathBuf::from(
        pub_rec_initial
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_BACKUP_DIR="))
            .unwrap(),
    );

    std::fs::write(&state_file, "active\n").unwrap();
    let _ = std::fs::remove_file(&rec_seen_at_stop);
    let _ = std::fs::remove_file(&post_stop_fail_flag);

    let pub_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_REC_PATH", rec_path.to_str().unwrap()),
            ("FAKE_REC_AT_STOP_OUT", rec_seen_at_stop.to_str().unwrap()),
            (
                "FAKE_POST_STOP_ARMED",
                post_stop_fail_flag.to_str().unwrap(),
            ),
            ("FAKE_FAIL_NEXT_IS_ACTIVE_AFTER_STOP", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !pub_fail.status.success() && bk_pub.is_dir(),
        "publishing recovery must fail and keep backup when post-stop check fails: {}",
        text(&pub_fail)
    );
    assert_eq!(
        std::fs::read_to_string(&state_file).unwrap().trim(),
        "inactive"
    );
    assert_eq!(
        std::fs::read_to_string(&rec_seen_at_stop)
            .unwrap_or_default()
            .trim(),
        "UPDATE_WAS_ACTIVE=1",
        "publishing recovery MUST persist UPDATE_WAS_ACTIVE=1 BEFORE invoking systemctl stop"
    );
    let pub_rec_after = std::fs::read_to_string(&rec_path).unwrap();
    assert!(
        pub_rec_after.contains("UPDATE_PHASE=publishing\n")
            && pub_rec_after.contains("UPDATE_WAS_ACTIVE=1\n"),
        "install.env must keep publishing phase and UPDATE_WAS_ACTIVE=1:\n{pub_rec_after}"
    );

    let pub_retry = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        pub_retry.status.success(),
        "publishing retry must succeed: {}",
        text(&pub_retry)
    );
    assert_eq!(
        std::fs::read_to_string(&state_file).unwrap().trim(),
        "active",
        "publishing retry must restart runner based on persisted UPDATE_WAS_ACTIVE=1"
    );
}

#[test]
fn uninstall_verifies_resolved_unit_fragment_and_clears_runtime_enablement_with_real_systemctl_root()
 {
    let real_systemctl = Path::new("/usr/bin/systemctl");
    if !real_systemctl.is_file() {
        return;
    }

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let iso_root = dir.path().join("iso-root");
    let etc_units = iso_root.join("etc/systemd/system");
    let run_units = iso_root.join("run/systemd/system");
    let usr_units = iso_root.join("usr/lib/systemd/system");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    for d in [
        &bin,
        &etc_units,
        &run_units,
        &usr_units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("realsc-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);

    let state_file = dir.path().join("svc.state");
    let sc_log = dir.path().join("sc.log");
    std::fs::write(&state_file, "inactive\n").unwrap();

    // Wrapper delegating enable/disable/is-enabled directly to REAL `/usr/bin/systemctl --root`
    // against `iso_root` (zero running systemd manager needed!), while simulating `is-active`,
    // `stop`, and optional live-manager `show` output.
    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ -n "${FAKE_SC_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_SC_LOG"; fi
case "$1" in
    is-active)
        st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
        case "$st" in
            active) echo active; exit 0 ;;
            inactive) echo inactive; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    daemon-reload | start)
        exit 0
        ;;
    show)
        if [ -n "${FAKE_SHOW_OUT:-}" ]; then
            printf '%s\n' "$FAKE_SHOW_OUT"
            exit 0
        fi
        exec /usr/bin/systemctl --root "${FAKE_SYSTEMD_ROOT:?}" "$@"
        ;;
    list-unit-files)
        exec /usr/bin/systemctl --root "${FAKE_SYSTEMD_ROOT:?}" "$@"
        ;;
    enable | disable | is-enabled | --runtime)
        exec /usr/bin/systemctl --root "${FAKE_SYSTEMD_ROOT:?}" "$@"
        ;;
    *)
        exec /usr/bin/systemctl --root "${FAKE_SYSTEMD_ROOT:?}" "$@"
        ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_name = "qeminga-realsc-box.service";
    let unit_dirs = format!(
        "{}:{}:{}",
        etc_units.display(),
        run_units.display(),
        usr_units.display()
    );

    let do_install = || {
        let out = run_setup_env(
            &[
                "install",
                "--repo",
                REPO_URL,
                "--name",
                "realsc-box",
                "--service",
                "qeminga-realsc-box",
                "--install-dir",
                inst.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
                "--hook-dir",
                hooks.to_str().unwrap(),
                "--config-dir",
                cfg.to_str().unwrap(),
                "--token-file",
                reg_file.to_str().unwrap(),
                "--runner-sha256",
                &v1_sha,
                "--skip-packages",
                "--no-start",
            ],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
                ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
                ("FAKE_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", etc_units.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ],
            Some(&bin),
        );
        assert!(out.status.success(), "install failed: {}", text(&out));
    };

    // 1. Runtime + persistent enablement with REAL `systemctl --root`:
    //    Enable unit BOTH persistently and with `--runtime`. Plain `systemctl disable` leaves
    //    `enabled-runtime` + `/run` symlink behind; `uninstall` MUST clear BOTH scopes!
    do_install();
    let en_pers = Command::new(real_systemctl)
        .args(["--root", iso_root.to_str().unwrap(), "enable", unit_name])
        .output()
        .unwrap();
    assert!(en_pers.status.success(), "{}", text(&en_pers));
    let en_rt = Command::new(real_systemctl)
        .args([
            "--root",
            iso_root.to_str().unwrap(),
            "enable",
            "--runtime",
            unit_name,
        ])
        .output()
        .unwrap();
    assert!(en_rt.status.success(), "{}", text(&en_rt));

    let etc_wants = etc_units.join("multi-user.target.wants").join(unit_name);
    let run_wants = run_units.join("multi-user.target.wants").join(unit_name);
    assert!(etc_wants.symlink_metadata().is_ok() && run_wants.symlink_metadata().is_ok());

    let uninst_rt = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", etc_units.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs),
        ],
        Some(&bin),
    );
    assert!(
        uninst_rt.status.success(),
        "uninstall MUST clear both persistent and --runtime enablement links: {}",
        text(&uninst_rt)
    );
    assert!(
        etc_wants.symlink_metadata().is_err()
            && run_wants.symlink_metadata().is_err()
            && !etc_units.join(unit_name).exists(),
        "both /etc and /run enablement links and unit file must be removed"
    );

    // 2. Missing managed `/etc` unit shadowed by a same-name vendor unit in `/usr/lib/systemd/system`:
    //    `uninstall` MUST verify resolved unit identity BEFORE stopping or disabling, preserving
    //    the vendor unit, its active state, its enablement link, and `install.env` (`OWNED_UNIT=1`)!
    do_install();
    std::fs::remove_file(etc_units.join(unit_name)).unwrap();
    let vendor_unit = usr_units.join(unit_name);
    std::fs::write(
        &vendor_unit,
        "[Unit]\nDescription=Unrelated vendor unit\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
    )
    .unwrap();
    let en_vendor = Command::new(real_systemctl)
        .args(["--root", iso_root.to_str().unwrap(), "enable", unit_name])
        .output()
        .unwrap();
    assert!(en_vendor.status.success(), "{}", text(&en_vendor));
    assert!(etc_wants.symlink_metadata().is_ok());

    std::fs::write(&state_file, "active\n").unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let uninst_vendor = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", etc_units.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs),
        ],
        Some(&bin),
    );
    let vendor_sc = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        !uninst_vendor.status.success(),
        "uninstall MUST refuse when managed /etc unit is missing and vendor unit occupies name: {}",
        text(&uninst_vendor)
    );
    assert!(
        vendor_unit.is_file()
            && etc_wants.symlink_metadata().is_ok()
            && std::fs::read_to_string(&state_file).unwrap().trim() == "active"
            && !vendor_sc.contains("stop ")
            && !vendor_sc.contains("disable ")
            && std::fs::read_to_string(cfg.join("install.env"))
                .unwrap()
                .contains("OWNED_UNIT=1\n"),
        "unrelated vendor unit, its active state, its enablement link, and OWNED_UNIT=1 MUST all be preserved (sc_log:\n{vendor_sc}): {}",
        text(&uninst_vendor)
    );

    // 3. Live manager `FragmentPath` mismatch: even if `/etc` fragment exists on disk, if the
    //    manager reports `FragmentPath=/usr/lib/systemd/system/<unit>`, `uninstall` MUST refuse
    //    BEFORE calling `stop` or `disable`!
    let dis_vendor = Command::new(real_systemctl)
        .args(["--root", iso_root.to_str().unwrap(), "disable", unit_name])
        .output()
        .unwrap();
    assert!(dis_vendor.status.success(), "{}", text(&dis_vendor));
    std::fs::remove_file(&vendor_unit).unwrap();
    std::fs::write(
        etc_units.join(unit_name),
        "[Unit]\nDescription=managed\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
    )
    .unwrap();
    let _ = std::fs::remove_file(&sc_log);
    let show_mismatch =
        format!("LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/{unit_name}");
    let uninst_frag_mismatch = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
            ("FAKE_SHOW_OUT", &show_mismatch),
            ("FAKE_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_ROOT", iso_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", etc_units.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", &unit_dirs),
        ],
        Some(&bin),
    );
    let frag_sc = std::fs::read_to_string(&sc_log).unwrap_or_default();
    assert!(
        !uninst_frag_mismatch.status.success()
            && !frag_sc.contains("stop ")
            && !frag_sc.contains("disable ")
            && std::fs::read_to_string(&state_file).unwrap().trim() == "active",
        "uninstall MUST refuse before stop/disable when manager FragmentPath differs (sc_log:\n{frag_sc}): {}",
        text(&uninst_frag_mismatch)
    );
}

#[test]
fn verify_resolved_unit_fragment_fails_closed_on_show_error_and_empty_output() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("showerr-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);

    let state_file = dir.path().join("svc.state");
    let sc_log = dir.path().join("sc.log");
    std::fs::write(&state_file, "inactive\n").unwrap();

    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
if [ -n "${FAKE_SC_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_SC_LOG"; fi
case "$1" in
    show)
        # Support check_unit_not_occupied (`show -p LoadState --value`) during install
        for a in "$@"; do
            if [ "$a" = "--value" ]; then echo "not-found"; exit 0; fi
        done
        if [ "${FAKE_SHOW_MODE:-ok}" = "error" ]; then
            echo "Failed to connect to bus" >&2
            exit 1
        elif [ "${FAKE_SHOW_MODE:-ok}" = "empty" ]; then
            exit 0
        elif [ "${FAKE_SHOW_MODE:-ok}" = "no_frag" ]; then
            echo "LoadState=loaded"
            echo "FragmentPath="
            exit 0
        else
            echo "LoadState=loaded"
            echo "FragmentPath=${FAKE_EXPECTED_FRAG:?}"
            exit 0
        fi
        ;;
    is-active)
        st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
        case "$st" in
            active) echo active; exit 0 ;;
            inactive) echo inactive; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    is-enabled)
        echo "disabled"; exit 1
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let unit_dir = units.to_str().unwrap();
    let unit_file = units.join("qeminga-showerr-box.service");

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "showerr-box",
            "--service",
            "qeminga-showerr-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));
    assert!(unit_file.is_file());

    // Even with a regular local unit file present, `systemctl show` failing, returning empty
    // output, or returning `LoadState=loaded` with empty `FragmentPath=` MUST fail closed
    // BEFORE `stop` or `disable`!
    for bad_mode in ["error", "empty", "no_frag"] {
        std::fs::write(&state_file, "active\n").unwrap();
        let _ = std::fs::remove_file(&sc_log);
        let uninst = run_setup_env(
            &["uninstall", "--config-dir", cfg.to_str().unwrap()],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
                ("FAKE_SC_LOG", sc_log.to_str().unwrap()),
                ("FAKE_SHOW_MODE", bad_mode),
                ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ],
            Some(&bin),
        );
        let logged = std::fs::read_to_string(&sc_log).unwrap_or_default();
        assert!(
            !uninst.status.success()
                && !logged.contains("stop ")
                && !logged.contains("disable ")
                && std::fs::read_to_string(&state_file).unwrap().trim() == "active"
                && cfg.join("install.env").is_file(),
            "mode={bad_mode}: uninstall MUST fail closed before stop/disable when live fragment cannot be verified (sc_log:\n{logged}): {}",
            text(&uninst)
        );
    }

    // With a matching live `LoadState=loaded` + `FragmentPath=<unit_file>`, uninstall succeeds!
    std::fs::write(&state_file, "active\n").unwrap();
    let uninst_ok = run_setup_env(
        &["uninstall", "--config-dir", cfg.to_str().unwrap()],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_SHOW_MODE", "ok"),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        uninst_ok.status.success() && !unit_file.exists(),
        "uninstall with confirmed live FragmentPath should succeed: {}",
        text(&uninst_ok)
    );
}

#[test]
fn retry_reconfirms_durable_restart_intent_before_stop_even_when_visible_flag_is_one() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("reconfirm-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);
    let (v2_tb, v2_sha) =
        build_versioned_runner_pkg(dir.path(), &v2_src, "v2", "v2.tar.gz", &cfg_sh);

    let state_file = dir.path().join("svc.state");
    let sc_count = dir.path().join("is_active.count");
    let post_stop_armed = dir.path().join("post_stop.armed");
    let rec_at_stop = dir.path().join("rec_at_stop.txt");
    std::fs::write(&state_file, "inactive\n").unwrap();

    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show)
        for a in "$@"; do
            if [ "$a" = "--value" ]; then echo "not-found"; exit 0; fi
        done
        echo "LoadState=loaded"
        echo "FragmentPath=${FAKE_EXPECTED_FRAG:?}"
        exit 0
        ;;
    is-active)
        if [ -n "${FAKE_POST_STOP_ARMED:-}" ] && [ -f "${FAKE_POST_STOP_ARMED}" ]; then
            rm -f "${FAKE_POST_STOP_ARMED}"
            echo "Failed to connect to bus" >&2
            exit 1
        fi
        if [ -n "${FAKE_FLIP_ACTIVE_ON_CALL:-}" ] && [ -n "${FAKE_SC_COUNT:-}" ]; then
            c="$(cat "${FAKE_SC_COUNT}" 2>/dev/null || echo 0)"
            c=$((c + 1))
            echo "$c" > "${FAKE_SC_COUNT}"
            if [ "$c" -eq "${FAKE_FLIP_ACTIVE_ON_CALL}" ]; then
                echo "active" > "${FAKE_STATE_FILE:?}"
            fi
        fi
        st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
        case "$st" in
            active) echo active; exit 0 ;;
            inactive) echo inactive; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        if [ -n "${FAKE_REC_PATH:-}" ] && [ -n "${FAKE_REC_AT_STOP_OUT:-}" ]; then
            grep '^UPDATE_WAS_ACTIVE=' "$FAKE_REC_PATH" > "$FAKE_REC_AT_STOP_OUT" 2>/dev/null || true
        fi
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        if [ "${FAKE_FAIL_NEXT_IS_ACTIVE_AFTER_STOP:-0}" = "1" ] && [ -n "${FAKE_POST_STOP_ARMED:-}" ]; then
            : > "${FAKE_POST_STOP_ARMED}"
        fi
        exit 0
        ;;
    start)
        echo "active" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = dir.path().join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let rec_path = cfg.join("install.env");
    let unit_dir = units.to_str().unwrap();
    let unit_file = units.join("qeminga-reconfirm-box.service");

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "reconfirm-box",
            "--service",
            "qeminga-reconfirm-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    // 1. Restored journal with UPDATE_WAS_ACTIVE=0 while service IS active:
    //    Fail post-rename dir fsync on `install.env:UPDATE_WAS_ACTIVE=1` TWICE in a row!
    //    After attempt 1, `UPDATE_WAS_ACTIVE=1` is visible on disk (unsynced) and service is active.
    //    Attempt 2 MUST STILL re-sync `UPDATE_WAS_ACTIVE=1` BEFORE stopping — so while the sync
    //    error persists, attempt 2 MUST ALSO fail BEFORE calling `systemctl stop`!
    let base_rec = std::fs::read_to_string(&rec_path).unwrap();
    std::fs::write(
        &rec_path,
        base_rec.replace(
            "RECORD_STATE=installed\n",
            "RECORD_STATE=updating\nUPDATE_PHASE=restored\nUPDATE_STAGE_DIR=\nUPDATE_STAGE_ID=\nUPDATE_BACKUP_DIR=\nUPDATE_BACKUP_ID=\nUPDATE_WAS_ACTIVE=0\n",
        ),
    )
    .unwrap();
    std::fs::write(&state_file, "active\n").unwrap();

    for attempt in [1, 2] {
        let fail_out = run_setup_env(
            &[
                "update",
                "--config-dir",
                cfg.to_str().unwrap(),
                "--runner-sha256",
                &v2_sha,
            ],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
                ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
                ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
                (
                    "QEMINGA_TEST_FAIL_REPLACE_DIR_FSYNC",
                    "install.env:UPDATE_WAS_ACTIVE=1",
                ),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ],
            Some(&bin),
        );
        assert!(
            !fail_out.status.success(),
            "attempt {attempt}: update must fail while UPDATE_WAS_ACTIVE=1 dir fsync fails: {}",
            text(&fail_out)
        );
        assert_eq!(
            std::fs::read_to_string(&state_file).unwrap().trim(),
            "active",
            "attempt {attempt}: MUST NOT stop service while durable restart intent sync fails (even when visible flag is already 1)"
        );
        assert!(
            std::fs::read_to_string(&rec_path)
                .unwrap()
                .contains("UPDATE_WAS_ACTIVE=1\n")
        );
    }

    // Attempt 3 without sync error succeeds and restarts the runner (`active`).
    let ok_rest = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(ok_rest.status.success(), "{}", text(&ok_rest));
    assert_eq!(
        std::fs::read_to_string(&state_file).unwrap().trim(),
        "active"
    );

    // 2. Forward `cmd_update`: unit is `inactive` during pre-download (call 1) and post-download
    //    (call 2), so `publishing` is written with `UPDATE_WAS_ACTIVE=0`. Right before
    //    `ensure_owned_service_stopped` (call 3), the unit becomes `active`, and ONLY the
    //    post-stop `is-active` query fails! Forward update MUST persist `UPDATE_WAS_ACTIVE=1`
    //    BEFORE calling `systemctl stop`!
    std::fs::write(&state_file, "inactive\n").unwrap();
    let _ = std::fs::remove_file(&sc_count);
    let _ = std::fs::remove_file(&post_stop_armed);
    let _ = std::fs::remove_file(&rec_at_stop);
    let fwd_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("FAKE_SC_COUNT", sc_count.to_str().unwrap()),
            ("FAKE_FLIP_ACTIVE_ON_CALL", "3"),
            ("FAKE_REC_PATH", rec_path.to_str().unwrap()),
            ("FAKE_REC_AT_STOP_OUT", rec_at_stop.to_str().unwrap()),
            ("FAKE_POST_STOP_ARMED", post_stop_armed.to_str().unwrap()),
            ("FAKE_FAIL_NEXT_IS_ACTIVE_AFTER_STOP", "1"),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(
        !fwd_fail.status.success(),
        "forward update must fail when post-stop check fails: {}",
        text(&fwd_fail)
    );
    assert_eq!(
        std::fs::read_to_string(&rec_at_stop)
            .unwrap_or_default()
            .trim(),
        "UPDATE_WAS_ACTIVE=1",
        "forward update MUST durably persist UPDATE_WAS_ACTIVE=1 BEFORE invoking systemctl stop"
    );
    let post_exit_state = std::fs::read_to_string(&state_file).unwrap();
    let post_exit_rec = std::fs::read_to_string(&rec_path).unwrap();
    assert!(
        post_exit_state.trim() == "active"
            || (post_exit_rec.contains("RECORD_STATE=updating\n")
                && post_exit_rec.contains("UPDATE_WAS_ACTIVE=1\n")),
        "forward update rollback MUST either restart the stopped service or preserve recoverable UPDATE_WAS_ACTIVE=1 (got state={:?}, record:\n{post_exit_rec})",
        post_exit_state.trim()
    );
    assert_eq!(
        post_exit_state.trim(),
        "active",
        "when rollback stop-check and start succeed, forward update rollback must restart the service"
    );

    // 3. Forward transactional reinstall (`cmd_install` on existing installation):
    //    Same late-activation + post-stop query failure scenario -> rollback MUST honor the
    //    newly recorded UPDATE_WAS_ACTIVE=1 and restart the service instead of leaving it
    //    inactive with RECORD_STATE=installed.
    std::fs::write(&state_file, "inactive\n").unwrap();
    let _ = std::fs::remove_file(&sc_count);
    let _ = std::fs::remove_file(&post_stop_armed);
    let _ = std::fs::remove_file(&rec_at_stop);
    let fwd_reinst_fail = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "reconfirm-box",
            "--service",
            "qeminga-reconfirm-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("FAKE_SC_COUNT", sc_count.to_str().unwrap()),
            ("FAKE_FLIP_ACTIVE_ON_CALL", "3"),
            ("FAKE_REC_PATH", rec_path.to_str().unwrap()),
            ("FAKE_REC_AT_STOP_OUT", rec_at_stop.to_str().unwrap()),
            ("FAKE_POST_STOP_ARMED", post_stop_armed.to_str().unwrap()),
            ("FAKE_FAIL_NEXT_IS_ACTIVE_AFTER_STOP", "1"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !fwd_reinst_fail.status.success(),
        "forward reinstall must fail when post-stop check fails: {}",
        text(&fwd_reinst_fail)
    );
    assert_eq!(
        std::fs::read_to_string(&rec_at_stop)
            .unwrap_or_default()
            .trim(),
        "UPDATE_WAS_ACTIVE=1",
        "forward reinstall MUST durably persist UPDATE_WAS_ACTIVE=1 BEFORE invoking systemctl stop"
    );
    let reinst_state = std::fs::read_to_string(&state_file).unwrap();
    let reinst_rec = std::fs::read_to_string(&rec_path).unwrap();
    assert!(
        reinst_state.trim() == "active"
            || (reinst_rec.contains("RECORD_STATE=updating\n")
                && reinst_rec.contains("UPDATE_WAS_ACTIVE=1\n")),
        "forward reinstall rollback MUST either restart the stopped service or preserve recoverable UPDATE_WAS_ACTIVE=1 (got state={:?}, record:\n{reinst_rec})",
        reinst_state.trim()
    );
    assert_eq!(
        reinst_state.trim(),
        "active",
        "when rollback stop-check and start succeed, forward reinstall rollback must restart the service"
    );
}

#[test]
fn rollback_stop_retains_stage_reference_when_stage_prune_and_restore_fail() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("etc-systemd");
    let rt_root = dir.path().join("run");
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        &bin,
        &units,
        &rt_root,
        &v1_src.join("bin"),
        &v1_src.join("externals"),
        &v2_src.join("bin"),
        &v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    install_standard_mock_bin(&bin);

    let cfg_sh = runner_registration_config_script("stage-retain-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);
    let (v2_tb, v2_sha) =
        build_versioned_runner_pkg(dir.path(), &v2_src, "v2", "v2.tar.gz", &cfg_sh);

    let state_file = dir.path().join("svc.state");
    let sc_count = dir.path().join("is_active.count");
    let inst_parent = dir.path().join("install-parent");
    std::fs::create_dir_all(&inst_parent).unwrap();
    std::fs::write(&state_file, "inactive\n").unwrap();

    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show)
        for a in "$@"; do
            if [ "$a" = "--value" ]; then echo "not-found"; exit 0; fi
        done
        echo "LoadState=loaded"
        echo "FragmentPath=${FAKE_EXPECTED_FRAG:?}"
        exit 0
        ;;
    is-active)
        if [ -n "${FAKE_ARM_READONLY_ON_CALL:-}" ] && [ -n "${FAKE_SC_COUNT:-}" ]; then
            c="$(cat "${FAKE_SC_COUNT}" 2>/dev/null || echo 0)"
            c=$((c + 1))
            echo "$c" > "${FAKE_SC_COUNT}"
            if [ "$c" -eq "${FAKE_ARM_READONLY_ON_CALL}" ]; then
                # Arm real EACCES on publish-runner-stage, rollback safe-rmtree-id, and
                # restore-runner-backup while flipping service active for rollback stop!
                for p in "${FAKE_INST_PARENT:?}"/.qeminga-extract.* "${FAKE_INST_PARENT:?}"/opt-runner "${FAKE_INST_PARENT:?}"; do
                    [ -d "$p" ] && chmod 0500 "$p" || true
                done
                if [ "${FAKE_FAIL_RESTORE_TOO:-1}" = "1" ]; then
                    for b in "${FAKE_INST_PARENT:?}"/.qeminga-update-backup.*; do
                        [ -d "$b" ] && chmod 0000 "$b" || true
                    done
                fi
                echo "active" > "${FAKE_STATE_FILE:?}"
                echo inactive
                exit 3
            fi
        fi
        st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
        case "$st" in
            active) echo active; exit 0 ;;
            inactive) echo inactive; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    start)
        echo "active" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = inst_parent.join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let rec_path = cfg.join("install.env");
    let unit_dir = units.to_str().unwrap();
    let unit_file = units.join("qeminga-stage-retain-box.service");

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "stage-retain-box",
            "--service",
            "qeminga-stage-retain-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    let upd_fail = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("FAKE_SC_COUNT", sc_count.to_str().unwrap()),
            ("FAKE_ARM_READONLY_ON_CALL", "3"),
            ("FAKE_INST_PARENT", inst_parent.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    // Restore write permissions so temp cleanup and retry can proceed cleanly.
    std::fs::set_permissions(&inst_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ = std::fs::set_permissions(&inst, std::fs::Permissions::from_mode(0o755));
    for entry in std::fs::read_dir(&inst_parent).unwrap().flatten() {
        let p = entry.path();
        if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            n.starts_with(".qeminga-extract.") || n.starts_with(".qeminga-update-backup.")
        }) {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
        }
    }
    assert!(!upd_fail.status.success(), "{}", text(&upd_fail));

    let rec_after = std::fs::read_to_string(&rec_path).unwrap();
    let stage_dir_val = rec_after
        .lines()
        .find_map(|l| l.strip_prefix("UPDATE_STAGE_DIR="))
        .unwrap_or("");
    let stage_id_val = rec_after
        .lines()
        .find_map(|l| l.strip_prefix("UPDATE_STAGE_ID="))
        .unwrap_or("");
    assert!(
        rec_after.contains("RECORD_STATE=updating\n")
            && rec_after.contains("UPDATE_PHASE=publishing\n")
            && rec_after.contains("UPDATE_WAS_ACTIVE=1\n"),
        "rollback stop must persist UPDATE_WAS_ACTIVE=1 in publishing journal:\n{rec_after}"
    );
    assert!(
        !stage_dir_val.is_empty()
            && !stage_id_val.is_empty()
            && std::path::Path::new(stage_dir_val).is_dir(),
        "rollback stop MUST retain UPDATE_STAGE_DIR and UPDATE_STAGE_ID when stage pruning failed:\n{rec_after}"
    );

    // Retry without fault injection reclaims the retained staging dir, recovers backup,
    // applies v2, and restarts the service (`active`)!
    let retry_ok = run_setup_env(
        &[
            "update",
            "--config-dir",
            cfg.to_str().unwrap(),
            "--runner-sha256",
            &v2_sha,
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
        ],
        Some(&bin),
    );
    assert!(retry_ok.status.success(), "{}", text(&retry_ok));
    assert!(
        !std::path::Path::new(stage_dir_val).exists(),
        "retry must reclaim the preserved staging directory {stage_dir_val}"
    );
    assert_eq!(
        std::fs::read_to_string(&state_file).unwrap().trim(),
        "active",
        "retry must honor preserved UPDATE_WAS_ACTIVE=1 and restart the service"
    );
}

#[test]
fn restored_journal_retains_unpruned_stage_and_inspect_is_readonly_and_fail_closed() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let units = dir.path().join("units");
    let rt_root = dir.path().join("rt");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&units).unwrap();
    std::fs::create_dir_all(&rt_root).unwrap();

    // Part 1: Direct unit check of read-only `fs_ops inspect-path-identity`:
    //   - Never creates `.qeminga-tx-id` in an empty post-marker-unlink dir (returns `match`).
    //   - Never creates `.qeminga-tx-id` in a forged replacement dir (returns `mismatch`).
    //   - Returns `absent` when the path is missing.
    //   - Exits non-zero (indeterminate, never `mismatch`) on EACCES (`chmod 0000`)!
    let inspect_parent = dir.path().join("inspect-parent");
    std::fs::create_dir_all(&inspect_parent).unwrap();
    let stage_a = inspect_parent.join(".qeminga-extract.empty1");
    std::fs::create_dir(&stage_a).unwrap();
    std::fs::set_permissions(&stage_a, std::fs::Permissions::from_mode(0o700)).unwrap();
    let id_out = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops path-identity "$2""#,
            "_",
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(id_out.status.success(), "{}", text(&id_out));
    let stage_a_id = String::from_utf8(id_out.stdout).unwrap().trim().to_string();

    // Empty directory with matching inode but missing `.qeminga-tx-id` (indistinguishable
    // from an ext4 immediate inode reuse after removal): MUST return `ambiguous` (NEVER
    // `match` or `mismatch`) without stamping `.qeminga-tx-id`!
    std::fs::remove_file(stage_a.join(".qeminga-tx-id")).unwrap();
    let insp_empty = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops inspect-path-identity "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
            &stage_a_id,
        ])
        .output()
        .unwrap();
    assert!(
        insp_empty.status.success()
            && String::from_utf8_lossy(&insp_empty.stdout).trim() == "ambiguous"
            && !stage_a.join(".qeminga-tx-id").exists(),
        "inspect-path-identity must classify markerless empty dir (reused-inode ambiguity) as `ambiguous` without stamping it: {}",
        text(&insp_empty)
    );

    // Mount obscuring the stage directory (both mountpoint table entry and same-fs bind
    // mount differing only by kernel mnt_id, plus volume change): MUST exit non-zero
    // (indeterminate, NEVER `mismatch`) so rollback preserves the journal reference!
    let insp_mount_py = Command::new("python3")
        .args([
            "-IB",
            "-c",
            r##"
import io, os, sys
script_text = open(sys.argv[1], "r", encoding="utf-8").read()
fs_section = script_text.split("fs_ops() {\n", 1)[1].split("\nPY\n", 1)[0]
py_body = fs_section.split("<<'PY'\n", 1)[1].split("\nop = sys.argv[1]", 1)[0]
op_body = fs_section.split("\nop = sys.argv[1]", 1)[1]
target, expected_id = sys.argv[2], sys.argv[3]

def run_with_hook(hook):
    ns = {"__name__": "__main__"}
    buf, err = io.StringIO(), io.StringIO()
    old_argv, old_out, old_err = sys.argv[:], sys.stdout, sys.stderr
    try:
        exec(py_body, ns)
        hook(ns)
        sys.argv = ["fs_ops", "inspect-path-identity", target, expected_id]
        sys.stdout, sys.stderr = buf, err
        rc = 0
        try:
            exec("op = sys.argv[1]" + op_body, ns)
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
        except OSError as exc:
            rc = 1
            err.write(str(exc))
        return rc, buf.getvalue().strip(), err.getvalue().strip()
    finally:
        sys.argv, sys.stdout, sys.stderr = old_argv, old_out, old_err

# Case A: target appears in mountpoints (covering mount hides the real underlying stage).
def hook_mountpoint(ns):
    orig = ns["visible_mountpoints"]
    ns["visible_mountpoints"] = lambda entries: orig(entries) | {os.path.normpath(target)}

rc, out, err = run_with_hook(hook_mountpoint)
assert rc != 0 and out != "mismatch", f"mountpoint covering stage MUST be indeterminate (non-zero), got rc={rc} out={out!r} err={err!r}"

# Case B: same-filesystem bind mount (same st_dev, different mnt_id) with a DIFFERENT visible inode!
def hook_bind_mount(ns):
    orig_mnt = ns["fd_mnt_id"]
    calls = {"n": 0}
    def fake_mnt(fd):
        calls["n"] += 1
        base = orig_mnt(fd)
        return base if calls["n"] == 1 else base + 777
    ns["fd_mnt_id"] = fake_mnt

rc, out, err = run_with_hook(hook_bind_mount)
assert rc != 0 and out != "mismatch", f"bind-mounted stage (mnt_id diff) MUST be indeterminate (non-zero), got rc={rc} out={out!r} err={err!r}"

# Case C: backing volume differs on target descriptor.
def hook_vol_diff(ns):
    orig_vol = ns["volume_id_of_fd"]
    def fake_vol(fd, path, entries):
        if os.path.normpath(path) == os.path.normpath(target):
            return "fsid:deadbeef"
        return orig_vol(fd, path, entries)
    ns["volume_id_of_fd"] = fake_vol

rc, out, err = run_with_hook(hook_vol_diff)
assert rc != 0 and out != "mismatch", f"volume-obscured stage MUST be indeterminate (non-zero), got rc={rc} out={out!r} err={err!r}"
"##,
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
            &stage_a_id,
        ])
        .output()
        .unwrap();
    assert!(
        insp_mount_py.status.success(),
        "inspect-path-identity mount/volume obscuration checks failed:\n{}",
        text(&insp_mount_py)
    );

    // Unreadable matching-inode dir (EACCES) MUST fail closed (non-zero, not mismatch/absent).
    std::fs::set_permissions(&stage_a, std::fs::Permissions::from_mode(0o000)).unwrap();
    let insp_eacces = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops inspect-path-identity "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
            &stage_a_id,
        ])
        .output()
        .unwrap();
    std::fs::set_permissions(&stage_a, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        !insp_eacces.status.success(),
        "inspect-path-identity must exit non-zero on EACCES (indeterminate read error): {}",
        text(&insp_eacces)
    );

    // Replace with forged directory (guaranteed different inode by keeping the original
    // inode allocated via rename, so ext4 cannot immediately reuse the freed inode):
    // MUST return `mismatch` without stamping `.qeminga-tx-id`!
    let saved_orig = inspect_parent.join("saved-orig-inode");
    std::fs::rename(&stage_a, &saved_orig).unwrap();
    std::fs::create_dir(&stage_a).unwrap();
    std::fs::set_permissions(&stage_a, std::fs::Permissions::from_mode(0o700)).unwrap();
    let insp_forged = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops inspect-path-identity "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
            &stage_a_id,
        ])
        .output()
        .unwrap();
    assert!(
        insp_forged.status.success()
            && String::from_utf8_lossy(&insp_forged.stdout).trim() == "mismatch"
            && !stage_a.join(".qeminga-tx-id").exists(),
        "inspect-path-identity must classify forged dir as `mismatch` without creating .qeminga-tx-id: {}",
        text(&insp_forged)
    );
    std::fs::remove_dir(&stage_a).unwrap();

    // Non-empty directory with the original inode but missing `.qeminga-tx-id`:
    // parent, volume, and inode still match the recorded stage, so missing marker
    // leaves ownership uncertain -> MUST return `ambiguous` (NEVER `mismatch` or
    // `match`) without stamping `.qeminga-tx-id`!
    std::fs::rename(&saved_orig, &stage_a).unwrap();
    std::fs::write(stage_a.join("unexpected-entry"), b"data\n").unwrap();
    let insp_nonempty_unmarked = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops inspect-path-identity "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
            &stage_a_id,
        ])
        .output()
        .unwrap();
    assert!(
        insp_nonempty_unmarked.status.success()
            && String::from_utf8_lossy(&insp_nonempty_unmarked.stdout).trim() == "ambiguous"
            && !stage_a.join(".qeminga-tx-id").exists(),
        "inspect-path-identity must classify non-empty markerless same-inode dir as `ambiguous` without stamping: {}",
        text(&insp_nonempty_unmarked)
    );
    // Same inode affirmatively stamped with a DIFFERENT valid transaction marker
    // is a confirmed replacement by another transaction -> MUST return `mismatch`.
    let other_tx = "00000000000000000000000000000000";
    let different_tx = if stage_a_id.contains(other_tx) {
        "11111111111111111111111111111111"
    } else {
        other_tx
    };
    let other_marker = stage_a.join(".qeminga-tx-id");
    std::fs::write(&other_marker, format!("{different_tx}\n")).unwrap();
    std::fs::set_permissions(&other_marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    let insp_other_tx = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops inspect-path-identity "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
            &stage_a_id,
        ])
        .output()
        .unwrap();
    assert!(
        insp_other_tx.status.success()
            && String::from_utf8_lossy(&insp_other_tx.stdout).trim() == "mismatch",
        "inspect-path-identity must classify directory stamped by a different transaction as `mismatch`: {}",
        text(&insp_other_tx)
    );
    std::fs::remove_dir_all(&stage_a).unwrap();
    let insp_absent = Command::new("bash")
        .args([
            "-c",
            r#"source "$1"; fs_ops inspect-path-identity "$2" "$3""#,
            "_",
            script().to_str().unwrap(),
            stage_a.to_str().unwrap(),
            &stage_a_id,
        ])
        .output()
        .unwrap();
    assert!(
        insp_absent.status.success()
            && String::from_utf8_lossy(&insp_absent.stdout).trim() == "absent",
        "inspect-path-identity must classify missing path as `absent`: {}",
        text(&insp_absent)
    );

    // Part 2 & 3: End-to-end rollback where restore succeeds, backup is pruned, and:
    //   - Case A (`chmod 0500` on stage): stage matches but cannot be removed -> `UPDATE_PHASE=restored`
    //     retains stage fields, and retry `update` MUST read the restored journal cleanly, prune the
    //     stage, install v2, and restart the service (`active`).
    //   - Case B (`chmod 0000` on stage): inspect fails with EACCES (indeterminate) -> rollback MUST
    //     NOT write `RECORD_STATE=installed`, keeping `UPDATE_PHASE=restored` + stage fields until
    //     recovery (`update`) reclaims the stage and restarts the service!
    install_standard_mock_bin(&bin);
    let v1_src = dir.path().join("v1-src");
    let v2_src = dir.path().join("v2-src");
    for d in [
        v1_src.join("bin"),
        v1_src.join("externals"),
        v2_src.join("bin"),
        v2_src.join("externals"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    let cfg_sh = runner_registration_config_script("restored-stage-box");
    let (v1_tb, v1_sha) =
        build_versioned_runner_pkg(dir.path(), &v1_src, "v1", "v1.tar.gz", &cfg_sh);
    let (v2_tb, v2_sha) =
        build_versioned_runner_pkg(dir.path(), &v2_src, "v2", "v2.tar.gz", &cfg_sh);

    let state_file = dir.path().join("svc.state");
    let sc_count = dir.path().join("is_active.count");
    let inst_parent = dir.path().join("install-parent");
    std::fs::create_dir_all(&inst_parent).unwrap();
    std::fs::write(&state_file, "inactive\n").unwrap();

    write_exec(
        &bin.join("systemctl"),
        r#"#!/bin/sh
case "$1" in
    show)
        for a in "$@"; do
            if [ "$a" = "--value" ]; then echo "not-found"; exit 0; fi
        done
        echo "LoadState=loaded"
        echo "FragmentPath=${FAKE_EXPECTED_FRAG:?}"
        exit 0
        ;;
    is-active)
        if [ -n "${FAKE_ARM_STAGE_MODE:-}" ] && [ -n "${FAKE_SC_COUNT:-}" ]; then
            c="$(cat "${FAKE_SC_COUNT}" 2>/dev/null || echo 0)"
            c=$((c + 1))
            echo "$c" > "${FAKE_SC_COUNT}"
            if [ "$c" -eq "${FAKE_ARM_ON_CALL:-3}" ]; then
                for p in "${FAKE_INST_PARENT:?}"/.qeminga-extract.*; do
                    [ -d "$p" ] && chmod "${FAKE_ARM_STAGE_MODE}" "$p" || true
                done
            fi
        fi
        st="$(cat "${FAKE_STATE_FILE:?}" 2>/dev/null || echo inactive)"
        case "$st" in
            active) echo active; exit 0 ;;
            inactive) echo inactive; exit 3 ;;
            *) exit 1 ;;
        esac
        ;;
    stop)
        echo "inactive" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    start)
        echo "active" > "${FAKE_STATE_FILE:?}"
        exit 0
        ;;
    *) exit 0 ;;
esac
"#,
    );

    let user_flag = dir.path().join("user_gecos");
    let cg_ctrls = dir.path().join("cgroup.controllers");
    std::fs::write(&cg_ctrls, "cpu memory pids\n").unwrap();
    let reg_file = dir.path().join("reg-in");
    std::fs::write(&reg_file, "FAKE_REG\n").unwrap();
    std::fs::set_permissions(&reg_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let inst = inst_parent.join("opt-runner");
    let state = dir.path().join("state");
    let hooks = dir.path().join("hooks");
    let cfg = dir.path().join("cfg");
    let rec_path = cfg.join("install.env");
    let unit_dir = units.to_str().unwrap();
    let unit_file = units.join("qeminga-restored-stage-box.service");

    let inst_out = run_setup_env(
        &[
            "install",
            "--repo",
            REPO_URL,
            "--name",
            "restored-stage-box",
            "--service",
            "qeminga-restored-stage-box",
            "--install-dir",
            inst.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--hook-dir",
            hooks.to_str().unwrap(),
            "--config-dir",
            cfg.to_str().unwrap(),
            "--token-file",
            reg_file.to_str().unwrap(),
            "--runner-sha256",
            &v1_sha,
            "--skip-packages",
            "--no-start",
        ],
        &[
            ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
            ("FAKE_GOOD_TARBALL", v1_tb.to_str().unwrap()),
            ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
            ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_CGROUP_CONTROLLERS", cg_ctrls.to_str().unwrap()),
            ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
            ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
            ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(inst_out.status.success(), "{}", text(&inst_out));

    for (case_label, stage_mode) in [
        ("matching-unremovable-0500", "0500"),
        ("indeterminate-0000", "0000"),
    ] {
        std::fs::write(&state_file, "active\n").unwrap();
        let _ = std::fs::remove_file(&sc_count);
        let upd_fail = run_setup_env(
            &[
                "update",
                "--config-dir",
                cfg.to_str().unwrap(),
                "--runner-sha256",
                &v2_sha,
            ],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
                ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
                ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
                ("FAKE_SC_COUNT", sc_count.to_str().unwrap()),
                ("FAKE_ARM_ON_CALL", "3"),
                ("FAKE_ARM_STAGE_MODE", stage_mode),
                ("FAKE_INST_PARENT", inst_parent.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ],
            Some(&bin),
        );
        // Restore 0700 so we can inspect and run retry cleanly.
        for entry in std::fs::read_dir(&inst_parent).unwrap().flatten() {
            let p = entry.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(".qeminga-extract."))
            {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
            }
        }
        assert!(
            !upd_fail.status.success(),
            "{case_label}: {}",
            text(&upd_fail)
        );

        let rec_after = std::fs::read_to_string(&rec_path).unwrap();
        let stage_dir_val = rec_after
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_STAGE_DIR="))
            .unwrap_or("");
        let stage_id_val = rec_after
            .lines()
            .find_map(|l| l.strip_prefix("UPDATE_STAGE_ID="))
            .unwrap_or("");
        assert!(
            rec_after.contains("RECORD_STATE=updating\n")
                && rec_after.contains("UPDATE_PHASE=restored\n")
                && rec_after.contains("UPDATE_WAS_ACTIVE=1\n")
                && !stage_dir_val.is_empty()
                && !stage_id_val.is_empty()
                && std::path::Path::new(stage_dir_val).is_dir(),
            "{case_label}: rollback after successful restore with unpruned stage MUST save readable UPDATE_PHASE=restored retaining stage fields (never installed):\n{rec_after}"
        );

        let retry_ok = run_setup_env(
            &[
                "update",
                "--config-dir",
                cfg.to_str().unwrap(),
                "--runner-sha256",
                &v2_sha,
            ],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
                ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
                ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ],
            Some(&bin),
        );
        assert!(
            retry_ok.status.success(),
            "{case_label}: retry update MUST read restored journal with stage fields and recover cleanly:\n{}",
            text(&retry_ok)
        );
        assert!(
            !std::path::Path::new(stage_dir_val).exists(),
            "{case_label}: retry must reclaim retained stage {stage_dir_val}"
        );
        assert_eq!(
            std::fs::read_to_string(&state_file).unwrap().trim(),
            "active",
            "{case_label}: retry must honor preserved UPDATE_WAS_ACTIVE=1 and restart service"
        );
    }

    // Part 4: Rollback caller with ambiguous markerless same-inode directories (both empty
    //   reused-inode case and non-empty stage that lost its `.qeminga-tx-id` marker while
    //   files remain on disk): `_rollback_runner_package_tx` MUST neither remove the
    //   directory via `safe-rmtree-id` nor clear `UPDATE_STAGE_DIR` / mark `installed`!
    for (amb_label, with_file) in [("empty", false), ("nonempty", true)] {
        let amb_stage = inst_parent.join(format!(".qeminga-extract.ambig-{amb_label}"));
        let amb_backup = inst_parent.join(format!(".qeminga-update-backup.ambig-{amb_label}"));
        std::fs::create_dir(&amb_stage).unwrap();
        std::fs::create_dir(&amb_backup).unwrap();
        std::fs::set_permissions(&amb_stage, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&amb_backup, std::fs::Permissions::from_mode(0o700)).unwrap();
        if with_file {
            std::fs::write(
                amb_stage.join("stage-payload.txt"),
                b"original-stage-data\n",
            )
            .unwrap();
        }
        let amb_sid = String::from_utf8(
            Command::new("bash")
                .args([
                    "-c",
                    r#"source "$1"; fs_ops path-identity "$2""#,
                    "_",
                    script().to_str().unwrap(),
                    amb_stage.to_str().unwrap(),
                ])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let amb_bid = String::from_utf8(
            Command::new("bash")
                .args([
                    "-c",
                    r#"source "$1"; fs_ops path-identity "$2""#,
                    "_",
                    script().to_str().unwrap(),
                    amb_backup.to_str().unwrap(),
                ])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        // Remove `.qeminga-tx-id` while keeping the original directory inode (empty or with files).
        std::fs::remove_file(amb_stage.join(".qeminga-tx-id")).unwrap();
        std::fs::write(&state_file, "inactive\n").unwrap();
        let rb_amb = Command::new("bash")
            .args([
                "-c",
                r#"
set -euo pipefail
source "$1"
OPT_CONFIG_DIR="$2"
OPT_INSTALL_DIR="$3"
OPT_SERVICE="qeminga-restored-stage-box"
read_install_record "$OPT_CONFIG_DIR/install.env"
_rollback_runner_package_tx \
    "$OPT_CONFIG_DIR/install.env" \
    "$REC_VOL_INSTALL_DIR" \
    "$4" "$5" "" "1" "" "" "" "" "" \
    "$6" "$7"
"#,
                "_",
                script().to_str().unwrap(),
                cfg.to_str().unwrap(),
                inst.to_str().unwrap(),
                amb_backup.to_str().unwrap(),
                &amb_bid,
                amb_stage.to_str().unwrap(),
                &amb_sid,
            ])
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("FAKE_STATE_FILE", &state_file)
            .env("FAKE_EXPECTED_FRAG", &unit_file)
            .env("QEMINGA_RUNTIME_ROOT", &rt_root)
            .env("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir)
            .env("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir)
            .output()
            .unwrap();
        assert!(rb_amb.status.success(), "{amb_label}: {}", text(&rb_amb));
        let rec_amb = std::fs::read_to_string(&rec_path).unwrap();
        assert!(
            amb_stage.is_dir()
                && !amb_stage.join(".qeminga-tx-id").exists()
                && rec_amb.contains("RECORD_STATE=updating\n")
                && rec_amb.contains("UPDATE_PHASE=restored\n")
                && rec_amb.contains(&format!("UPDATE_STAGE_DIR={}\n", amb_stage.display()))
                && rec_amb.contains(&format!("UPDATE_STAGE_ID={amb_sid}\n"))
                && rec_amb.contains("UPDATE_WAS_ACTIVE=1\n"),
            "{amb_label}: rollback MUST leave ambiguous markerless dir untouched and retain UPDATE_STAGE_DIR/ID in restored journal:\n{rec_amb}"
        );
        if with_file {
            assert_eq!(
                std::fs::read_to_string(amb_stage.join("stage-payload.txt")).unwrap(),
                "original-stage-data\n",
                "{amb_label}: rollback MUST preserve original files inside markerless stage directory"
            );
        }

        // Second invocation (`update` AND `uninstall`) consuming the exact restored journal
        // written by the first rollback MUST ALSO fail closed without removing `amb_stage`
        // (even when empty!) and MUST keep the restored journal entry intact.
        for second_cmd in ["update", "uninstall"] {
            let args: Vec<&str> = if second_cmd == "update" {
                vec![
                    "update",
                    "--config-dir",
                    cfg.to_str().unwrap(),
                    "--runner-sha256",
                    &v2_sha,
                ]
            } else {
                vec!["uninstall", "--config-dir", cfg.to_str().unwrap()]
            };
            let second_out = run_setup_env(
                &args,
                &[
                    ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                    ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
                    ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
                    ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
                    ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                    ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                    ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
                ],
                Some(&bin),
            );
            assert!(
                !second_out.status.success(),
                "{amb_label}/{second_cmd}: subsequent {second_cmd} MUST refuse to prune markerless ambiguous stage:\n{}",
                text(&second_out)
            );
            let rec_second = std::fs::read_to_string(&rec_path).unwrap();
            assert!(
                amb_stage.is_dir()
                    && !amb_stage.join(".qeminga-tx-id").exists()
                    && inst.is_dir()
                    && rec_second.contains("RECORD_STATE=updating\n")
                    && rec_second.contains("UPDATE_PHASE=restored\n")
                    && rec_second.contains(&format!("UPDATE_STAGE_DIR={}\n", amb_stage.display()))
                    && rec_second.contains(&format!("UPDATE_STAGE_ID={amb_sid}\n"))
                    && rec_second.contains("UPDATE_WAS_ACTIVE=1\n"),
                "{amb_label}/{second_cmd}: subsequent {second_cmd} MUST preserve ambiguous stage dir and restored journal:\n{rec_second}"
            );
            if with_file {
                assert_eq!(
                    std::fs::read_to_string(amb_stage.join("stage-payload.txt")).unwrap(),
                    "original-stage-data\n",
                    "{amb_label}/{second_cmd}: subsequent {second_cmd} MUST preserve files inside markerless stage dir"
                );
            }
        }

        // Once the operator inspects and removes `amb_stage`, retrying `update` MUST
        // recover cleanly, return to `RECORD_STATE=installed`, and restart the service.
        std::fs::remove_dir_all(&amb_stage).unwrap();
        let after_manual_rm = run_setup_env(
            &[
                "update",
                "--config-dir",
                cfg.to_str().unwrap(),
                "--runner-sha256",
                &v2_sha,
            ],
            &[
                ("FAKE_USER_FLAG", user_flag.to_str().unwrap()),
                ("FAKE_GOOD_TARBALL", v2_tb.to_str().unwrap()),
                ("FAKE_STATE_FILE", state_file.to_str().unwrap()),
                ("FAKE_EXPECTED_FRAG", unit_file.to_str().unwrap()),
                ("QEMINGA_RUNTIME_ROOT", rt_root.to_str().unwrap()),
                ("QEMINGA_SYSTEMD_UNIT_DIR", unit_dir),
                ("QEMINGA_SYSTEMD_UNIT_DIRS", unit_dir),
            ],
            Some(&bin),
        );
        assert!(
            after_manual_rm.status.success(),
            "{amb_label}: update after operator removed ambiguous stage MUST succeed:\n{}",
            text(&after_manual_rm)
        );
        let rec_done = std::fs::read_to_string(&rec_path).unwrap();
        assert!(
            rec_done.contains("RECORD_STATE=installed\n")
                && !rec_done.contains("UPDATE_STAGE_DIR="),
            "{amb_label}: record must return to installed after manual removal and retry:\n{rec_done}"
        );
        assert_eq!(
            std::fs::read_to_string(&state_file).unwrap().trim(),
            "active",
            "{amb_label}: retry after manual removal must honor UPDATE_WAS_ACTIVE=1"
        );
    }
}
