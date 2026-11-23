//! The libvirt + QEMU KVM smoke lanes (#53, AC16):
//!
//! - `.github/workflows/libvirt-kvm-hosted.yml`: builds the production release
//!   candidate on GitHub-hosted `ubuntu-24.04` (`x86_64`), enables `/dev/kvm`
//!   for the unprivileged `runner` user via the `99-kvm4all.rules` udev
//!   workaround (`OPTIONS+="static_node=kvm"`), and exercises the candidate
//!   under real libvirt + KVM (`qemu:///session`, no `sudo` during the run) on
//!   `push` (`main`), `pull_request`, and `workflow_dispatch`.
//! - `.github/workflows/libvirt-kvm.yml` + `libvirt-kvm-lane.yml`:
//!   `workflow_dispatch`-only lane that builds on GitHub-hosted runners and
//!   exercises the exact candidate on self-hosted `x86_64` and `aarch64` KVM
//!   runners without root, `sudo`, or a Rust toolchain.
//!
//! Mirrors `tests/libvirt_tcg_smoke.rs` for the KVM lanes: candidate manifest
//! and fail-closed verification, image-pin parity with the TCG script, KVM
//! domain XML (`type='kvm'`, `host-passthrough`, aarch64 UEFI + `gic host`,
//! unprivileged `user` networking under `qemu:///session`), URI validation,
//! missing/non-char `/dev/kvm` fail-closed preflight, stale-domain and cleanup
//! namespace guards, the `libvirt-kvm-smoke-v1` result contract (refusing TCG
//! as a pass), and workflow security/shape invariants for both the self-hosted
//! and GitHub-hosted workflows.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    root().join("scripts/ci/libvirt-kvm-smoke.sh")
}

fn tcg_script() -> PathBuf {
    root().join("scripts/ci/libvirt-tcg-smoke.sh")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn lane(args: &[&str]) -> Output {
    lane_env(args, &[], None)
}

fn lane_env(args: &[&str], env: &[(&str, &str)], bin: Option<&Path>) -> Output {
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

fn require_jq() {
    let found = Command::new("jq")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        found,
        "jq is required by scripts/ci/libvirt-kvm-smoke.sh and these tests"
    );
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn sha256_hex(path: &Path) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn common_script() -> PathBuf {
    root().join("scripts/ci/libvirt-smoke-common.sh")
}

// ---- candidate manifest & shared image-pin helper -------------------------

#[test]
fn kvm_and_tcg_scripts_share_common_candidate_and_image_helper() {
    let common = std::fs::read_to_string(common_script())
        .unwrap_or_else(|e| panic!("missing scripts/ci/libvirt-smoke-common.sh: {e}"));
    let kvm = std::fs::read_to_string(script()).unwrap();
    let tcg = std::fs::read_to_string(tcg_script()).unwrap();

    // Shared pins and candidate/image-fetch logic live in one file.
    for required in [
        "SOURCE_REPOSITORY=\"vicaya/qeminga\"",
        "BUILD_COMMAND=\"cargo build --release --locked --features seccomp\"",
        "PACKAGING_FILES=\"",
        "IMAGE_RELEASE=\"",
        "IMAGE_SHA256_x86_64=\"",
        "IMAGE_SHA256_aarch64=\"",
        "cmd_manifest()",
        "cmd_verify_candidate()",
        "cmd_image_key()",
        "cmd_fetch_image()",
    ] {
        assert!(
            common.contains(required),
            "common helper must define {required:?}"
        );
    }

    for (label, body) in [("kvm", &kvm), ("tcg", &tcg)] {
        assert!(
            body.contains("source \"$HERE/libvirt-smoke-common.sh\""),
            "{label} script must source libvirt-smoke-common.sh"
        );
        for duplicated in [
            "IMAGE_RELEASE=\"",
            "IMAGE_SHA256_x86_64=\"",
            "IMAGE_SHA256_aarch64=\"",
            "PACKAGING_FILES=\"",
            "BUILD_COMMAND=\"",
            "cmd_manifest()",
            "cmd_verify_candidate()",
            "cmd_fetch_image()",
        ] {
            assert!(
                !body.contains(duplicated),
                "{label} script must not duplicate {duplicated:?} (keep in libvirt-smoke-common.sh)"
            );
        }
    }
}

#[test]
fn kvm_manifest_and_candidate_verification_fail_closed() {
    require_jq();
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("qeminga-bin");
    std::fs::write(&binary, b"fake release binary\n").unwrap();
    let out = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        out.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--arch",
        "aarch64",
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "99",
        "--run-attempt",
        "1",
        "--runner",
        "ubuntu-24.04-arm",
    ]);
    assert!(m.status.success(), "{}", text(&m));

    let verified = lane(&["verify-candidate", out.to_str().unwrap(), "aarch64", SHA]);
    assert!(verified.status.success(), "{}", text(&verified));
    assert_eq!(
        String::from_utf8_lossy(&verified.stdout).trim(),
        sha256_hex(&out.join("qeminga"))
    );

    // Wrong arch, wrong SHA, and tampered binary fail closed.
    assert!(
        !lane(&["verify-candidate", out.to_str().unwrap(), "x86_64", SHA])
            .status
            .success()
    );
    assert!(
        !lane(&[
            "verify-candidate",
            out.to_str().unwrap(),
            "aarch64",
            &SHA.replace('0', "f")
        ])
        .status
        .success()
    );
    std::fs::write(out.join("qeminga"), b"tampered").unwrap();
    assert!(
        !lane(&["verify-candidate", out.to_str().unwrap(), "aarch64", SHA])
            .status
            .success()
    );
}

// ---- KVM domain XML -------------------------------------------------------

fn domain_xml(arch: &str, env: &[(&str, &str)]) -> Output {
    lane_env(
        &[
            "domain-xml",
            "--arch",
            arch,
            "--name",
            "qeminga-e2e-42-1-x",
            "--dir",
            "/var/lib/qeminga-runner/images/qeminga-e2e-42-1-x",
        ],
        env,
        None,
    )
}

#[test]
fn kvm_domain_xml_uses_kvm_and_host_passthrough_on_both_architectures() {
    for (arch, machine) in [("x86_64", "q35"), ("aarch64", "virt")] {
        let out = domain_xml(arch, &[]);
        assert!(out.status.success(), "{arch}: {}", text(&out));
        let xml = String::from_utf8(out.stdout).unwrap();
        assert!(xml.contains("<domain type='kvm'>"), "{arch}: {xml}");
        assert!(!xml.contains("<domain type='qemu'>"), "{arch}: {xml}");
        assert!(
            xml.contains(&format!(
                "<type arch='{arch}' machine='{machine}'>hvm</type>"
            )),
            "{arch}: {xml}"
        );
        assert!(
            xml.contains("<cpu mode='host-passthrough' check='none'/>"),
            "{arch}: {xml}"
        );
        assert!(
            xml.contains("<target type='virtio' name='org.qemu.guest_agent.0'/>"),
            "{arch}: {xml}"
        );
        // Unprivileged qemu:///session default uses user-mode networking, not a root bridge.
        assert!(xml.contains("<interface type='user'>"), "{arch}: {xml}");
        assert!(!xml.contains("source network='default'"), "{arch}: {xml}");
        assert!(xml.contains("<rom enabled='no'/>"), "{arch}: {xml}");

        if arch == "x86_64" {
            assert!(xml.contains("<apic/>"), "{arch}: {xml}");
        } else {
            assert!(
                xml.contains("<gic version='host'/>"),
                "aarch64 KVM must match host GIC version: {xml}"
            );
            assert!(
                xml.contains("<loader readonly='yes' type='pflash'>"),
                "aarch64 KVM boots UEFI: {xml}"
            );
            assert!(xml.contains("<nvram template='"), "{xml}");
        }
    }

    // qemu:///system mode uses the default libvirt network bridge.
    let sys = domain_xml("x86_64", &[("QEMINGA_E2E_CONNECT", "qemu:///system")]);
    assert!(sys.status.success(), "{}", text(&sys));
    let xml = String::from_utf8(sys.stdout).unwrap();
    assert!(xml.contains("<interface type='network'>"), "{xml}");
    assert!(xml.contains("<source network='default'/>"), "{xml}");
}

#[test]
fn refuses_unknown_libvirt_connect_uris_and_missing_expect_sha256() {
    for bad_uri in [
        "qemu+ssh://root@evil.example/system",
        "qemu+tcp://127.0.0.1/system",
        "lxc:///",
        "qemu:///session;id",
    ] {
        let out = domain_xml("x86_64", &[("QEMINGA_E2E_CONNECT", bad_uri)]);
        assert!(!out.status.success(), "{bad_uri}: {}", text(&out));
    }

    // Missing or malformed --expect-sha256 is refused before preflight.
    for expect in [None, Some(""), Some("not-a-digest")] {
        let mut args = vec![
            "run",
            "--arch",
            "aarch64",
            "--candidate",
            "/nonexistent/candidate",
            "--source-sha",
            SHA,
            "--run-id",
            "42",
            "--run-attempt",
            "1",
            "--out",
            "/nonexistent/out",
        ];
        if let Some(e) = expect {
            args.extend(["--expect-sha256", e]);
        }
        let out = lane(&args);
        assert!(!out.status.success(), "{expect:?}: {}", text(&out));
        assert!(text(&out).contains("--expect-sha256"), "{}", text(&out));
        assert!(!text(&out).contains("preflight"), "{}", text(&out));
    }
}

// ---- stale domains & conservative cleanup ---------------------------------

const FAKE_VIRSH: &str = r#"#!/bin/sh
echo "$*" >> "${FAKE_LOG:?}"
case "$1" in --connect=*) shift ;; esac
case "$1" in
    list)
        [ "${FAKE_LIST_FAILS:-0}" = 1 ] && { echo "error: failed to connect" >&2; exit 1; }
        printf '%s\n' ${FAKE_LIST:-} ""; exit 0 ;;
    domstate)
        [ "${FAKE_STATE_FAILS:-0}" = 1 ] && { echo "error: internal error" >&2; exit 1; }
        if [ -n "${FAKE_LIST:-}" ]; then echo "${FAKE_DOMSTATE:-running}"; exit 0; fi
        echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#;

#[test]
fn stale_check_and_cleanup_protect_unrelated_domains_and_unknown_state() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    write_exec(&bin.join("virsh"), FAKE_VIRSH);
    let log = dir.path().join("virsh.log");
    let images = dir.path().join("images");
    let mine = images.join("qeminga-e2e-42-1-aarch64");
    let other = images.join("qeminga-e2e-43-1-aarch64");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(mine.join("root.qcow2"), b"x").unwrap();
    std::fs::write(other.join("root.qcow2"), b"y").unwrap();

    // Clean stale-check uses qemu:///session by default.
    let clean = lane_env(
        &["stale-check"],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("FAKE_LIST", "other-vm"),
        ],
        Some(&bin),
    );
    assert!(clean.status.success(), "{}", text(&clean));
    assert!(
        std::fs::read_to_string(&log)
            .unwrap()
            .contains("--connect=qemu:///session")
    );

    // Stale qeminga domain stops the lane.
    let stale = lane_env(
        &["stale-check"],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("FAKE_LIST", "qeminga-e2e-42-1-aarch64"),
        ],
        Some(&bin),
    );
    assert!(!stale.status.success());

    // Unknown libvirt state keeps the disks.
    let unknown = lane_env(
        &[
            "cleanup",
            "--arch",
            "aarch64",
            "--run-id",
            "42",
            "--run-attempt",
            "1",
        ],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
            ("FAKE_LIST", "qeminga-e2e-42-1-aarch64"),
            ("FAKE_STATE_FAILS", "1"),
        ],
        Some(&bin),
    );
    assert!(!unknown.status.success());
    assert!(mine.join("root.qcow2").exists());

    // Absent domain removes only the current run's directory.
    let done = lane_env(
        &[
            "cleanup",
            "--arch",
            "aarch64",
            "--run-id",
            "42",
            "--run-attempt",
            "1",
        ],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(done.status.success(), "{}", text(&done));
    assert!(!mine.exists());
    assert!(other.join("root.qcow2").exists());
}

// ---- result contract ------------------------------------------------------

const MANDATORY: [&str; 4] = [
    "production_install",
    "accelerator_kvm",
    "libvirt_interop",
    "agent_shutdown",
];

fn result(tests: &[(&str, &str)], accelerator: &str) -> (bool, serde_json::Value) {
    require_jq();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("tests")).unwrap();
    for (name, status) in tests {
        std::fs::write(dir.path().join("tests").join(name), status).unwrap();
    }
    let output = lane(&[
        "result",
        "--out",
        dir.path().to_str().unwrap(),
        "--arch",
        "aarch64",
        "--source-sha",
        SHA,
        "--binary-sha256",
        &"a".repeat(64),
        "--accelerator",
        accelerator,
    ]);
    let json = serde_json::from_slice(&std::fs::read(dir.path().join("result.json")).unwrap())
        .unwrap_or_else(|e| panic!("{e}: {}", text(&output)));
    (output.status.success(), json)
}

#[test]
fn passing_result_requires_kvm_accelerator_and_all_mandatory_tests() {
    let all: Vec<(&str, &str)> = MANDATORY.iter().map(|t| (*t, "pass")).collect();
    let (ok, json) = result(&all, "kvm");
    assert!(ok);
    assert_eq!(json["schema"], 1);
    assert_eq!(json["suite"], "libvirt-kvm-smoke-v1");
    assert_eq!(json["virtualization"]["hypervisor"], "qemu");
    assert_eq!(json["virtualization"]["accelerator"], "kvm");
    assert_eq!(json["virtualization"]["machine"], "virt");
    assert_eq!(json["result"], "pass");
    for t in MANDATORY {
        assert_eq!(json["tests"][t], "pass", "{t}");
    }

    // A TCG fallback must NEVER pass the KVM lane.
    let (ok, json) = result(&all, "tcg");
    assert!(!ok);
    assert_eq!(json["result"], "fail");

    // Any missing or failed mandatory test fails closed.
    for skip in MANDATORY {
        let partial: Vec<(&str, &str)> = MANDATORY
            .iter()
            .filter(|t| **t != skip)
            .map(|t| (*t, "pass"))
            .collect();
        let (ok, json) = result(&partial, "kvm");
        assert!(!ok, "{skip} missing");
        assert_eq!(json["tests"][skip], "not_run");
        assert_eq!(json["result"], "fail");
    }
}

// ---- workflow security & shape --------------------------------------------

fn caller() -> String {
    std::fs::read_to_string(root().join(".github/workflows/libvirt-kvm.yml")).unwrap()
}

fn lane_workflow() -> String {
    std::fs::read_to_string(root().join(".github/workflows/libvirt-kvm-lane.yml")).unwrap()
}

fn job<'a>(text: &'a str, name: &str) -> &'a str {
    let key = format!("\n  {name}:\n");
    let start = text.find(&key).unwrap_or_else(|| panic!("no job {name}")) + 1;
    let rest = &text[start + key.len() - 1..];
    let end = rest
        .match_indices('\n')
        .map(|(i, _)| i + 1)
        .find(|&i| {
            let line = &rest[i..];
            line.starts_with("  ")
                && !line.starts_with("   ")
                && !line.trim_start().starts_with('#')
                && line
                    .lines()
                    .next()
                    .is_some_and(|l| l.trim_end().ends_with(':'))
        })
        .unwrap_or(rest.len());
    &text[start..start + key.len() - 1 + end]
}

#[test]
fn kvm_workflow_never_triggers_on_pull_requests_and_supports_both_arches() {
    let text = caller();
    // Self-hosted runners on a public repository must NEVER run on pull_request events.
    assert!(text.contains("workflow_dispatch:"), "{text}");
    for forbidden_trigger in ["pull_request:", "pull_request_target:", "issue_comment:"] {
        assert!(
            !text.contains(forbidden_trigger),
            "forbidden trigger {forbidden_trigger} in libvirt-kvm.yml"
        );
    }
    assert!(text.contains("permissions:\n  contents: read"), "{text}");
    // Never accept a user-controlled ref/SHA input in workflow_dispatch: checking out an
    // arbitrary SHA in the default branch context risks cache poisoning (CodeQL) and could
    // check out a commit outside the donor runner's ALLOWED_REFS allowlist.
    assert!(
        !text.contains("source_sha:"),
        "libvirt-kvm.yml must not accept a user-controlled source_sha input:\n{text}"
    );
    // Resolve one vetted vicaya/qeminga commit once (works both from a private controller
    // repository via qeminga-target.rev / vicaya/qeminga main and from vicaya/qeminga itself).
    let resolve = job(&text, "resolve");
    assert!(resolve.contains("target_rev:"), "{resolve}");
    assert!(resolve.contains("vicaya/qeminga"), "{resolve}");
    assert!(resolve.contains("qeminga-target.rev"), "{resolve}");
    assert!(resolve.contains("persist-credentials: false"), "{resolve}");

    let lane = lane_workflow();
    assert!(
        !lane.contains("source_sha:"),
        "libvirt-kvm-lane.yml must not accept a source_sha input:\n{lane}"
    );
    assert!(
        lane.contains("target_rev:"),
        "libvirt-kvm-lane.yml must accept the resolved target_rev:\n{lane}"
    );
    // Caller must NEVER control the hosted build runner or runner_arch labels.
    assert!(
        !lane.contains("build_runner:"),
        "libvirt-kvm-lane.yml must derive build runner from arch, never accept build_runner input:\n{lane}"
    );
    assert!(
        !lane.contains("runner_arch:"),
        "libvirt-kvm-lane.yml must derive runner_arch from arch, never accept runner_arch input:\n{lane}"
    );

    for arch in ["x86_64", "aarch64"] {
        let j = job(&text, arch);
        assert!(j.contains("needs: resolve"), "{arch}");
        assert!(
            j.contains("uses: ./.github/workflows/libvirt-kvm-lane.yml"),
            "{arch}"
        );
        assert!(j.contains(&format!("arch: {arch}\n")), "{arch}");
        assert!(
            j.contains("target_rev: ${{ needs.resolve.outputs.target_rev }}\n"),
            "{arch}"
        );
        assert!(
            !j.contains("build_runner:") && !j.contains("runner_arch:"),
            "{arch}: caller must not pass build_runner or runner_arch to reusable lane:\n{j}"
        );
    }
    assert!(
        !text.contains("strategy:") && !lane.contains("strategy:"),
        "no matrix couples x86_64 and aarch64"
    );
}

#[test]
fn kvm_lane_builds_on_hosted_runner_and_tests_unprivileged_on_self_hosted_kvm_runner() {
    let text = lane_workflow();
    assert!(text.contains("workflow_call:"));
    assert!(text.contains("permissions:\n  contents: read"));

    // Fixed hosted verify gate enforces caller workflow, event, ref, arch, and
    // commit reachability from vicaya/qeminga's protected main branch BEFORE
    // scheduling candidate or self-hosted kvm jobs.
    let verify = job(&text, "verify");
    assert!(
        verify.contains("runs-on: ubuntu-24.04\n"),
        "verify gate must run on fixed GitHub-hosted ubuntu-24.04:\n{verify}"
    );
    assert!(
        verify.contains("github.event_name == 'workflow_dispatch'"),
        "verify gate must restrict event to workflow_dispatch:\n{verify}"
    );
    assert!(
        verify.contains("github.ref == 'refs/heads/main'"),
        "verify gate must restrict ref to refs/heads/main:\n{verify}"
    );
    assert!(
        verify.contains(".github/workflows/libvirt-kvm.yml"),
        "verify gate must restrict caller workflow to libvirt-kvm.yml:\n{verify}"
    );
    assert!(
        verify.contains("merge-base --is-ancestor \"$TARGET_REV\" FETCH_HEAD"),
        "verify gate must prove target_rev is reachable from vicaya/qeminga main:\n{verify}"
    );
    assert!(
        verify.contains("https://github.com/vicaya/qeminga.git")
            && verify.contains("refs/heads/main"),
        "verify gate must check ancestry against vicaya/qeminga refs/heads/main:\n{verify}"
    );

    let build = job(&text, "candidate");
    assert!(build.contains("needs: verify"), "{build}");
    assert!(
        build.contains(
            "runs-on: ${{ inputs.arch == 'x86_64' && 'ubuntu-24.04' || 'ubuntu-24.04-arm' }}"
        ),
        "candidate must derive hosted build runner from a fixed architecture mapping:\n{build}"
    );
    assert!(
        build.contains("github.event_name == 'workflow_dispatch'")
            && build.contains("github.ref == 'refs/heads/main'"),
        "candidate must repeat caller/event/ref guard:\n{build}"
    );
    assert!(build.contains("repository: vicaya/qeminga"));
    assert!(build.contains("ref: ${{ needs.verify.outputs.target_rev }}"));
    assert!(build.contains("cargo build --release --locked --features seccomp\n"));
    assert!(build.contains("sha256: ${{ steps.digest.outputs.sha256 }}"));
    assert!(build.contains("persist-credentials: false"));
    assert!(
        build.contains(r#"test "$(git rev-parse HEAD)" = "$TARGET_REV""#),
        "candidate must verify checked-out commit equals target_rev:\n{build}"
    );
    assert!(
        build.contains(r#"--source-sha "$TARGET_REV""#),
        "candidate must stamp manifest with the vetted vicaya/qeminga TARGET_REV:\n{build}"
    );
    for forbidden in ["--all-features", "test-fakes", "seccomp-log"] {
        assert!(!build.contains(forbidden), "candidate: {forbidden}");
    }

    let kvm = job(&text, "kvm");
    assert!(kvm.contains("needs: [verify, candidate]"), "{kvm}");
    assert!(
        kvm.contains(
            r#"runs-on: [self-hosted, linux, "${{ inputs.arch == 'x86_64' && 'X64' || 'ARM64' }}", qeminga-kvm]"#
        ),
        "kvm must derive runner_arch from a fixed architecture mapping:\n{kvm}"
    );
    assert!(
        kvm.contains("github.event_name == 'workflow_dispatch'")
            && kvm.contains("github.ref == 'refs/heads/main'"),
        "kvm must repeat caller/event/ref guard:\n{kvm}"
    );
    assert!(kvm.contains("repository: vicaya/qeminga"));
    assert!(kvm.contains("ref: ${{ needs.verify.outputs.target_rev }}"));
    assert!(kvm.contains("cancel-in-progress: false"));
    assert!(kvm.contains("timeout-minutes:"));
    assert!(kvm.contains("persist-credentials: false"));
    assert!(kvm.contains(r#"test "$(uname -m)" = "$ARCH""#));
    assert!(kvm.contains(r#"EXPECTED_RUNNER_ARCH: ${{ needs.verify.outputs.expected_arch }}"#));
    assert!(kvm.contains(r#"test "$RUNNER_ARCH" = "$EXPECTED_RUNNER_ARCH""#));
    assert!(
        kvm.contains(r#"test "$(git rev-parse HEAD)" = "$TARGET_REV""#),
        "kvm job must verify checked-out commit equals target_rev:\n{kvm}"
    );
    assert!(
        kvm.contains(r#"--source-sha "$TARGET_REV""#),
        "kvm job must verify candidate against the vetted vicaya/qeminga TARGET_REV:\n{kvm}"
    );
    assert!(kvm.contains(r#"--expect-sha256 "${{ needs.candidate.outputs.sha256 }}""#));
    assert!(kvm.contains("libvirt-kvm-smoke.sh run"));
    assert!(kvm.contains("libvirt-kvm-smoke.sh cleanup"));
    assert!(!kvm.contains("continue-on-error"));

    // The self-hosted KVM runner must NEVER need sudo, apt-get, cargo, or rustup.
    for forbidden in ["sudo ", "apt-get", "cargo ", "rustup"] {
        assert!(
            !kvm.contains(forbidden),
            "self-hosted kvm job must not use {forbidden:?}:\n{kvm}"
        );
    }

    // Cleanup and artifact upload run even on failure.
    let cleanup_idx = kvm.find("libvirt-kvm-smoke.sh cleanup").unwrap();
    let cleanup_step = &kvm[kvm[..cleanup_idx].rfind("- name:").unwrap()..cleanup_idx];
    assert!(cleanup_step.contains("if: always()"), "{cleanup_step}");
    let upload_idx = kvm.find("actions/upload-artifact").unwrap();
    let upload_step = &kvm[kvm[..upload_idx].rfind("- name:").unwrap()..upload_idx];
    assert!(upload_step.contains("if: always()"), "{upload_step}");

    // Validate strict YAML syntax for all KVM workflow files when Ruby Psych is installed.
    let has_ruby = Command::new("ruby")
        .args(["-ryaml", "-e", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if has_ruby {
        for rel in [
            ".github/workflows/libvirt-kvm.yml",
            ".github/workflows/libvirt-kvm-lane.yml",
            ".github/workflows/libvirt-kvm-hosted.yml",
        ] {
            let path = root().join(rel);
            let out = Command::new("ruby")
                .args(["-ryaml", "-e", "YAML.load_file(ARGV[0])"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "invalid YAML in {rel}:\n{}",
                self::text(&out)
            );
        }
    }
}

fn hosted_workflow() -> String {
    let path = root().join(".github/workflows/libvirt-kvm-hosted.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn hosted_amd64_kvm_workflow_enables_dev_kvm_via_udev_and_runs_unprivileged_session_kvm() {
    let text = hosted_workflow();

    // Runs automatically on pushes to main, pull requests, and manual dispatch
    // because GitHub-hosted ubuntu-24.04 runners are ephemeral.
    assert!(text.contains("push:\n    branches: [main]"), "{text}");
    assert!(text.contains("pull_request:"), "{text}");
    assert!(text.contains("workflow_dispatch:"), "{text}");
    assert!(text.contains("permissions:\n  contents: read"), "{text}");
    assert!(
        text.contains("cancel-in-progress: ${{ github.event_name == 'pull_request' }}"),
        "{text}"
    );
    assert!(
        !text.contains("self-hosted"),
        "hosted workflow must never target self-hosted runners:\n{text}"
    );

    // Gated on docs-only change classification just like ci.yml and libvirt-tcg.yml.
    let changes = job(&text, "changes");
    assert!(changes.contains("runs-on: ubuntu-24.04\n"), "{changes}");
    assert!(changes.contains("persist-credentials: false"), "{changes}");
    assert!(changes.contains("scripts/ci/docs-only.sh"), "{changes}");

    // Candidate build job: native x86_64, production features only, digest anchored.
    let build = job(&text, "candidate");
    assert!(build.contains("needs: changes"), "{build}");
    assert!(
        build.contains("if: needs.changes.outputs.code == 'true'"),
        "{build}"
    );
    assert!(build.contains("runs-on: ubuntu-24.04\n"), "{build}");
    assert!(build.contains("timeout-minutes:"), "{build}");
    assert!(!build.contains("continue-on-error"), "{build}");
    assert!(build.contains("persist-credentials: false"), "{build}");
    assert!(
        build.contains(r#"test "$(uname -m)" = "x86_64""#),
        "{build}"
    );
    assert!(build.contains(r#"test "$RUNNER_ARCH" = "X64""#), "{build}");
    assert!(
        build.contains(r#"rustc -vV | grep -qx "host: x86_64-unknown-linux-gnu""#),
        "{build}"
    );
    assert!(build.contains("cargo build --release --locked --features seccomp\n"));
    assert!(build.contains("sha256: ${{ steps.digest.outputs.sha256 }}"));
    assert!(build.contains("sha256sum target/release/qeminga"));
    assert!(build.contains("scripts/ci/libvirt-kvm-smoke.sh manifest"));
    for forbidden in ["--all-features", "test-fakes", "seccomp-log"] {
        assert!(!build.contains(forbidden), "candidate: {forbidden}");
    }

    // Hosted KVM smoke job: native ubuntu-24.04, fail-fast udev workaround for /dev/kvm,
    // minimal session packages, unprivileged qemu:///session run, always() cleanup & upload.
    let smoke = job(&text, "smoke");
    assert!(smoke.contains("needs: candidate"), "{smoke}");
    assert!(smoke.contains("runs-on: ubuntu-24.04\n"), "{smoke}");
    assert!(smoke.contains("timeout-minutes:"), "{smoke}");
    assert!(!smoke.contains("continue-on-error"), "{smoke}");
    assert!(smoke.contains("persist-credentials: false"), "{smoke}");
    assert!(
        smoke.contains(r#"test "$(uname -m)" = "x86_64""#),
        "{smoke}"
    );
    assert!(smoke.contains(r#"test "$RUNNER_ARCH" = "X64""#), "{smoke}");
    assert!(
        smoke.contains("QEMINGA_E2E_CONNECT: qemu:///session"),
        "{smoke}"
    );
    for forbidden in ["cargo ", "rustup", "libvirt-daemon-system"] {
        assert!(
            !smoke.contains(forbidden),
            "hosted smoke job must not use {forbidden:?}:\n{smoke}"
        );
    }

    // The udev rule from GitHub's 2024-04-02 changelog / randax/talos-box#74 applies
    // MODE="0666" to the static /dev/kvm node; explicit mode checks before apt-get and
    // again inside libvirt-kvm-smoke.sh preflight detect any permissions regression.
    let udev_rule = r#"KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm""#;
    let udev_idx = smoke
        .find(udev_rule)
        .unwrap_or_else(|| panic!("missing 99-kvm4all.rules with static_node=kvm:\n{smoke}"));
    assert!(
        smoke.contains("/etc/udev/rules.d/99-kvm4all.rules"),
        "{smoke}"
    );
    assert!(smoke.contains("udevadm control --reload-rules"), "{smoke}");
    assert!(
        smoke.contains("udevadm trigger --name-match=kvm"),
        "{smoke}"
    );
    assert!(smoke.contains("udevadm settle"), "{smoke}");
    assert!(smoke.contains("test -c /dev/kvm"), "{smoke}");
    let rw_idx = smoke
        .find("test -r /dev/kvm && test -w /dev/kvm")
        .unwrap_or_else(|| panic!("missing fail-fast /dev/kvm rw check:\n{smoke}"));
    let apt_idx = smoke.find("apt-get install").unwrap();
    let run_idx = smoke.find("libvirt-kvm-smoke.sh run").unwrap();
    assert!(
        udev_idx < rw_idx && rw_idx < apt_idx && apt_idx < run_idx,
        "udev workaround and fail-fast /dev/kvm check must happen before apt-get and run"
    );

    // Minimal unprivileged session virtualization packages (no root libvirtd-system).
    for pkg in [
        "libvirt-daemon",
        "libvirt-daemon-driver-qemu",
        "libvirt-clients",
        "qemu-system-x86",
        "qemu-utils",
        "genisoimage",
    ] {
        assert!(smoke.contains(pkg), "missing package {pkg}:\n{smoke}");
    }

    // Guest image cached under a distinct key prefix so its path never collides with TCG's.
    assert!(
        smoke.contains("scripts/ci/libvirt-kvm-smoke.sh image-key"),
        "{smoke}"
    );
    assert!(smoke.contains("kvm-hosted-"), "{smoke}");
    assert!(smoke.contains("uses: actions/cache@"), "{smoke}");
    assert!(smoke.contains("--image-cache"), "{smoke}");

    // Binary digest anchored to build job output; smoke and cleanup run unprivileged (no sudo).
    assert!(
        smoke.contains(r#"--expect-sha256 "${{ needs.candidate.outputs.sha256 }}""#),
        "{smoke}"
    );
    for line in smoke.lines().filter(|l| l.contains("libvirt-kvm-smoke.sh")) {
        assert!(
            !line.contains("sudo"),
            "hosted qemu:///session invocation must not use sudo: {line}"
        );
    }

    // Cleanup, fallback failure-result generation (for early exits before `run` installs its
    // EXIT trap), summary, and artifact upload all run under `if: always()` in order.
    let cleanup_idx = smoke.find("libvirt-kvm-smoke.sh cleanup").unwrap();
    let cleanup_step = &smoke[smoke[..cleanup_idx].rfind("- name:").unwrap()..cleanup_idx];
    assert!(cleanup_step.contains("if: always()"), "{cleanup_step}");

    let fallback_idx = smoke
        .find("libvirt-kvm-smoke.sh result")
        .unwrap_or_else(|| {
            panic!("missing early-failure structured result.json fallback step:\n{smoke}")
        });
    let fallback_start = smoke[..fallback_idx].rfind("- name:").unwrap();
    let summary_idx = smoke.find("- name: Result summary").unwrap();
    let fallback_step = &smoke[fallback_start..summary_idx];
    assert!(fallback_step.contains("if: always()"), "{fallback_step}");
    assert!(
        fallback_step.contains("jq -e"),
        "fallback must validate existing and replacement result.json with jq:\n{fallback_step}"
    );
    assert!(
        fallback_step.contains("--accelerator unknown"),
        "{fallback_step}"
    );
    assert!(
        fallback_step.contains(&format!("--binary-sha256 {}", "0".repeat(64))),
        "fallback must use the unverified-digest sentinel:\n{fallback_step}"
    );

    let upload_idx = smoke.find("actions/upload-artifact").unwrap();
    let upload_step = &smoke[smoke[..upload_idx].rfind("- name:").unwrap()..upload_idx];
    assert!(upload_step.contains("if: always()"), "{upload_step}");
    assert!(
        cleanup_idx < fallback_idx && fallback_idx < summary_idx && summary_idx < upload_idx,
        "cleanup -> fallback result -> summary -> upload ordering must hold"
    );
}

#[test]
fn early_failure_fallback_writes_structured_fail_result_json() {
    require_jq();
    let sentinel = "0".repeat(64);

    // 1. Direct `result` subcommand exits non-zero (fail-closed) and publishes
    // result.json atomically via a temporary file + rename, leaving no temp files.
    let direct_dir = tempfile::tempdir().unwrap();
    let direct_out = direct_dir.path().join("out");
    std::fs::create_dir(&direct_out).unwrap();
    let output = lane(&[
        "result",
        "--out",
        direct_out.to_str().unwrap(),
        "--arch",
        "x86_64",
        "--source-sha",
        SHA,
        "--binary-sha256",
        &sentinel,
        "--accelerator",
        "unknown",
    ]);
    assert!(
        !output.status.success(),
        "fallback result must exit non-zero (fail-closed): {}",
        text(&output)
    );
    let entries: Vec<String> = std::fs::read_dir(&direct_out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["result.json"], "no leftover temp files");
    let script_src = std::fs::read_to_string(script()).unwrap();
    let wr_start = script_src.find("write_result()").unwrap();
    let wr_end = script_src[wr_start..].find("\ncmd_result()").unwrap() + wr_start;
    let write_result_fn = &script_src[wr_start..wr_end];
    assert!(
        write_result_fn.contains("mv -f ") && !write_result_fn.contains(r#">"$out/result.json""#),
        "write_result must publish atomically via temp file + mv -f:\n{write_result_fn}"
    );

    // 2. Execute the exact fallback step script from `.github/workflows/libvirt-kvm-hosted.yml`
    // against missing, empty, truncated, and valid-pass `result.json` inputs.
    let wf_path = root().join(".github/workflows/libvirt-kvm-hosted.yml");
    let extract = Command::new("ruby")
        .args([
            "-ryaml",
            "-e",
            r#"wf = YAML.load_file(ARGV[0]); step = wf["jobs"]["smoke"]["steps"].find { |s| s["name"].to_s.include?("Record structured failure") }; abort("missing step") unless step; print step["run"]"#,
            wf_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(extract.status.success(), "{}", text(&extract));
    let fallback_script = String::from_utf8(extract.stdout).unwrap();

    for case in ["missing", "empty", "truncated", "valid_pass"] {
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("out");
        if case != "missing" {
            std::fs::create_dir(&out_dir).unwrap();
        }
        match case {
            "missing" => {}
            "empty" => std::fs::write(out_dir.join("result.json"), b"").unwrap(),
            "truncated" => {
                std::fs::write(out_dir.join("result.json"), b"{\"schema\": 1, \"suite\":").unwrap()
            }
            "valid_pass" => std::fs::write(
                out_dir.join("result.json"),
                r#"{"schema":1,"suite":"libvirt-kvm-smoke-v1","result":"pass","virtualization":{"accelerator":"kvm"}}"#,
            )
            .unwrap(),
            _ => unreachable!(),
        }
        let run = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &fallback_script])
            .current_dir(root())
            .env("OUT", &out_dir)
            .env("ARCH", "x86_64")
            .env("GITHUB_SHA", SHA)
            .output()
            .unwrap();
        assert!(run.status.success(), "{case}: {}", text(&run));
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out_dir.join("result.json")).unwrap())
                .unwrap_or_else(|e| panic!("{case}: invalid result.json: {e}: {}", text(&run)));
        if case == "valid_pass" {
            assert_eq!(json["result"], "pass", "{case}: must preserve valid pass");
            assert_eq!(json["virtualization"]["accelerator"], "kvm", "{case}");
        } else {
            assert_eq!(json["schema"], 1, "{case}");
            assert_eq!(json["suite"], "libvirt-kvm-smoke-v1", "{case}");
            assert_eq!(json["source_repository"], "vicaya/qeminga", "{case}");
            assert_eq!(json["source_sha"], SHA, "{case}");
            assert_eq!(json["architecture"], "x86_64", "{case}");
            assert_eq!(json["candidate_binary_sha256"], sentinel, "{case}");
            assert_eq!(json["virtualization"]["hypervisor"], "qemu", "{case}");
            assert_eq!(json["virtualization"]["accelerator"], "unknown", "{case}");
            assert_eq!(json["virtualization"]["machine"], "q35", "{case}");
            for t in MANDATORY {
                assert_eq!(json["tests"][t], "not_run", "{case}/{t}");
            }
            assert_eq!(json["result"], "fail", "{case}");
        }
    }
}

/// Runs `libvirt-kvm-smoke.sh` guaranteed unprivileged (dropping to uid/gid
/// 65534 if the test suite itself is invoked as root) so `qemu:///session`'s
/// root refusal can never satisfy an assertion meant for a later preflight check.
fn lane_unprivileged(args: &[&str], env: &[(&str, &str)], path_override: Option<&Path>) -> Output {
    let bash = ["/usr/bin/bash", "/bin/bash"]
        .iter()
        .find(|p| Path::new(p).exists())
        .unwrap();
    let mut cmd = Command::new(bash);
    cmd.arg(script()).args(args);
    if let Some(p) = path_override {
        cmd.env("PATH", p);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    if std::fs::metadata("/proc/self").unwrap().uid() == 0 {
        cmd.uid(65534).gid(65534);
    }
    cmd.output().unwrap()
}

/// Gives the dropped test subprocess (uid/gid 65534 when the test runner is
/// root) private ownership of `path` with `mode`; leaves unprivileged runs at
/// their default user-private permissions.
fn grant_child_private(path: &Path, mode: u32, as_root: bool) {
    if as_root {
        std::os::unix::fs::chown(path, Some(65534), Some(65534)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

#[test]
fn run_fails_closed_with_result_json_when_kvm_device_is_missing_or_not_a_char_device() {
    require_jq();
    let arch = std::env::consts::ARCH;
    if arch != "x86_64" && arch != "aarch64" {
        return;
    }
    let as_root = std::fs::metadata("/proc/self").unwrap().uid() == 0;
    let dir = tempfile::tempdir().unwrap();
    if as_root {
        // Traversal-only for non-root; parent stays root-owned and never
        // world-writable during setup.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    }
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().mode() & 0o002,
        0,
        "temp parent must never be world-writable"
    );

    // Build a real, valid candidate directory and matching digest so the test
    // cannot accidentally pass because of a missing candidate.
    let bin_file = dir.path().join("built-qeminga");
    std::fs::write(&bin_file, b"valid fake candidate\n").unwrap();
    let cand_dir = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        cand_dir.to_str().unwrap(),
        "--binary",
        bin_file.to_str().unwrap(),
        "--arch",
        arch,
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "42",
        "--run-attempt",
        "1",
        "--runner",
        "ubuntu-24.04",
    ]);
    assert!(m.status.success(), "{}", text(&m));
    if as_root {
        std::fs::set_permissions(&cand_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        for entry in std::fs::read_dir(&cand_dir).unwrap() {
            let p = entry.unwrap().path();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
    let digest = sha256_hex(&cand_dir.join("qeminga"));

    let missing = dir.path().join("no-such-kvm");
    let regular = dir.path().join("regular-file-kvm");
    std::fs::write(&regular, b"").unwrap();
    grant_child_private(&regular, 0o600, as_root);

    let images_dir = dir.path().join("images");
    std::fs::create_dir(&images_dir).unwrap();
    grant_child_private(&images_dir, 0o700, as_root);
    assert_eq!(
        std::fs::metadata(&images_dir).unwrap().mode() & 0o002,
        0,
        "images dir must never be world-writable"
    );

    for (label, kvm_path) in [("missing", &missing), ("regular", &regular)] {
        let out_dir = dir.path().join(format!("out-{label}"));
        std::fs::create_dir(&out_dir).unwrap();
        grant_child_private(&out_dir, 0o700, as_root);
        assert_eq!(
            std::fs::metadata(&out_dir).unwrap().mode() & 0o002,
            0,
            "out dir must never be world-writable"
        );
        let output = lane_unprivileged(
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                cand_dir.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "42",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_KVM_DEVICE", kvm_path.to_str().unwrap()),
                ("QEMINGA_E2E_IMAGES", images_dir.to_str().unwrap()),
            ],
            None,
        );
        let combined = text(&output);
        assert!(
            !output.status.success(),
            "{label}: expected failure: {combined}"
        );
        let expected_diag = format!(
            "KVM device {} is missing or not readable/writable by uid ",
            kvm_path.display()
        );
        assert!(
            combined.contains(&expected_diag),
            "{label}: failure must name the rejected KVM device path ({expected_diag:?}):\n{combined}"
        );
        assert!(
            !combined.contains("refusing to run qemu:///session as root"),
            "{label}: must not stop at root-session check:\n{combined}"
        );
        assert!(
            !combined.contains("missing tool:"),
            "{label}: must fail at the KVM device check before tool checks:\n{combined}"
        );
        let result_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out_dir.join("result.json")).unwrap())
                .unwrap_or_else(|e| panic!("{label}: {e}: {combined}"));
        assert_eq!(result_json["suite"], "libvirt-kvm-smoke-v1", "{label}");
        assert_eq!(result_json["result"], "fail", "{label}");
        assert_eq!(
            result_json["virtualization"]["accelerator"], "unknown",
            "{label}: must never silently fall back to tcg"
        );
        assert_eq!(
            result_json["tests"]["accelerator_kvm"], "not_run",
            "{label}"
        );
    }

    // Positive control: a readable/writable char device (/dev/null) gets PAST the KVM device
    // guard and reaches the subsequent tool check (stopping at `missing tool: virsh` under a
    // PATH that omits `virsh`), proving the assertions above only pass because of the guard.
    let minimal_bin = dir.path().join("minimal-bin");
    std::fs::create_dir(&minimal_bin).unwrap();
    if as_root {
        std::fs::set_permissions(&minimal_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for tool in [
        "dirname", "basename", "uname", "id", "mkdir", "rm", "cat", "tr", "jq", "printf", "cut",
        "cp", "mv",
    ] {
        if let Some(real) = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
        {
            std::os::unix::fs::symlink(real, minimal_bin.join(tool)).unwrap();
        }
    }
    let ctrl_out = dir.path().join("out-control");
    std::fs::create_dir(&ctrl_out).unwrap();
    grant_child_private(&ctrl_out, 0o700, as_root);
    let ctrl = lane_unprivileged(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            cand_dir.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "42",
            "--run-attempt",
            "1",
            "--out",
            ctrl_out.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_E2E_IMAGES", images_dir.to_str().unwrap()),
        ],
        Some(&minimal_bin),
    );
    let ctrl_text = text(&ctrl);
    assert!(!ctrl.status.success(), "{ctrl_text}");
    assert!(
        !ctrl_text.contains("KVM device /dev/null is missing"),
        "rw char device must pass the KVM device check:\n{ctrl_text}"
    );
    assert!(
        ctrl_text.contains("missing tool: virsh"),
        "control run should reach the next preflight stage (missing tool: virsh):\n{ctrl_text}"
    );
}
