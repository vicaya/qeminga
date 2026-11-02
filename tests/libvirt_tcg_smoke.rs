//! The libvirt + QEMU TCG smoke lane (#53, AC16): the hosted-runner lane
//! that boots a disposable Ubuntu guest under real libvirt with the TCG
//! accelerator on both supported architectures, installs the hosted
//! release candidate with the shipped packaging and runs
//! `scripts/e2e-libvirt.sh` against it.
//!
//! The lane itself needs root, libvirt and minutes of emulation, so it
//! runs in `.github/workflows/libvirt-tcg.yml` only. What is checked here
//! is the logic around it that must fail closed: the candidate manifest
//! and its verification, the domain definition (TCG, never KVM), the
//! stale-domain and cleanup namespace guards, the result contract, and
//! the workflow's shape (native runners, no rebuild in the lane, the
//! production feature set only).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
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
    lane_with_path(args, None)
}

/// Runs the lane script; `bin`, when given, is put first on `PATH` so a
/// scripted `virsh` stands in for the real one.
fn lane_with_path(args: &[&str], bin: Option<&Path>) -> Output {
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
    cmd.output().unwrap()
}

/// The script's `manifest`, `verify-candidate` and `result` subcommands
/// build and read JSON with `jq` (preinstalled on GitHub's Ubuntu runners;
/// AGENTS.md lists it). Without it those tests would fail with a bare
/// `jq: command not found` from the script, or pass a refusal for the
/// wrong reason, so they stop here with the fix instead.
fn require_jq() {
    let found = Command::new("jq")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        found,
        "jq is required by scripts/ci/libvirt-tcg-smoke.sh and these tests: install it (apt-get install jq)"
    );
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A candidate directory as the hosted build job produces it.
fn candidate(dir: &Path, arch: &str) -> PathBuf {
    require_jq();
    let binary = dir.join("built-qeminga");
    std::fs::write(&binary, b"not really an ELF, but bytes with a digest\n").unwrap();
    let out = dir.join("candidate");
    let output = lane(&[
        "manifest",
        "--out",
        out.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
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
    assert!(output.status.success(), "{}", text(&output));
    out
}

fn manifest(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap()
}

fn sha256_hex(path: &Path) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(std::fs::read(path).unwrap());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- candidate manifest ------------------------------------------------

#[test]
fn the_manifest_names_the_source_the_build_and_the_digest_of_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let out = candidate(dir.path(), "x86_64");
    let m = manifest(&out);
    assert_eq!(m["schema"], 1);
    assert_eq!(m["source_repository"], "vicaya/qeminga");
    assert_eq!(m["source_sha"], SHA);
    assert_eq!(m["architecture"], "x86_64");
    assert_eq!(m["version"], "0.1.0");
    assert_eq!(m["binary"]["path"], "qeminga");
    assert_eq!(m["binary"]["sha256"], sha256_hex(&out.join("qeminga")));
    assert_eq!(m["build"]["run_id"], 42);
    assert_eq!(m["build"]["run_attempt"], 1);
    assert_eq!(m["build"]["runner"], "ubuntu-24.04");
    assert_eq!(
        m["build"]["command"],
        "cargo build --release --locked --features seccomp"
    );
    // The shipped packaging travels with the candidate, digested too.
    for file in [
        "packaging/systemd/qeminga.service",
        "packaging/udev/99-qeminga.rules",
        "packaging/sysusers.d/qeminga.conf",
        "packaging/tmpfiles.d/qeminga.conf",
        "packaging/config.toml",
    ] {
        assert_eq!(
            std::fs::read(out.join(file)).unwrap(),
            std::fs::read(root().join(file)).unwrap(),
            "{file}"
        );
        assert_eq!(
            m["packaging"][file],
            sha256_hex(&root().join(file)),
            "{file}"
        );
    }
}

#[test]
fn the_manifest_refuses_a_short_sha_an_unknown_architecture_and_a_rerun_identity() {
    require_jq();
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("b");
    std::fs::write(&binary, b"x").unwrap();
    let base = |sha: &str, arch: &str, id: &str| {
        lane(&[
            "manifest",
            "--out",
            dir.path().join("o").to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--arch",
            arch,
            "--source-sha",
            sha,
            "--version",
            "0.1.0",
            "--run-id",
            id,
            "--run-attempt",
            "1",
            "--runner",
            "ubuntu-24.04",
        ])
    };
    assert!(!base("0123456", "x86_64", "42").status.success());
    assert!(!base("main", "x86_64", "42").status.success());
    assert!(!base(SHA, "riscv64", "42").status.success());
    assert!(!base(SHA, "x86_64", "42; rm -rf /").status.success());
}

#[test]
fn a_verified_candidate_prints_its_digest() {
    let dir = tempfile::tempdir().unwrap();
    let out = candidate(dir.path(), "aarch64");
    let output = lane(&["verify-candidate", out.to_str().unwrap(), "aarch64", SHA]);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        sha256_hex(&out.join("qeminga"))
    );
}

#[test]
fn candidate_verification_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let out = candidate(dir.path(), "x86_64");
    let verify = |arch: &str, sha: &str| {
        lane(&["verify-candidate", out.to_str().unwrap(), arch, sha])
            .status
            .success()
    };
    assert!(verify("x86_64", SHA));
    // Wrong architecture, wrong source.
    assert!(!verify("aarch64", SHA));
    assert!(!verify("x86_64", &SHA.replace('0', "f")));

    // A binary that is not the one the manifest names.
    let good = std::fs::read(out.join("qeminga")).unwrap();
    std::fs::write(out.join("qeminga"), b"substituted").unwrap();
    assert!(!verify("x86_64", SHA));
    std::fs::write(out.join("qeminga"), &good).unwrap();
    assert!(verify("x86_64", SHA));

    // A packaging file that is not the one the manifest names.
    let unit = out.join("packaging/systemd/qeminga.service");
    let original = std::fs::read(&unit).unwrap();
    std::fs::write(&unit, b"[Service]\nExecStart=/bin/true\n").unwrap();
    assert!(!verify("x86_64", SHA));
    std::fs::write(&unit, &original).unwrap();

    // Unknown schema, malformed manifest, missing manifest.
    let path = out.join("manifest.json");
    let mut m = manifest(&out);
    m["schema"] = 2.into();
    std::fs::write(&path, m.to_string()).unwrap();
    assert!(!verify("x86_64", SHA));
    std::fs::write(&path, b"{not json").unwrap();
    assert!(!verify("x86_64", SHA));
    std::fs::remove_file(&path).unwrap();
    assert!(!verify("x86_64", SHA));
}

// ---- domain definition -------------------------------------------------

fn domain_xml(arch: &str) -> Output {
    lane(&[
        "domain-xml",
        "--arch",
        arch,
        "--name",
        "qeminga-e2e-42-1-x",
        "--dir",
        "/var/lib/libvirt/images/qeminga-e2e-42-1-x",
    ])
}

#[test]
fn the_domain_runs_under_tcg_never_kvm_on_both_architectures() {
    for (arch, machine) in [("x86_64", "q35"), ("aarch64", "virt")] {
        let output = domain_xml(arch);
        assert!(output.status.success(), "{}", text(&output));
        let xml = String::from_utf8(output.stdout).unwrap();
        assert!(xml.contains("<domain type='qemu'>"), "{arch}: {xml}");
        assert!(!xml.to_lowercase().contains("kvm"), "{arch}: {xml}");
        assert!(
            xml.contains(&format!(
                "<type arch='{arch}' machine='{machine}'>hvm</type>"
            )),
            "{arch}: {xml}"
        );
        assert!(
            xml.contains("<target type='virtio' name='org.qemu.guest_agent.0'/>"),
            "{arch}: the guest-agent channel: {xml}"
        );
        // The guest boots from disk: no NIC option ROM, so the lane does
        // not depend on the ROM package of the runner's QEMU.
        assert!(xml.contains("<rom enabled='no'/>"), "{arch}: {xml}");
        assert!(
            xml.contains("<name>qeminga-e2e-42-1-x</name>"),
            "{arch}: {xml}"
        );
        // Every file the domain uses lies in the run's own directory.
        for line in xml.lines().filter(|l| l.contains("<source file=")) {
            assert!(
                line.contains("'/var/lib/libvirt/images/qeminga-e2e-42-1-x/"),
                "{arch}: {line}"
            );
        }
    }
}

#[test]
fn the_aarch64_domain_boots_uefi_with_an_explicit_aarch64_cpu_model() {
    let xml = String::from_utf8(domain_xml("aarch64").stdout).unwrap();
    assert!(
        xml.contains("<loader readonly='yes' type='pflash'>/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd</loader>"),
        "{xml}"
    );
    assert!(
        xml.contains("<nvram template='/usr/share/AAVMF/AAVMF_VARS.fd'>"),
        "{xml}"
    );
    assert!(
        xml.contains("<model fallback='forbid'>cortex-a57</model>"),
        "{xml}"
    );
}

#[test]
fn the_domain_refuses_names_outside_the_run_namespace_and_unknown_architectures() {
    let bad_name = lane(&[
        "domain-xml",
        "--arch",
        "x86_64",
        "--name",
        "production-vm",
        "--dir",
        "/var/lib/libvirt/images/production-vm",
    ]);
    assert!(!bad_name.status.success());
    assert!(!domain_xml("riscv64").status.success());
}

fn domain_xml_with_vcpus(vcpus: &str) -> Output {
    lane(&[
        "domain-xml",
        "--arch",
        "x86_64",
        "--name",
        "qeminga-e2e-42-1-x",
        "--dir",
        "/var/lib/libvirt/images/qeminga-e2e-42-1-x",
        "--vcpus",
        vcpus,
    ])
}

#[test]
fn the_vcpu_count_is_explicit_and_bounded() {
    assert!(
        String::from_utf8(domain_xml("x86_64").stdout)
            .unwrap()
            .contains("<vcpu>2</vcpu>")
    );
    let four = domain_xml_with_vcpus("4");
    assert!(four.status.success(), "{}", text(&four));
    assert!(
        String::from_utf8(four.stdout)
            .unwrap()
            .contains("<vcpu>4</vcpu>")
    );
    for bad in ["0", "100", "four", "4</vcpu><vcpu>8"] {
        assert!(!domain_xml_with_vcpus(bad).status.success(), "{bad}");
    }
}

#[test]
fn more_vcpus_than_eight_are_capped_at_eight() {
    for (asked, got) in [
        ("8", "<vcpu>8</vcpu>"),
        ("9", "<vcpu>8</vcpu>"),
        ("64", "<vcpu>8</vcpu>"),
    ] {
        let output = domain_xml_with_vcpus(asked);
        assert!(output.status.success(), "{asked}: {}", text(&output));
        assert!(
            String::from_utf8(output.stdout).unwrap().contains(got),
            "{asked} vCPUs"
        );
    }
}

#[test]
fn the_machine_type_is_the_one_the_result_records() {
    // One source for the machine: the domain's <type machine=...> and the
    // result's virtualization.machine come from the same function.
    for arch in ["x86_64", "aarch64"] {
        let xml = String::from_utf8(domain_xml(arch).stdout).unwrap();
        let machine = xml
            .split("machine='")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("tests")).unwrap();
        require_jq();
        lane(&[
            "result",
            "--out",
            dir.path().to_str().unwrap(),
            "--arch",
            arch,
            "--source-sha",
            SHA,
            "--binary-sha256",
            &"a".repeat(64),
            "--accelerator",
            "tcg",
        ]);
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("result.json")).unwrap())
                .unwrap();
        assert_eq!(json["virtualization"]["machine"], machine, "{arch}");
    }
}

#[test]
fn a_run_directory_that_would_not_be_literal_xml_is_refused() {
    // The directory is written into attributes and elements unescaped, so
    // only a plain path character set is accepted.
    for parent in [
        "/srv/o'brien/images",
        "/srv/a&b",
        "/srv/<x>",
        "relative/images",
        "/srv/sp ace",
    ] {
        let dir = format!("{parent}/qeminga-e2e-42-1-x");
        let output = lane(&[
            "domain-xml",
            "--arch",
            "x86_64",
            "--name",
            "qeminga-e2e-42-1-x",
            "--dir",
            &dir,
        ]);
        assert!(!output.status.success(), "{dir}: {}", text(&output));
    }
}

// ---- guest image ---------------------------------------------------------

fn fetch(dir: &Path, sha: &str, cache: Option<&Path>, sources: &[String]) -> Output {
    let dest = dir.join("root.qcow2");
    let mut args: Vec<String> = vec![
        "fetch-image".into(),
        "--sha256".into(),
        sha.into(),
        "--dest".into(),
        dest.display().to_string(),
    ];
    if let Some(cache) = cache {
        args.push("--cache".into());
        args.push(cache.display().to_string());
    }
    args.push("--".into());
    args.extend(sources.iter().cloned());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    lane(&refs)
}

/// A source directory holding `img` with the given bytes, as a file:// URL.
fn source(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let d = dir.join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("img"), bytes).unwrap();
    format!("file://{}/img", d.display())
}

fn sha_of(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn a_missing_source_falls_back_to_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let good = b"the pinned image";
    let gone = format!("file://{}/pruned/img", dir.path().display());
    let mirror = source(dir.path(), "mirror", good);
    let output = fetch(dir.path(), &sha_of(good), None, &[gone, mirror]);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(std::fs::read(dir.path().join("root.qcow2")).unwrap(), good);
}

#[test]
fn a_source_with_other_bytes_is_skipped_and_nothing_matching_fails() {
    let dir = tempfile::tempdir().unwrap();
    let good = b"the pinned image";
    let wrong = source(dir.path(), "tampered", b"something else");
    let right = source(dir.path(), "mirror", good);
    let output = fetch(dir.path(), &sha_of(good), None, &[wrong.clone(), right]);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(std::fs::read(dir.path().join("root.qcow2")).unwrap(), good);

    let none = fetch(dir.path(), &sha_of(good), None, &[wrong]);
    assert!(!none.status.success(), "{}", text(&none));
}

#[test]
fn a_cached_image_is_used_only_when_its_digest_matches() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    let good = b"the pinned image";
    let sha = sha_of(good);
    let src = source(dir.path(), "mirror", good);
    // First run fills the cache.
    let first = fetch(dir.path(), &sha, Some(&cache), std::slice::from_ref(&src));
    assert!(first.status.success(), "{}", text(&first));
    // Second run needs no source at all.
    std::fs::remove_file(dir.path().join("root.qcow2")).unwrap();
    let gone = format!("file://{}/pruned/img", dir.path().display());
    let cached = fetch(dir.path(), &sha, Some(&cache), std::slice::from_ref(&gone));
    assert!(cached.status.success(), "{}", text(&cached));
    assert_eq!(std::fs::read(dir.path().join("root.qcow2")).unwrap(), good);
    // A corrupted cache entry is not used; with no good source it fails.
    for entry in std::fs::read_dir(&cache).unwrap() {
        std::fs::write(entry.unwrap().path(), b"bit rot").unwrap();
    }
    std::fs::remove_file(dir.path().join("root.qcow2")).unwrap();
    let corrupt = fetch(dir.path(), &sha, Some(&cache), &[gone]);
    assert!(!corrupt.status.success(), "{}", text(&corrupt));
}

#[test]
fn the_image_cache_key_names_the_pinned_release_and_digest() {
    for arch in ["x86_64", "aarch64"] {
        let output = lane(&["image-key", arch]);
        assert!(output.status.success(), "{}", text(&output));
        let key = String::from_utf8(output.stdout).unwrap();
        let script = std::fs::read_to_string(script()).unwrap();
        let release = script
            .lines()
            .find_map(|l| l.strip_prefix("IMAGE_RELEASE=\""))
            .unwrap()
            .trim_end_matches('"');
        assert!(key.contains(release), "{key}");
        let var = format!("IMAGE_SHA256_{arch}=\"");
        let digest = script
            .lines()
            .find_map(|l| l.strip_prefix(var.as_str()))
            .unwrap()
            .trim_end_matches('"');
        assert!(key.trim_end().ends_with(digest), "{key}");
    }
    assert!(!lane(&["image-key", "riscv64"]).status.success());
}

// ---- stale domains and cleanup -----------------------------------------

/// A `virsh` stand-in for the listing and teardown commands. `FAKE_LIST`
/// is the `list --all --name` output; `FAKE_LIST_FAILS=1` makes the
/// listing fail. Every call is appended to `FAKE_LOG`.
const FAKE_VIRSH: &str = r#"#!/bin/sh
echo "$*" >> "${FAKE_LOG:?}"
case "$1" in --connect=*) shift ;; esac
case "$1" in
    list)
        [ "${FAKE_LIST_FAILS:-0}" = 1 ] && { echo "error: failed to connect to the hypervisor" >&2; exit 1; }
        printf '%s\n' ${FAKE_LIST:-} ""; exit 0 ;;
    domstate)
        [ "${FAKE_STATE_FAILS:-0}" = 1 ] && { echo "error: internal error" >&2; exit 1; }
        if [ -n "${FAKE_LIST:-}" ]; then echo "${FAKE_DOMSTATE:-running}"; exit 0; fi
        echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#;

struct Fake {
    dir: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bin")).unwrap();
        write_exec(&dir.path().join("bin/virsh"), FAKE_VIRSH);
        Fake { dir }
    }

    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new("bash");
        cmd.arg(script()).args(args);
        let path = format!(
            "{}:{}",
            self.dir.path().join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path)
            .env("FAKE_LOG", self.dir.path().join("log"));
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("log")).unwrap_or_default()
    }
}

#[test]
fn a_stale_test_domain_stops_the_lane() {
    let fake = Fake::new();
    let clean = fake.run(&["stale-check"], &[("FAKE_LIST", "other-vm")]);
    assert!(clean.status.success(), "{}", text(&clean));
    let stale = fake.run(
        &["stale-check"],
        &[("FAKE_LIST", "other-vm qeminga-e2e-41-1-x86_64")],
    );
    assert!(!stale.status.success());
    assert!(
        text(&stale).contains("qeminga-e2e-41-1-x86_64"),
        "the diagnostic names the stale domain: {}",
        text(&stale)
    );
}

#[test]
fn an_unknown_libvirt_state_is_not_taken_for_no_stale_domain() {
    let fake = Fake::new();
    let output = fake.run(&["stale-check"], &[("FAKE_LIST_FAILS", "1")]);
    assert!(!output.status.success(), "{}", text(&output));
}

#[test]
fn cleanup_refuses_anything_outside_the_run_namespace() {
    let fake = Fake::new();
    let images = tempfile::tempdir().unwrap();
    let victim = images.path().join("production-vm");
    std::fs::create_dir(&victim).unwrap();
    for (run_id, attempt) in [("../production-vm", "1"), ("42", "1/../..")] {
        let output = fake.run(
            &[
                "cleanup",
                "--arch",
                "x86_64",
                "--run-id",
                run_id,
                "--run-attempt",
                attempt,
            ],
            &[("QEMINGA_E2E_IMAGES", images.path().to_str().unwrap())],
        );
        assert!(!output.status.success(), "{}", text(&output));
    }
    assert!(victim.exists());
    assert!(
        !fake.log().contains("destroy") && !fake.log().contains("undefine"),
        "{}",
        fake.log()
    );
}

#[test]
fn cleanup_keeps_the_disks_while_the_domain_state_is_unknown() {
    let fake = Fake::new();
    let images = tempfile::tempdir().unwrap();
    let dir = images.path().join("qeminga-e2e-42-1-x86_64");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("disk.qcow2"), b"x").unwrap();
    let args = [
        "cleanup",
        "--arch",
        "x86_64",
        "--run-id",
        "42",
        "--run-attempt",
        "1",
    ];
    let env = [
        ("QEMINGA_E2E_IMAGES", images.path().to_str().unwrap()),
        ("FAKE_LIST", "qeminga-e2e-42-1-x86_64"),
        ("FAKE_STATE_FAILS", "1"),
    ];
    let output = fake.run(&args, &env);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        dir.join("disk.qcow2").exists(),
        "disks of a domain in an unknown state are kept"
    );
}

/// Runs the script with a PATH that has no `virsh` (as on a runner whose
/// libvirt install step never ran): only the few tools the cleanup path
/// uses besides bash builtins.
fn without_virsh(args: &[&str], images: &Path) -> Output {
    let bin = tempfile::tempdir().unwrap();
    for tool in ["dirname", "basename", "rm"] {
        let real = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
            .unwrap();
        std::os::unix::fs::symlink(real, bin.path().join(tool)).unwrap();
    }
    let bash = ["/usr/bin/bash", "/bin/bash"]
        .iter()
        .find(|p| Path::new(p).exists())
        .unwrap();
    Command::new(bash)
        .arg(script())
        .args(args)
        .env("PATH", bin.path())
        .env("QEMINGA_E2E_IMAGES", images)
        .output()
        .unwrap()
}

#[test]
fn cleanup_without_libvirt_and_without_files_has_nothing_to_do() {
    let images = tempfile::tempdir().unwrap();
    let args = [
        "cleanup",
        "--arch",
        "x86_64",
        "--run-id",
        "42",
        "--run-attempt",
        "1",
    ];
    let output = without_virsh(&args, images.path());
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        text(&output).contains("nothing to clean up"),
        "{}",
        text(&output)
    );

    // Files of this run but no libvirt to ask about the domain: keep them.
    let dir = images.path().join("qeminga-e2e-42-1-x86_64");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("disk.qcow2"), b"x").unwrap();
    let output = without_virsh(&args, images.path());
    assert!(!output.status.success(), "{}", text(&output));
    assert!(dir.join("disk.qcow2").exists());
}

#[test]
fn cleanup_removes_only_the_current_run() {
    let fake = Fake::new();
    let images = tempfile::tempdir().unwrap();
    let mine = images.path().join("qeminga-e2e-42-1-x86_64");
    let other = images.path().join("qeminga-e2e-43-1-x86_64");
    for d in [&mine, &other] {
        std::fs::create_dir(d).unwrap();
        std::fs::write(d.join("disk.qcow2"), b"x").unwrap();
    }
    // The domain is already gone (the lane shut it down).
    let output = fake.run(
        &[
            "cleanup",
            "--arch",
            "x86_64",
            "--run-id",
            "42",
            "--run-attempt",
            "1",
        ],
        &[("QEMINGA_E2E_IMAGES", images.path().to_str().unwrap())],
    );
    assert!(output.status.success(), "{}", text(&output));
    assert!(!mine.exists());
    assert!(other.join("disk.qcow2").exists());
}

// ---- result contract ---------------------------------------------------

const MANDATORY: [&str; 4] = [
    "production_install",
    "accelerator_tcg",
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
fn a_passing_result_records_tcg_and_every_mandatory_test() {
    let all: Vec<(&str, &str)> = MANDATORY.iter().map(|t| (*t, "pass")).collect();
    let (ok, json) = result(&all, "tcg");
    assert!(ok);
    assert_eq!(json["schema"], 1);
    assert_eq!(json["suite"], "libvirt-tcg-smoke-v1");
    assert_eq!(json["source_sha"], SHA);
    assert_eq!(json["architecture"], "aarch64");
    assert_eq!(json["candidate_binary_sha256"], "a".repeat(64));
    assert_eq!(json["virtualization"]["hypervisor"], "qemu");
    assert_eq!(json["virtualization"]["accelerator"], "tcg");
    assert_eq!(json["virtualization"]["machine"], "virt");
    for t in MANDATORY {
        assert_eq!(json["tests"][t], "pass", "{t}");
    }
    assert_eq!(json["result"], "pass");
}

#[test]
fn a_missing_or_failed_test_or_another_accelerator_fails_the_result() {
    for skip in MANDATORY {
        let partial: Vec<(&str, &str)> = MANDATORY
            .iter()
            .filter(|t| **t != skip)
            .map(|t| (*t, "pass"))
            .collect();
        let (ok, json) = result(&partial, "tcg");
        assert!(!ok, "{skip} missing");
        assert_eq!(json["tests"][skip], "not_run");
        assert_eq!(json["result"], "fail");

        let failed: Vec<(&str, &str)> = MANDATORY
            .iter()
            .map(|t| (*t, if *t == skip { "fail" } else { "pass" }))
            .collect();
        let (ok, json) = result(&failed, "tcg");
        assert!(!ok, "{skip} failed");
        assert_eq!(json["result"], "fail");
    }
    // A status file holding anything but pass/fail is not a pass.
    let odd: Vec<(&str, &str)> = MANDATORY
        .iter()
        .map(|t| {
            (
                *t,
                if *t == "libvirt_interop" {
                    "skipped"
                } else {
                    "pass"
                },
            )
        })
        .collect();
    let (ok, json) = result(&odd, "tcg");
    assert!(!ok);
    assert_eq!(json["tests"]["libvirt_interop"], "fail");

    let all: Vec<(&str, &str)> = MANDATORY.iter().map(|t| (*t, "pass")).collect();
    let (ok, json) = result(&all, "kvm");
    assert!(!ok, "the TCG lane never reports KVM evidence as a pass");
    assert_eq!(json["result"], "fail");
}

// ---- workflow ----------------------------------------------------------

fn caller() -> String {
    std::fs::read_to_string(root().join(".github/workflows/libvirt-tcg.yml")).unwrap()
}

fn lane_workflow() -> String {
    std::fs::read_to_string(root().join(".github/workflows/libvirt-tcg-lane.yml")).unwrap()
}

/// The text of one job, from its key to the next two-space-indented key.
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
fn each_architecture_is_its_own_lane_on_its_native_hosted_runner() {
    // One call of the reusable lane per architecture: an architecture's
    // smoke job waits only for its own candidate, never for the other's.
    let text = caller();
    for (arch, runner, runner_arch) in [
        ("x86_64", "ubuntu-24.04", "X64"),
        ("aarch64", "ubuntu-24.04-arm", "ARM64"),
    ] {
        let job = job(&text, arch);
        assert!(
            job.contains("uses: ./.github/workflows/libvirt-tcg-lane.yml"),
            "{arch}"
        );
        assert!(job.contains(&format!("arch: {arch}\n")), "{arch}");
        assert!(job.contains(&format!("runner: {runner}\n")), "{arch}");
        assert!(
            job.contains(&format!("runner_arch: {runner_arch}\n")),
            "{arch}"
        );
        assert!(job.contains("needs: changes"), "{arch}");
        assert!(
            job.contains("if: needs.changes.outputs.code == 'true'"),
            "{arch}: waits for the change classification"
        );
    }
    assert!(job(&text, "changes").contains("scripts/ci/docs-only.sh"));
    assert!(
        !text.contains("strategy:") && !lane_workflow().contains("strategy:"),
        "no matrix couples the architectures"
    );
}

#[test]
fn both_lane_jobs_prove_the_runner_architecture_and_are_bounded() {
    let text = lane_workflow();
    assert!(text.contains("workflow_call:"));
    for name in ["candidate", "smoke"] {
        let job = job(&text, name);
        assert!(job.contains("runs-on: ${{ inputs.runner }}"), "{name}");
        assert!(
            job.contains(r#"test "$(uname -m)" = "${{ inputs.arch }}""#),
            "{name}: the runner proves its architecture"
        );
        assert!(
            job.contains(r#"test "$RUNNER_ARCH" = "${{ inputs.runner_arch }}""#),
            "{name}"
        );
        assert!(!job.contains("continue-on-error"), "{name}");
        assert!(job.contains("timeout-minutes:"), "{name}: bounded");
    }
}

#[test]
fn the_candidate_is_the_production_build_and_the_lane_never_rebuilds_it() {
    let text = lane_workflow();
    let build = job(&text, "candidate");
    assert!(build.contains("cargo build --release --locked --features seccomp\n"));
    for forbidden in ["--all-features", "test-fakes", "seccomp-log"] {
        assert!(!build.contains(forbidden), "candidate: {forbidden}");
    }
    let smoke = job(&text, "smoke");
    assert!(smoke.contains("needs: candidate"));
    assert!(
        !smoke.contains("cargo "),
        "the lane installs the candidate, it never builds one"
    );
    assert!(!smoke.contains("rustup"), "the lane has no toolchain");
    assert!(smoke.contains("libvirt-tcg-smoke.sh run"));
}

#[test]
fn the_installed_binary_is_anchored_to_the_digest_the_build_job_reported() {
    // The artifact carries the binary and its manifest together, so a
    // manifest check alone proves consistency, not provenance. The build
    // job reports the digest of the binary it built as a job output, and
    // the lane refuses a candidate whose binary does not have it.
    let text = lane_workflow();
    let build = job(&text, "candidate");
    assert!(build.contains("sha256: ${{ steps.digest.outputs.sha256 }}"));
    assert!(build.contains("sha256sum target/release/qeminga"));
    let smoke = job(&text, "smoke");
    assert!(
        smoke.contains(r#"--expect-sha256 "${{ needs.candidate.outputs.sha256 }}""#),
        "{smoke}"
    );
}

#[test]
fn the_guest_image_is_cached_under_its_pinned_digest() {
    let smoke = job(&lane_workflow(), "smoke").to_owned();
    assert!(smoke.contains("libvirt-tcg-smoke.sh image-key"));
    assert!(smoke.contains("uses: actions/cache@"));
    assert!(smoke.contains("--image-cache"));
}

#[test]
fn the_lane_cleans_up_and_keeps_its_evidence_whatever_happened() {
    let text = lane_workflow();
    let smoke = job(&text, "smoke");
    let cleanup = smoke
        .find("libvirt-tcg-smoke.sh cleanup")
        .expect("a cleanup step");
    let before = &smoke[..cleanup];
    let step = &before[before.rfind("- name:").unwrap()..];
    assert!(step.contains("if: always()"), "{step}");
    let upload = smoke
        .find("actions/upload-artifact")
        .expect("evidence upload");
    let step = &smoke[..upload];
    let step = &step[step.rfind("- name:").unwrap()..];
    assert!(step.contains("if: always()"), "{step}");
}
