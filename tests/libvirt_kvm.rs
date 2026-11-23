//! The libvirt + QEMU KVM smoke lane (#53, AC16): builds the production
//! release candidate on GitHub-hosted runners and exercises it under real
//! libvirt + KVM on self-hosted x86_64 and aarch64 runners without root,
//! `sudo`, or a Rust toolchain on the runner host.
//!
//! Mirrors `tests/libvirt_tcg_smoke.rs` for the KVM lane: candidate manifest
//! and fail-closed verification, image-pin parity with the TCG script, KVM
//! domain XML (`type='kvm'`, `host-passthrough`, aarch64 UEFI + `gic host`,
//! unprivileged `user` networking under `qemu:///session`), URI validation,
//! stale-domain and cleanup namespace guards, the `libvirt-kvm-smoke-v1`
//! result contract (refusing TCG as a pass), and workflow security invariants
//! (never triggered by `pull_request` / `pull_request_target`, no `sudo` or
//! build tools on the self-hosted runner, checks out `$GITHUB_SHA` directly
//! without a user-controlled ref input, bounded concurrency with
//! `cancel-in-progress: false`).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
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

#[test]
fn kvm_run_directory_permissions_match_libvirt_connection_mode() {
    require_jq();
    let arch = std::env::consts::ARCH;
    assert!(
        arch == "x86_64" || arch == "aarch64",
        "unexpected test arch {arch}"
    );

    let dir = tempfile::tempdir().unwrap();
    // Ensure the outer tempdir root itself is traversable (0755) for simulated QEMU checks.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();

    // Build a valid candidate bundle matching the host arch.
    let binary = dir.path().join("qeminga-bin");
    std::fs::write(&binary, b"fake release binary\n").unwrap();
    let candidate = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        candidate.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--arch",
        arch,
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "77",
        "--run-attempt",
        "1",
        "--runner",
        "test-runner",
    ]);
    assert!(m.status.success(), "{}", text(&m));
    let digest = sha256_hex(&candidate.join("qeminga"));

    // Resolve the pinned image SHA for this arch from the common helper so our
    // mock curl / cache-hit fixtures exercise the real `fetch_image` path.
    let img_key = lane(&["image-key", arch]);
    assert!(img_key.status.success(), "{}", text(&img_key));
    let pinned_image_sha = String::from_utf8(img_key.stdout)
        .unwrap()
        .trim()
        .rsplit('-')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(pinned_image_sha.len(), 64);

    // Current primary group number so real `chgrp` succeeds unprivileged while
    // `qemu_acct_num` is strictly distinct from the current caller account.
    let caller_grp_num = String::from_utf8(
        Command::new("/usr/bin/id")
            .arg("-g")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let qemu_acct_num = "64055";
    let qemu_user_spec = format!("+{qemu_acct_num}");
    let qemu_group_spec = format!("+{caller_grp_num}");

    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
case "$1" in --connect=*) shift ;; esac
case "$1" in
    version) echo "Compiled against library: libvirt 10.0.0"; exit 0 ;;
    domcapabilities) echo "<domainCapabilities/>"; exit 0 ;;
    net-info) echo "Active:         yes"; exit 0 ;;
    list) echo ""; exit 0 ;;
    define) exit 0 ;;
    start) exit 42 ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(&bin.join("qemu-img"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("genisoimage"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -output) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$out" ] && : > "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join(format!("qemu-system-{arch}")),
        "#!/bin/sh\necho 'QEMU emulator version 8.2.2'\n",
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
if [ -n "${FAKE_CURL_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_CURL_LOG"; fi
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf 'fake qcow2 bytes\n' > "$out"
if [ "${FAKE_CURL_OPEN_MODE:-0}" = "1" ]; then
    chmod 0644 "$out"
fi
exit 0
"#,
    );
    write_exec(
        &bin.join("sha256sum"),
        r#"#!/bin/sh
case "$1" in
    *.qcow2.part | */img-cache/*) printf '%s  %s\n' "${FAKE_IMAGE_SHA:?}" "$1"; exit 0 ;;
esac
exec /usr/bin/sha256sum "$@"
"#,
    );
    write_exec(
        &bin.join("chown"),
        r#"#!/bin/sh
if [ -n "${FAKE_CHOWN_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_CHOWN_LOG"; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("df"),
        "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/mock 99999999 0 99999999 0%% /\\n'\n",
    );
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo "${FAKE_ID_U:?}"; exit 0; fi
exec /usr/bin/id "$@"
"#,
    );
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    // Helper: run `libvirt-kvm-smoke.sh` under an explicit umask (e.g., 0077 or 0022).
    let run_with_umask = |mask: &str, args: &[&str], env: &[(&str, &str)]| -> Output {
        let mut cmd = Command::new("bash");
        cmd.args(["-c", r#"umask "$1"; shift; exec bash "$@""#, "_"]);
        cmd.arg(mask).arg(script()).args(args);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    // Helper: evaluate effective Linux directory traversal (standard POSIX mode + POSIX ACL
    // xattr `system.posix_acl_access`) for a given numeric account/group along every component
    // from `stop_ancestor` down to `leaf_dir`.
    let check_effective_traversal =
        |stop_ancestor: &Path, leaf_dir: &Path, acct: &str, grp: &str| -> bool {
            let out = Command::new("python3")
                .args([
                    "-I",
                    "-c",
                    r#"
import errno, os, stat, struct, sys

stop = os.path.normpath(sys.argv[1])
leaf = os.path.normpath(sys.argv[2])
target_u = int(sys.argv[3])
target_g = int(sys.argv[4])

def can_traverse(p):
    st = os.stat(p)
    if not stat.S_ISDIR(st.st_mode):
        return False
    if target_u == 0:
        return True
    try:
        raw = os.getxattr(p, b"system.posix_acl_access")
    except OSError:
        raw = None
    if raw and len(raw) >= 4:
        ver, = struct.unpack_from("<I", raw, 0)
        if ver == 2:
            mask = 0o7
            entries = []
            for off in range(4, len(raw), 8):
                if off + 8 <= len(raw):
                    tag, perm, eid = struct.unpack_from("<HHI", raw, off)
                    entries.append((tag, perm, eid))
                    if tag == 0x10:
                        mask = perm
            if target_u == st.st_uid:
                for tag, perm, _ in entries:
                    if tag == 0x01:
                        return bool(perm & 1)
            for tag, perm, eid in entries:
                if tag == 0x02 and eid == target_u:
                    return bool((perm & mask) & 1)
            matched_grp = False
            for tag, perm, eid in entries:
                if (tag == 0x04 and st.st_gid == target_g) or (tag == 0x08 and eid == target_g):
                    matched_grp = True
                    if (perm & mask) & 1:
                        return True
            if matched_grp:
                return False
            for tag, perm, _ in entries:
                if tag == 0x20:
                    return bool(perm & 1)
            return False
    if target_u == st.st_uid:
        return bool(st.st_mode & 0o100)
    if target_g == st.st_gid:
        return bool(st.st_mode & 0o010)
    return bool(st.st_mode & 0o001)

cur = leaf
chain = []
while True:
    chain.append(cur)
    if cur == stop or cur == "/":
        break
    cur = os.path.dirname(cur)
for p in reversed(chain):
    if not can_traverse(p):
        sys.stderr.write(f"blocked at {p} mode={oct(os.stat(p).st_mode & 0o777)}\n")
        sys.exit(1)
"#,
                    stop_ancestor.to_str().unwrap(),
                    leaf_dir.to_str().unwrap(),
                    acct,
                    grp,
                ])
                .output()
                .unwrap();
            out.status.success()
        };

    // 1. qemu:///session (under umask 0022): run dir stays 0700 and root.qcow2 is private 0600.
    {
        let images = dir.path().join("session-images");
        let out_dir = dir.path().join("out-session");
        let run_out = run_with_umask(
            "0022",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "77",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///session"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "1000"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CURL_OPEN_MODE", "1"),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-77-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        assert_eq!(
            std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "session mode run dir must remain 0700"
        );
        assert_eq!(
            std::fs::metadata(&disk).unwrap().permissions().mode() & 0o777,
            0o600,
            "session mode root.qcow2 must be private 0600"
        );
    }

    // 2. qemu:///system download path under restrictive umask 0077 with a NEW nested
    //    QEMINGA_E2E_IMAGES root:
    //    - Both new image root components AND run dir must grant effective traversal to QEMU
    //      without exposing world access (`mode & 0o007 == 0`).
    //    - Even if curl produces a 0644 file, `root.qcow2` MUST be private 0600 and chowned
    //      to the configured QEMU identity before boot.
    {
        let images = dir.path().join("sys-new-parent/nested-images");
        let out_dir = dir.path().join("out-sys-dl");
        let chown_log = dir.path().join("chown-dl.log");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "78",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CURL_OPEN_MODE", "1"),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-78-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        assert!(
            check_effective_traversal(dir.path(), &run_dir, qemu_acct_num, &caller_grp_num),
            "QEMU identity must have effective traversal across newly created image root and run dir under umask 0077: {}",
            text(&run_out)
        );
        let run_dir_mode = std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            run_dir_mode & 0o007,
            0,
            "system mode run dir must not grant world access (got {run_dir_mode:#o})"
        );
        let disk_mode = std::fs::metadata(&disk).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            disk_mode, 0o600,
            "system mode downloaded root.qcow2 must be private 0600, got {disk_mode:#o}"
        );
        let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            chowns.contains(&format!("{qemu_acct_num}:{caller_grp_num}"))
                && chowns.contains(disk.to_str().unwrap()),
            "system mode root.qcow2 must be chowned to configured QEMU identity before boot:\n{chowns}"
        );
    }

    // 3. qemu:///system cache-hit path under umask 0022 with a world-readable `0644` cache file:
    //    copied `root.qcow2` MUST STILL end up private `0600` owned by QEMU (never `0644`)!
    {
        let cache_dir = dir.path().join("img-cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        let cached = cache_dir.join(&pinned_image_sha);
        std::fs::write(&cached, b"cached qcow2 image\n").unwrap();
        std::fs::set_permissions(&cached, std::fs::Permissions::from_mode(0o644)).unwrap();

        let images = dir.path().join("sys-cache-images");
        let out_dir = dir.path().join("out-sys-cache");
        let chown_log = dir.path().join("chown-cache.log");
        let run_out = run_with_umask(
            "0022",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "79",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
                "--image-cache",
                cache_dir.to_str().unwrap(),
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-79-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        let disk_mode = std::fs::metadata(&disk).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            disk_mode, 0o600,
            "system mode cache-hit root.qcow2 copied from 0644 cache must be private 0600, got {disk_mode:#o}"
        );
        let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            chowns.contains(&format!("{qemu_acct_num}:{caller_grp_num}"))
                && chowns.contains(disk.to_str().unwrap()),
            "system mode cache-hit root.qcow2 must be chowned to configured QEMU identity:\n{chowns}"
        );
    }

    // 4. qemu:///system with an EXISTING untraversable ancestor (`0700`):
    //    `preflight` MUST report the blocking ancestor path, fail BEFORE downloading the image,
    //    and leave the ancestor's `0700` permissions untouched!
    {
        let blocked_ancestor = dir.path().join("blocked-0700-ancestor");
        std::fs::create_dir(&blocked_ancestor).unwrap();
        std::fs::set_permissions(&blocked_ancestor, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let images = blocked_ancestor.join("images");
        let out_dir = dir.path().join("out-sys-blocked");
        let curl_log = dir.path().join("curl-blocked.log");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "80",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CURL_LOG", curl_log.to_str().unwrap()),
            ],
        );
        let msg = text(&run_out);
        assert!(
            !run_out.status.success(),
            "system mode run with untraversable ancestor must fail closed: {msg}"
        );
        assert!(
            msg.contains(blocked_ancestor.to_str().unwrap()),
            "error must report the blocking ancestor path ({}):\n{msg}",
            blocked_ancestor.display()
        );
        assert!(
            !curl_log.exists() && !images.exists(),
            "must fail in preflight before creating images dir or downloading image:\n{msg}"
        );
        assert_eq!(
            std::fs::metadata(&blocked_ancestor)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "existing blocking ancestor permissions must remain untouched (0700)"
        );
    }

    // 5. qemu:///system identity resolution from `/etc/libvirt/qemu.conf` (via
    //    `QEMINGA_LIBVIRT_QEMU_CONF`, without `QEMINGA_E2E_QEMU_USER/GROUP` overrides):
    //    must parse active `user = ...` / `group = ...` entries (ignoring comments) and
    //    apply them to both traversal provisioning and private disk ownership.
    {
        let qemu_conf = dir.path().join("qemu.conf");
        std::fs::write(
            &qemu_conf,
            format!(
                "# user = \"nobody\"\nuser = \"{qemu_user_spec}\" # active user\ngroup = \"{qemu_group_spec}\"\n"
            ),
        )
        .unwrap();
        let images = dir.path().join("sys-conf-images");
        let out_dir = dir.path().join("out-sys-conf");
        let chown_log = dir.path().join("chown-conf.log");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "81",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_LIBVIRT_QEMU_CONF", qemu_conf.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-81-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        assert!(
            check_effective_traversal(dir.path(), &run_dir, qemu_acct_num, &caller_grp_num),
            "qemu.conf identity must have effective traversal across image root and run dir"
        );
        let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            chowns.contains(&format!("{qemu_acct_num}:{caller_grp_num}"))
                && chowns.contains(disk.to_str().unwrap()),
            "qemu.conf identity must be applied to root.qcow2 ownership:\n{chowns}"
        );
    }
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

    // Validate strict YAML syntax for both workflow files when Ruby Psych is installed.
    let has_ruby = Command::new("ruby")
        .args(["-ryaml", "-e", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if has_ruby {
        for rel in [
            ".github/workflows/libvirt-kvm.yml",
            ".github/workflows/libvirt-kvm-lane.yml",
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
