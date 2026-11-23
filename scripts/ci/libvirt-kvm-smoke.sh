#!/usr/bin/env bash
# libvirt + QEMU KVM smoke lane (#53, AC16) for self-hosted x86_64 and aarch64
# KVM runners (community-donated or maintainer-operated).
#
# Runs completely unprivileged by default against `qemu:///session` with
# user-mode networking (`<interface type='user'>` via libslirp), requiring zero
# root privileges, zero `sudo`, and zero access to host `qemu:///system` VMs.
# The candidate is always built on a GitHub-hosted runner (`cargo build
# --release --locked --features seccomp`); this lane never builds qeminga, it
# verifies the candidate against the build job's reported SHA-256, boots a
# disposable pinned Ubuntu 24.04 cloud image under real libvirt + KVM, proves
# KVM acceleration (refusing any TCG fallback), installs qeminga with the
# shipped packaging, runs scripts/e2e-libvirt.sh, and shuts the guest down
# through the agent.
#
#   libvirt-kvm-smoke.sh manifest --out DIR --binary PATH --arch ARCH
#       --source-sha SHA --version V --run-id N --run-attempt N --runner R
#   libvirt-kvm-smoke.sh verify-candidate DIR ARCH SHA     # prints the digest
#   libvirt-kvm-smoke.sh domain-xml --arch ARCH --name NAME --dir DIR
#       [--vcpus N]                                         # N above 8 -> 8
#   libvirt-kvm-smoke.sh stale-check
#   libvirt-kvm-smoke.sh image-key ARCH                     # cache key
#   libvirt-kvm-smoke.sh fetch-image --sha256 HEX --dest PATH [--cache DIR]
#       -- URL...                                           # first match wins
#   libvirt-kvm-smoke.sh run --arch ARCH --candidate DIR --source-sha SHA
#       --run-id N --run-attempt N --out DIR --expect-sha256 HEX
#       [--image-cache DIR]
#   libvirt-kvm-smoke.sh result --out DIR --arch ARCH --source-sha SHA
#       --binary-sha256 HEX --accelerator ACCEL
#   libvirt-kvm-smoke.sh cleanup --arch ARCH --run-id N --run-attempt N
#       [--out DIR]
#
# Environment overrides:
#   QEMINGA_E2E_CONNECT               qemu:///session (default) or qemu:///system
#   QEMINGA_E2E_IMAGES                run image root (default per connect URI)
#   QEMINGA_E2E_QEMU_USER             override system-mode QEMU user (or +UID)
#   QEMINGA_E2E_QEMU_GROUP            override system-mode QEMU group (or +GID)
#   QEMINGA_E2E_BOOT_TIMEOUT_SECS     default 300 (5 min under KVM)
#   QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS default 120 (2 min under KVM)
#
# tests/libvirt_kvm.rs covers the logic that runs without a hypervisor.
set -euo pipefail

export LC_ALL=C LANG=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

SUITE="libvirt-kvm-smoke-v1"
MANDATORY_TESTS="production_install accelerator_kvm libvirt_interop agent_shutdown"

die() { echo "libvirt-kvm-smoke: $*" >&2; exit 1; }
say() { echo "== $*"; }

# shellcheck source=scripts/ci/libvirt-smoke-common.sh
source "$HERE/libvirt-smoke-common.sh"

# ---- connection URI & paths -----------------------------------------------

CONNECT_URI="${QEMINGA_E2E_CONNECT:-qemu:///session}"
case "$CONNECT_URI" in
    qemu:///session | qemu:///system) ;;
    *) die "unsupported QEMINGA_E2E_CONNECT '$CONNECT_URI' (allowed: qemu:///session or qemu:///system)" ;;
esac
CONNECT="--connect=$CONNECT_URI"

if [ -n "${QEMINGA_E2E_IMAGES:-}" ]; then
    IMAGES="$QEMINGA_E2E_IMAGES"
elif [ "$CONNECT_URI" = "qemu:///session" ]; then
    IMAGES="${XDG_DATA_HOME:-${HOME:?HOME must be set}/.local/share}/qeminga-e2e/images"
else
    IMAGES="/var/lib/libvirt/images"
fi

qemu_log_of() {
    local name="$1"
    if [ "$CONNECT_URI" = "qemu:///session" ]; then
        echo "${XDG_CACHE_HOME:-${HOME:?HOME must be set}/.cache}/libvirt/qemu/log/${name}.log"
    else
        echo "/var/log/libvirt/qemu/${name}.log"
    fi
}

# Resolve AArch64 UEFI firmware (Debian/Ubuntu or Fedora/RHEL).
resolve_aavmf() {
    local pair code vars
    if [ -n "${QEMINGA_AAVMF_CODE:-}" ] && [ -n "${QEMINGA_AAVMF_VARS:-}" ]; then
        echo "${QEMINGA_AAVMF_CODE}:${QEMINGA_AAVMF_VARS}"
        return 0
    fi
    for pair in \
        "/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd:/usr/share/AAVMF/AAVMF_VARS.fd" \
        "/usr/share/AAVMF/AAVMF_CODE.fd:/usr/share/AAVMF/AAVMF_VARS.fd" \
        "/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw:/usr/share/edk2/aarch64/vars-template-pflash.raw" \
        "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw:/usr/share/edk2/aarch64/vars-template-pflash.raw"; do
        code="${pair%%:*}"
        vars="${pair#*:}"
        if [ -f "$code" ] && [ -f "$vars" ]; then
            echo "$pair"
            return 0
        fi
    done
    # Default path when rendering XML without firmware installed on the host.
    echo "/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd:/usr/share/AAVMF/AAVMF_VARS.fd"
}

# ---- domain ---------------------------------------------------------------

cmd_domain_xml() {
    parse_opts "$@"
    local arch name dir vcpus
    arch="$(need arch)"; name="$(need name)"; dir="$(need dir)"
    vcpus="${opt_vcpus:-2}"
    check_arch "$arch"; check_name "$name"
    check_path --dir "$dir"
    [ "$(basename "$dir")" = "$name" ] || die "the run directory must be named $name"
    [[ "$vcpus" =~ ^[1-9][0-9]{0,8}$ ]] || die "--vcpus must be a positive whole number: '$vcpus'"
    [ "$vcpus" -le 8 ] || vcpus=8

    local machine os features net
    machine="$(machine_of "$arch")"
    case "$arch" in
        x86_64)
            os="    <type arch='x86_64' machine='$machine'>hvm</type>"
            features="    <acpi/>
    <apic/>"
            ;;
        aarch64)
            local fw fw_code fw_vars
            fw="$(resolve_aavmf)"
            fw_code="${fw%%:*}"
            fw_vars="${fw#*:}"
            os="    <type arch='aarch64' machine='$machine'>hvm</type>
    <loader readonly='yes' type='pflash'>$fw_code</loader>
    <nvram template='$fw_vars'>$dir/VARS.fd</nvram>"
            # Match the physical arm64 server's GIC (v2 or v3) automatically.
            features="    <acpi/>
    <gic version='host'/>"
            ;;
    esac

    if [ "$CONNECT_URI" = "qemu:///session" ]; then
        net="    <interface type='user'>
      <model type='virtio'/>
      <rom enabled='no'/>
    </interface>"
    else
        net="    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
      <rom enabled='no'/>
    </interface>"
    fi

    cat <<EOF
<domain type='kvm'>
  <name>$name</name>
  <memory unit='MiB'>2048</memory>
  <vcpu>$vcpus</vcpu>
  <os>
$os
    <boot dev='hd'/>
  </os>
  <features>
$features
  </features>
  <cpu mode='host-passthrough' check='none'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$dir/root.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw'/>
      <source file='$dir/seed.iso'/>
      <target dev='vdb' bus='virtio'/>
      <readonly/>
    </disk>
    <disk type='file' device='disk'>
      <driver name='qemu' type='raw'/>
      <source file='$dir/payload.iso'/>
      <target dev='vdc' bus='virtio'/>
      <readonly/>
    </disk>
$net
    <channel type='unix'>
      <source mode='bind'/>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <serial type='file'>
      <source path='$dir/serial.log'/>
      <target port='0'/>
    </serial>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
    <memballoon model='none'/>
  </devices>
</domain>
EOF
}

# ---- libvirt state --------------------------------------------------------

v() { virsh "$CONNECT" "$@"; }

cmd_stale_check() {
    local names stale
    names="$(v list --all --name)" || die "cannot list libvirt domains on $CONNECT_URI; refusing to proceed on an unknown host state"
    stale="$(printf '%s\n' "$names" | grep -E '^qeminga-e2e-' || true)"
    if [ -n "$stale" ]; then
        echo "libvirt-kvm-smoke: stale qeminga test domain(s) on $CONNECT_URI:" >&2
        printf '  %s\n' "$stale" >&2
        echo "inspect them with 'virsh $CONNECT dominfo NAME', then remove each with" >&2
        echo "'$0 cleanup --arch ARCH --run-id N --run-attempt N' for its run" >&2
        exit 1
    fi
}

domain_state() {
    local name="$1" out
    if out="$(v domstate "$name" 2>&1)"; then
        printf '%s\n' "$out" | head -n 1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        return 0
    fi
    case "$out" in
        *"failed to get domain"* | *"Domain not found"*)
            local names
            names="$(v list --all --name)" || return 1
            if printf '%s\n' "$names" | grep -qx -- "$name"; then return 1; fi
            echo absent
            ;;
        *) echo "$out" >&2; return 1 ;;
    esac
}

collect_diagnostics() {
    local name="$1" dir="$2" out="$3" qlog
    mkdir -p "$out"
    v dumpxml "$name" >"$out/domain.xml" 2>/dev/null || true
    qlog="$(qemu_log_of "$name")"
    if [ -f "$qlog" ]; then cp "$qlog" "$out/qemu.log" || true; fi
    if [ -f "$dir/serial.log" ]; then cp "$dir/serial.log" "$out/serial.log" || true; fi
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        chmod -R a+rX "$out" 2>/dev/null || true
    fi
}

cmd_cleanup() {
    parse_opts "$@"
    local arch run_id attempt out
    arch="$(need arch)"; run_id="$(need run_id)"; attempt="$(need run_attempt)"
    out="${opt_out:-}"
    check_arch "$arch"
    check_number --run-id "$run_id"; check_number --run-attempt "$attempt"
    local name dir state
    name="$(domain_name "$run_id" "$attempt" "$arch")"
    check_name "$name"
    check_path QEMINGA_E2E_IMAGES "$IMAGES"
    dir="$IMAGES/$name"
    if ! command -v virsh >/dev/null 2>&1; then
        [ ! -e "$dir" ] || die "virsh is not installed, so the state of $name cannot be established; keeping $dir"
        local note="nothing to clean up: libvirt is not installed and $dir does not exist"
        echo "$note"
        if [ -n "$out" ]; then
            mkdir -p "$out" && echo "$note" >"$out/cleanup.txt"
        fi
        return 0
    fi
    [ -n "$out" ] && collect_diagnostics "$name" "$dir" "$out"

    state="$(domain_state "$name")" \
        || die "the state of $name cannot be established; keeping $dir"
    if [ "$state" != absent ]; then
        if [ "$state" != "shut off" ]; then
            v destroy "$name" || true
            state="$(domain_state "$name")" || die "cannot establish $name's state after destroy; keeping $dir"
            [ "$state" = "shut off" ] || die "$name is still '$state'; keeping $dir"
        fi
        v undefine --nvram "$name" || v undefine "$name" || die "cannot undefine $name; keeping $dir"
        state="$(domain_state "$name")" || die "cannot confirm $name is gone; keeping $dir"
        [ "$state" = absent ] || die "$name is still defined; keeping $dir"
    fi
    if [ -d "$dir" ]; then
        rm -rf --one-file-system -- "$dir"
        echo "removed $dir"
    fi
    echo "cleanup of $name done"
}

# ---- result ---------------------------------------------------------------

write_result() {
    local out="$1" arch="$2" sha="$3" digest="$4" accel="$5"
    local tests='{}' overall=pass t status
    for t in $MANDATORY_TESTS; do
        if [ -f "$out/tests/$t" ]; then
            case "$(tr -d '[:space:]' <"$out/tests/$t")" in
                pass) status=pass ;;
                *) status=fail ;;
            esac
        else
            status=not_run
        fi
        [ "$status" = pass ] || overall=fail
        tests="$(jq -c --arg t "$t" --arg s "$status" '. + {($t): $s}' <<<"$tests")"
    done
    [ "$accel" = kvm ] || overall=fail
    jq -n \
        --arg suite "$SUITE" --arg repo "$SOURCE_REPOSITORY" --arg sha "$sha" \
        --arg arch "$arch" --arg digest "$digest" --arg accel "$accel" \
        --arg machine "$(machine_of "$arch")" \
        --arg image "$(image_file_of "$arch")" --arg image_release "$IMAGE_RELEASE" \
        --arg image_sha "$(image_sha_of "$arch")" \
        --argjson tests "$tests" --arg result "$overall" \
        '{schema: 1, suite: $suite, source_repository: $repo, source_sha: $sha,
          architecture: $arch, candidate_binary_sha256: $digest,
          virtualization: {hypervisor: "qemu", accelerator: $accel, machine: $machine},
          guest: {image: $image, image_release: $image_release, image_sha256: $image_sha},
          tests: $tests, result: $result}' >"$out/result.json"
    cat "$out/result.json"
    [ "$overall" = pass ]
}

cmd_result() {
    parse_opts "$@"
    local out arch sha digest accel
    out="$(need out)"; arch="$(need arch)"; sha="$(need source_sha)"
    digest="$(need binary_sha256)"; accel="$(need accelerator)"
    check_arch "$arch"; check_sha "$sha"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "bad digest '$digest'"
    write_result "$out" "$arch" "$sha" "$digest" "$accel"
}

# ---- the lane -------------------------------------------------------------

mark() { mkdir -p "$OUT/tests"; echo "$2" >"$OUT/tests/$1"; echo "-- $1: $2"; }

QEMU_UID=0
QEMU_GID=0
QEMU_GROUPS="0"

# Resolve the user/group DAC identity that the connected system libvirt daemon
# uses for KVM guests:
#   1. Explicit overrides (`QEMINGA_E2E_QEMU_USER` / `QEMINGA_E2E_QEMU_GROUP`)
#   2. Connected daemon's `dac` KVM `<baselabel>` from `virsh capabilities`
#      (falling back to `qemu` or untyped `dac` baselabel)
#   3. Active `user`/`group` entries in `QEMINGA_LIBVIRT_QEMU_CONF`
#      (`/etc/libvirt/qemu.conf`)
#   4. Standard distro accounts (`libvirt-qemu`, `qemu`, `root`)
# Follows libvirt's numeric-ID rules: `+NNN` is always numeric; an unprefixed
# decimal integer falls back to a numeric UID/GID when NSS name lookup fails.
resolve_system_qemu_identity() {
    local conf="${QEMINGA_LIBVIRT_QEMU_CONF:-/etc/libvirt/qemu.conf}"
    local override_user="${QEMINGA_E2E_QEMU_USER:-}"
    local override_group="${QEMINGA_E2E_QEMU_GROUP:-}"
    local caps_xml=""
    if [ -z "$override_user" ] || [ -z "$override_group" ]; then
        caps_xml="$(v capabilities 2>/dev/null || true)"
    fi
    local resolved=""
    if ! resolved="$(python3 -I - "$conf" "$override_user" "$override_group" 3<<<"$caps_xml" <<'PY'
import grp, os, pwd, re, sys, xml.etree.ElementTree as ET

conf_path, user, group = sys.argv[1], sys.argv[2], sys.argv[3]
with os.fdopen(3, "r", encoding="utf-8", errors="replace") as caps_fh:
    caps_xml = caps_fh.read()

def parse_dac_baselabel(xml_text):
    if not xml_text or "<" not in xml_text:
        return "", ""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "", ""
    for secmodel in root.findall(".//secmodel"):
        model_el = secmodel.find("model")
        if model_el is None or (model_el.text or "").strip() != "dac":
            continue
        labels = {}
        for bl in secmodel.findall("baselabel"):
            txt = (bl.text or "").strip()
            if ":" not in txt:
                continue
            btype = bl.attrib.get("type", "")
            labels[btype] = txt
        chosen = labels.get("kvm") or labels.get("qemu") or labels.get("") or ""
        if ":" in chosen:
            u, g = chosen.split(":", 1)
            return u.strip(), g.strip()
    return "", ""

if not user or not group:
    cap_u, cap_g = parse_dac_baselabel(caps_xml)
    if not user and cap_u:
        user = cap_u
    if not group and cap_g:
        group = cap_g

if (not user or not group) and conf_path and os.path.isfile(conf_path) and os.access(conf_path, os.R_OK):
    conf_u = conf_g = ""
    with open(conf_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r'^(user|group)\s*=\s*(["\'])(.*?)\2\s*$', line)
            if m:
                if m.group(1) == "user":
                    conf_u = m.group(3).strip()
                else:
                    conf_g = m.group(3).strip()
    if not user and conf_u:
        user = conf_u
    if not group and conf_g:
        group = conf_g

if not user:
    for candidate in ("libvirt-qemu", "qemu"):
        try:
            pwd.getpwnam(candidate)
            user = candidate
            break
        except KeyError:
            pass
    if not user:
        user = "root"

pw = None
if re.fullmatch(r"\+[0-9]+", user):
    uid = int(user[1:])
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        pw = None
else:
    try:
        pw = pwd.getpwnam(user)
        uid = pw.pw_uid
    except KeyError:
        if re.fullmatch(r"[0-9]+", user):
            uid = int(user)
            try:
                pw = pwd.getpwuid(uid)
            except KeyError:
                pw = None
        else:
            sys.stderr.write(f"libvirt-kvm-smoke: cannot resolve system libvirt QEMU user '{user}'\n")
            sys.exit(1)

if group:
    if re.fullmatch(r"\+[0-9]+", group):
        gid = int(group[1:])
    else:
        try:
            gid = grp.getgrnam(group).gr_gid
        except KeyError:
            if re.fullmatch(r"[0-9]+", group):
                gid = int(group)
            else:
                sys.stderr.write(f"libvirt-kvm-smoke: cannot resolve system libvirt QEMU group '{group}'\n")
                sys.exit(1)
elif pw is not None:
    gid = pw.pw_gid
else:
    gid = uid

groups = {gid}
if pw is not None:
    groups.add(pw.pw_gid)
    try:
        groups.update(os.getgrouplist(pw.pw_name, gid))
    except OSError:
        pass

print(f"{uid}\t{gid}\t{','.join(str(g) for g in sorted(groups))}")
PY
    )"; then
        exit 1
    fi
    IFS=$'\t' read -r QEMU_UID QEMU_GID QEMU_GROUPS <<<"$resolved"
}

# FD-anchored filesystem operations for the root-run `qemu:///system` lane:
# - Validates every existing ancestor (including intermediate directories visited
#   through symlink hops) for trusted ownership, protection against replacement
#   by non-trusted accounts, and QEMU traversal (plus a real Linux kernel child
#   verdict when running as real root).
# - Prepares newly created image-root and per-run directories privately via
#   `.qeminga-e2e-init.<hex>`, clears inherited default ACLs, replaces the full
#   access ACL with owner rwx + QEMU --x + mask --x (falling back to group-only
#   `0710` on no-ACL filesystems — never `0711`), and publishes atomically via
#   `renameat2(RENAME_NOREPLACE)` so a failed grant never leaves a blocking
#   `0700` public directory behind.
# - Performs guest file `fchmod 0600`, extended-ACL stripping, and `fchown`
#   directly on verified open `O_NOFOLLOW` regular-file descriptors.
sys_fs_ops() {
    python3 -I - "$@" <<'PY'
from collections import deque
import ctypes
import errno
import os
import stat
import struct
import sys

READ_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
RENAME_NOREPLACE = 1
SYMLOOP_MAX = 40

_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _RENAMEAT2.restype = ctypes.c_int


def renameat2_noreplace(src_dir_fd, src_name, dst_dir_fd, dst_name):
    if _RENAMEAT2 is not None:
        rc = _RENAMEAT2(
            src_dir_fd,
            os.fsencode(src_name),
            dst_dir_fd,
            os.fsencode(dst_name),
            RENAME_NOREPLACE,
        )
        if rc == 0:
            return
        err = ctypes.get_errno()
        if err not in (errno.ENOSYS, errno.EINVAL):
            raise OSError(err, os.strerror(err), dst_name)
    try:
        os.lstat(dst_name, dir_fd=dst_dir_fd)
    except FileNotFoundError:
        os.rename(src_name, dst_name, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
        return
    raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst_name)


def encode_acl(entries):
    return struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, perm, eid) for tag, perm, eid in entries
    )


def decode_acl_fd(fd, attr=b"system.posix_acl_access"):
    try:
        raw = os.getxattr(fd, attr)
    except OSError as exc:
        if exc.errno in (errno.ENODATA, errno.EOPNOTSUPP, errno.ENOSYS):
            return None
        raise
    if not raw or len(raw) < 4:
        return None
    (ver,) = struct.unpack_from("<I", raw, 0)
    if ver != 2:
        return None
    entries = []
    for off in range(4, len(raw), 8):
        if off + 8 <= len(raw):
            entries.append(struct.unpack_from("<HHI", raw, off))
    return entries


def remove_xattr_if_present(fd, attr):
    try:
        os.removexattr(fd, attr)
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.EOPNOTSUPP, errno.ENOSYS):
            raise


def effective_perms_fd(fd, st, uid, groups):
    if uid == 0:
        return 7
    entries = decode_acl_fd(fd, b"system.posix_acl_access")
    if entries:
        mask = 7
        for tag, perm, _ in entries:
            if tag == 0x10:
                mask = perm
        if uid == st.st_uid:
            for tag, perm, _ in entries:
                if tag == 0x01:
                    return perm
            return 0
        for tag, perm, eid in entries:
            if tag == 0x02 and eid == uid:
                return perm & mask
        matched = [
            perm & mask
            for tag, perm, eid in entries
            if (tag == 0x04 and st.st_gid in groups) or (tag == 0x08 and eid in groups)
        ]
        if matched:
            val = 0
            for m in matched:
                val |= m
            return val
        for tag, perm, _ in entries:
            if tag == 0x20:
                return perm
        return 0
    if uid == st.st_uid:
        return (st.st_mode >> 6) & 7
    if st.st_gid in groups:
        return (st.st_mode >> 3) & 7
    return st.st_mode & 7


def can_traverse_fd(fd, st, uid, groups):
    return stat.S_ISDIR(st.st_mode) and bool(effective_perms_fd(fd, st, uid, groups) & 1)


def trusted_owner_uids():
    euid = os.geteuid()
    return {0} if euid == 0 else {0, euid}


def dir_trust_info(fd, st, trusted_uids):
    if st.st_uid not in trusted_uids:
        return False, True, f"owned by untrusted uid {st.st_uid}"
    entries = decode_acl_fd(fd, b"system.posix_acl_access")
    if entries:
        mask = 7
        for tag, perm, _ in entries:
            if tag == 0x10:
                mask = perm
        for tag, perm, eid in entries:
            if tag == 0x20 and (perm & 2):
                return True, True, "world-writable via POSIX ACL"
            if tag == 0x02 and eid not in trusted_uids and ((perm & mask) & 2):
                return True, True, f"writable by named uid {eid} via POSIX ACL"
            if tag == 0x04 and ((perm & mask) & 2):
                return True, True, f"group-writable (gid {st.st_gid}) via POSIX ACL"
            if tag == 0x08 and ((perm & mask) & 2):
                return True, True, f"writable by named gid {eid} via POSIX ACL"
        return True, False, ""
    if st.st_mode & 0o002:
        return True, True, f"world-writable (mode {oct(st.st_mode & 0o7777)})"
    if st.st_mode & 0o020:
        return True, True, f"group-writable (mode {oct(st.st_mode & 0o7777)})"
    return True, False, ""


def kernel_verdict_traversal(original_path, qemu_uid, qemu_gid, qemu_groups):
    if os.geteuid() != 0 or qemu_uid == 0:
        return
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        code = 0
        msg = b""
        try:
            os.setgroups(sorted(qemu_groups))
            os.setgid(qemu_gid)
            os.setuid(qemu_uid)
            st = os.stat(original_path)
            if not stat.S_ISDIR(st.st_mode):
                raise OSError(errno.ENOTDIR, f"'{original_path}' is not a directory")
            if not os.access(original_path, os.X_OK):
                raise OSError(errno.EACCES, f"kernel denied X_OK on '{original_path}'")
        except OSError as exc:
            code = 1
            msg = f"{exc.strerror or exc} (errno {exc.errno})".encode("utf-8", errors="replace")
        except Exception as exc:
            code = 1
            msg = str(exc).encode("utf-8", errors="replace")
        try:
            if msg:
                os.write(w_fd, msg)
        finally:
            os.close(w_fd)
            os._exit(code)
    os.close(w_fd)
    chunks = []
    try:
        while True:
            chunk = os.read(r_fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(r_fd)
    _, status = os.waitpid(pid, 0)
    if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
        detail = b"".join(chunks).decode("utf-8", errors="replace").strip() or f"status={status}"
        raise OSError(
            errno.EACCES,
            f"kernel denied traversal of '{original_path}' for uid {qemu_uid}: {detail}",
        )


def verify_dir_fd(dfd, path_label, qemu_uid, qemu_groups, trusted_uids, allow_sticky_writable=True):
    st = os.fstat(dfd)
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.ENOTDIR, f"image root component '{path_label}' is not a directory")
    trusted_owner, is_writable, reason = dir_trust_info(dfd, st, trusted_uids)
    if not trusted_owner:
        raise OSError(
            errno.EACCES,
            f"refusing untrusted ancestor directory '{path_label}' ({reason}); choose a root-owned non-shared QEMINGA_E2E_IMAGES path",
        )
    if is_writable:
        if not (allow_sticky_writable and bool(st.st_mode & stat.S_ISVTX)):
            raise OSError(
                errno.EACCES,
                f"refusing shared writable ancestor directory '{path_label}' ({reason}); choose a root-owned non-shared QEMINGA_E2E_IMAGES path",
            )
    if not can_traverse_fd(dfd, st, qemu_uid, qemu_groups):
        raise OSError(
            errno.EACCES,
            f"QEMU uid {qemu_uid} cannot traverse existing ancestor directory '{path_label}'; adjust its permissions or ACLs or choose a traversable QEMINGA_E2E_IMAGES path",
        )
    return st, is_writable, reason


def walk_existing_prefix(target, qemu_uid, qemu_groups, trusted_uids):
    # Walk `target` component by component resolving every symlink hop
    # explicitly so intermediate directories visited between symlinks are
    # checked for BOTH control/trust and QEMU traversal.
    norm = os.path.normpath(target)
    if not norm.startswith("/"):
        raise OSError(errno.EINVAL, f"path must be absolute: '{target}'")
    parts = [p for p in norm.split("/") if p]
    pending = deque(
        (part, "/" + "/".join(parts[: idx + 1]), False) for idx, part in enumerate(parts)
    )
    cur_fd = os.open("/", READ_DIR_FLAGS)
    try:
        cur_path = "/"
        cur_st, cur_writable, cur_reason = verify_dir_fd(
            cur_fd, cur_path, qemu_uid, qemu_groups, trusted_uids, allow_sticky_writable=True
        )
        deepest_lexical = "/"
        remaining = []
        symlinks = 0
        while pending:
            comp, orig_prefix, from_symlink = pending.popleft()
            if comp == ".":
                if orig_prefix is not None:
                    deepest_lexical = orig_prefix
                continue
            if comp == "..":
                next_fd = os.open("..", READ_DIR_FLAGS, dir_fd=cur_fd)
                next_path = os.path.dirname(cur_path) or "/"
                try:
                    nst, nwritable, nreason = verify_dir_fd(
                        next_fd, next_path, qemu_uid, qemu_groups, trusted_uids, allow_sticky_writable=True
                    )
                except Exception:
                    os.close(next_fd)
                    raise
                os.close(cur_fd)
                cur_fd, cur_path, cur_st, cur_writable, cur_reason = (
                    next_fd, next_path, nst, nwritable, nreason
                )
                if orig_prefix is not None:
                    deepest_lexical = orig_prefix
                continue
            try:
                lst = os.lstat(comp, dir_fd=cur_fd)
            except FileNotFoundError:
                if from_symlink:
                    raise OSError(errno.ENOENT, f"dangling symlink encountered while resolving '{target}' at '{os.path.join(cur_path, comp)}'")
                remaining = [comp] + [p[0] for p in pending]
                break
            if stat.S_ISLNK(lst.st_mode):
                symlinks += 1
                if symlinks > SYMLOOP_MAX:
                    raise OSError(errno.ELOOP, f"too many symbolic links resolving '{target}'")
                if lst.st_uid not in trusted_uids:
                    raise OSError(
                        errno.EACCES,
                        f"refusing untrusted symlink '{os.path.join(cur_path, comp)}' owned by uid {lst.st_uid}",
                    )
                link_target = os.readlink(comp, dir_fd=cur_fd)
                if not link_target:
                    raise OSError(errno.ENOENT, f"empty symlink at '{os.path.join(cur_path, comp)}'")
                link_parts = [p for p in link_target.split("/") if p]
                if link_target.startswith("/"):
                    root_fd = os.open("/", READ_DIR_FLAGS)
                    try:
                        rst, rwritable, rreason = verify_dir_fd(
                            root_fd, "/", qemu_uid, qemu_groups, trusted_uids, allow_sticky_writable=True
                        )
                    except Exception:
                        os.close(root_fd)
                        raise
                    os.close(cur_fd)
                    cur_fd, cur_path, cur_st, cur_writable, cur_reason = (
                        root_fd, "/", rst, rwritable, rreason
                    )
                if not link_parts:
                    if orig_prefix is not None:
                        deepest_lexical = orig_prefix
                    continue
                for idx in range(len(link_parts) - 1, -1, -1):
                    attach = orig_prefix if idx == len(link_parts) - 1 else None
                    pending.appendleft((link_parts[idx], attach, True))
                continue
            next_path = os.path.join(cur_path, comp)
            if not stat.S_ISDIR(lst.st_mode):
                raise OSError(errno.ENOTDIR, f"image root component '{next_path}' is not a directory")
            next_fd = os.open(comp, READ_DIR_FLAGS, dir_fd=cur_fd)
            try:
                nst = os.fstat(next_fd)
                if nst.st_dev != lst.st_dev or nst.st_ino != lst.st_ino:
                    raise OSError(errno.EXDEV, f"directory '{next_path}' changed during verification")
                nst, nwritable, nreason = verify_dir_fd(
                    next_fd, next_path, qemu_uid, qemu_groups, trusted_uids, allow_sticky_writable=True
                )
            except Exception:
                os.close(next_fd)
                raise
            os.close(cur_fd)
            cur_fd, cur_path, cur_st, cur_writable, cur_reason = (
                next_fd, next_path, nst, nwritable, nreason
            )
            if orig_prefix is not None:
                deepest_lexical = orig_prefix

        # The deepest existing directory will host newly created components or
        # the per-run directory, so it MUST NOT be writable by other accounts
        # even when the sticky bit is set.
        if cur_writable:
            raise OSError(
                errno.EACCES,
                f"refusing shared writable directory '{cur_path}' ({cur_reason}); choose a root-owned non-shared QEMINGA_E2E_IMAGES path",
            )
        return cur_fd, cur_path, deepest_lexical, remaining
    except Exception:
        os.close(cur_fd)
        raise


def provision_private_dir_fd(tfd, qemu_uid, qemu_gid, qemu_groups):
    if os.geteuid() == 0:
        os.fchown(tfd, 0, 0)
    os.fchmod(tfd, 0o700)
    # Always strip any inherited default ACL BEFORE creating children or
    # adjusting access permissions so unrelated accounts never inherit access.
    remove_xattr_if_present(tfd, b"system.posix_acl_default")
    if qemu_uid == 0:
        remove_xattr_if_present(tfd, b"system.posix_acl_access")
        os.fchmod(tfd, 0o700)
        return

    disable_acl = os.environ.get("QEMINGA_TEST_DISABLE_ACL") == "1"
    acl_applied = False
    if not disable_acl:
        # Complete replacement access ACL:
        #   user::rwx, user:<qemu_uid>:--x, group::---, mask::--x, other::---
        # Replacing the full ACL drops any inherited named user/group entries
        # and pins the mask strictly to search (--x).
        acl_bytes = encode_acl(
            [
                (0x01, 0o7, 0xFFFFFFFF),
                (0x02, 0o1, qemu_uid),
                (0x04, 0o0, 0xFFFFFFFF),
                (0x10, 0o1, 0xFFFFFFFF),
                (0x20, 0o0, 0xFFFFFFFF),
            ]
        )
        try:
            os.setxattr(tfd, b"system.posix_acl_access", acl_bytes)
            acl_applied = True
        except OSError as exc:
            if exc.errno not in (errno.EOPNOTSUPP, errno.ENOSYS):
                raise

    if acl_applied:
        if decode_acl_fd(tfd, b"system.posix_acl_default") is not None:
            raise OSError(errno.EIO, "inherited default ACL remained after removal")
        entries = decode_acl_fd(tfd, b"system.posix_acl_access") or []
        expected = {
            (0x01, 0o7, 0xFFFFFFFF),
            (0x02, 0o1, qemu_uid),
            (0x04, 0o0, 0xFFFFFFFF),
            (0x10, 0o1, 0xFFFFFFFF),
            (0x20, 0o0, 0xFFFFFFFF),
        }
        if set(entries) != expected:
            raise OSError(errno.EIO, f"unexpected POSIX access ACL after replacement: {entries}")
    else:
        # No-ACL fallback: ALWAYS group-only search (`0710`, owning group
        # `qemu_gid` even when `qemu_gid == 0`), NEVER world-searchable `0711`.
        remove_xattr_if_present(tfd, b"system.posix_acl_access")
        owner_uid = 0 if os.geteuid() == 0 else -1
        os.fchown(tfd, owner_uid, qemu_gid)
        os.fchmod(tfd, 0o710)
        st = os.fstat(tfd)
        if st.st_gid != qemu_gid or (st.st_mode & 0o7777) != 0o710:
            raise OSError(errno.EIO, f"failed to apply 0710 group {qemu_gid} fallback")

    st = os.fstat(tfd)
    if not can_traverse_fd(tfd, st, qemu_uid, qemu_groups):
        raise OSError(errno.EACCES, f"QEMU uid {qemu_uid} still cannot traverse newly provisioned directory")


def create_component_in_fd(parent_fd, parent_path, comp, qemu_uid, qemu_gid, qemu_groups, fail_if_exists=False):
    tmp_name = f".qeminga-e2e-init.{os.urandom(8).hex()}"
    os.mkdir(tmp_name, 0o700, dir_fd=parent_fd)
    published = False
    tfd = None
    try:
        tfd = os.open(tmp_name, READ_DIR_FLAGS, dir_fd=parent_fd)
        provision_private_dir_fd(tfd, qemu_uid, qemu_gid, qemu_groups)
        os.fsync(tfd)
        try:
            renameat2_noreplace(parent_fd, tmp_name, parent_fd, comp)
        except FileExistsError:
            if fail_if_exists:
                raise OSError(errno.EEXIST, f"{os.path.join(parent_path, comp)} already exists; refusing to reuse another run's files")
            os.close(tfd)
            tfd = None
            os.rmdir(tmp_name, dir_fd=parent_fd)
            return None
        published = True
        os.fsync(parent_fd)
        ret_fd = tfd
        tfd = None
        return ret_fd
    finally:
        if tfd is not None:
            os.close(tfd)
        if not published:
            try:
                os.rmdir(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass


op = sys.argv[1]
try:
    if op == "prepare-images-root":
        target = sys.argv[2]
        qemu_uid = int(sys.argv[3])
        qemu_gid = int(sys.argv[4])
        qemu_groups = {int(x) for x in sys.argv[5].split(",") if x}
        trusted_uids = trusted_owner_uids()
        cur_fd, cur_path, deepest_lexical, remaining = walk_existing_prefix(
            target, qemu_uid, qemu_groups, trusted_uids
        )
        try:
            kernel_verdict_traversal(deepest_lexical, qemu_uid, qemu_gid, qemu_groups)
            for comp in remaining:
                next_fd = create_component_in_fd(
                    cur_fd, cur_path, comp, qemu_uid, qemu_gid, qemu_groups, fail_if_exists=False
                )
                next_path = os.path.join(cur_path, comp)
                if next_fd is None:
                    next_fd = os.open(comp, READ_DIR_FLAGS, dir_fd=cur_fd)
                    try:
                        verify_dir_fd(
                            next_fd, next_path, qemu_uid, qemu_groups, trusted_uids, allow_sticky_writable=False
                        )
                    except Exception:
                        os.close(next_fd)
                        raise
                os.close(cur_fd)
                cur_fd, cur_path = next_fd, next_path
        finally:
            os.close(cur_fd)
        kernel_verdict_traversal(os.path.normpath(target), qemu_uid, qemu_gid, qemu_groups)
    elif op == "create-run-dir":
        images_dir = sys.argv[2]
        run_name = sys.argv[3]
        qemu_uid = int(sys.argv[4])
        qemu_gid = int(sys.argv[5])
        qemu_groups = {int(x) for x in sys.argv[6].split(",") if x}
        if "/" in run_name or run_name in ("", ".", ".."):
            raise OSError(errno.EINVAL, f"invalid run dir name '{run_name}'")
        trusted_uids = trusted_owner_uids()
        img_fd, img_path, deepest_lexical, remaining = walk_existing_prefix(
            images_dir, qemu_uid, qemu_groups, trusted_uids
        )
        try:
            if remaining:
                raise OSError(errno.ENOENT, f"images root '{images_dir}' does not exist")
            kernel_verdict_traversal(deepest_lexical, qemu_uid, qemu_gid, qemu_groups)
            rfd = create_component_in_fd(
                img_fd, img_path, run_name, qemu_uid, qemu_gid, qemu_groups, fail_if_exists=True
            )
            os.close(rfd)
        finally:
            os.close(img_fd)
        kernel_verdict_traversal(os.path.join(os.path.normpath(images_dir), run_name), qemu_uid, qemu_gid, qemu_groups)
    elif op == "handoff-file":
        images_dir = sys.argv[2]
        run_name = sys.argv[3]
        filename = sys.argv[4]
        qemu_uid = int(sys.argv[5])
        qemu_gid = int(sys.argv[6])
        qemu_groups = {int(x) for x in sys.argv[7].split(",") if x}
        do_chown = sys.argv[8] == "1"
        if "/" in run_name or "/" in filename or run_name in ("", ".", "..") or filename in ("", ".", ".."):
            raise OSError(errno.EINVAL, f"invalid run/file name: '{run_name}' / '{filename}'")
        trusted_uids = trusted_owner_uids()
        img_fd, img_path, _, remaining = walk_existing_prefix(
            images_dir, qemu_uid, qemu_groups, trusted_uids
        )
        try:
            if remaining:
                raise OSError(errno.ENOENT, f"images root '{images_dir}' does not exist")
            rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
            try:
                verify_dir_fd(
                    rfd, os.path.join(img_path, run_name), qemu_uid, qemu_groups, trusted_uids, allow_sticky_writable=False
                )
                ffd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=rfd)
                try:
                    fst = os.fstat(ffd)
                    if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                        raise OSError(errno.EINVAL, f"refusing unsafe guest file '{filename}' (must be regular file with nlink == 1)")
                    remove_xattr_if_present(ffd, b"system.posix_acl_access")
                    os.fchmod(ffd, 0o600)
                    if do_chown and qemu_uid != 0:
                        if os.geteuid() == 0:
                            os.fchown(ffd, qemu_uid, qemu_gid)
                        else:
                            print("DELEGATE_CHOWN")
                    fst_after = os.fstat(ffd)
                    if (fst_after.st_mode & 0o777) != 0o600:
                        raise OSError(errno.EIO, f"guest file '{filename}' did not reach mode 0600")
                finally:
                    os.close(ffd)
            finally:
                os.close(rfd)
        finally:
            os.close(img_fd)
    elif op == "strip-session-dir-acl":
        target = sys.argv[2]
        dfd = os.open(target, READ_DIR_FLAGS)
        try:
            remove_xattr_if_present(dfd, b"system.posix_acl_default")
            remove_xattr_if_present(dfd, b"system.posix_acl_access")
            os.fchmod(dfd, 0o700)
        finally:
            os.close(dfd)
    else:
        raise OSError(errno.EINVAL, f"unknown sys_fs_ops op '{op}'")
except OSError as exc:
    msg = exc.strerror if exc.strerror else str(exc)
    sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
    sys.exit(1)
PY
}

prepare_system_images_root() {
    local target="$1"
    resolve_system_qemu_identity
    sys_fs_ops prepare-images-root "$target" "$QEMU_UID" "$QEMU_GID" "$QEMU_GROUPS" \
        || exit 1
}

create_system_run_dir() {
    local images_dir="$1" run_name="$2"
    sys_fs_ops create-run-dir "$images_dir" "$run_name" "$QEMU_UID" "$QEMU_GID" "$QEMU_GROUPS" \
        || exit 1
}

handoff_system_guest_file() {
    local images_dir="$1" run_name="$2" filename="$3" do_chown="$4"
    local action=""
    if ! action="$(sys_fs_ops handoff-file "$images_dir" "$run_name" "$filename" "$QEMU_UID" "$QEMU_GID" "$QEMU_GROUPS" "$do_chown")"; then
        exit 1
    fi
    if [ "$action" = "DELEGATE_CHOWN" ] && [ "$do_chown" = "1" ] && [ "${QEMU_UID:-0}" -ne 0 ]; then
        chown -h "${QEMU_UID}:${QEMU_GID}" "${images_dir}/${run_name}/${filename}"
    fi
}

create_session_run_dir() {
    local dir="$1"
    [ ! -e "$dir" ] && [ ! -L "$dir" ] || die "$dir already exists; refusing to reuse another run's files"
    mkdir -m 0700 "$dir"
    if command -v python3 >/dev/null 2>&1; then
        sys_fs_ops strip-session-dir-acl "$dir" || exit 1
    fi
}

preflight() {
    local arch="$1"
    say "preflight ($arch, KVM on $CONNECT_URI)"
    [ "$(uname -m)" = "$arch" ] || die "this host is $(uname -m), not $arch"
    if [ "$CONNECT_URI" = "qemu:///session" ]; then
        [ "$(id -u)" -ne 0 ] || die "refusing to run qemu:///session as root; run as the unprivileged runner user"
    else
        [ "$(id -u)" -eq 0 ] || die "qemu:///system requires root"
    fi
    local kvm_dev="${QEMINGA_KVM_DEVICE:-/dev/kvm}"
    { [ -c "$kvm_dev" ] && [ -r "$kvm_dev" ] && [ -w "$kvm_dev" ]; } \
        || die "KVM device $kvm_dev is missing or not readable/writable by uid $(id -u)"

    local tool
    for tool in virsh qemu-img genisoimage jq curl sha256sum "qemu-system-$arch"; do
        command -v "$tool" >/dev/null || die "missing tool: $tool"
    done
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        command -v python3 >/dev/null || die "missing tool: python3"
    fi
    if [ "$arch" = aarch64 ]; then
        local fw fw_code fw_vars
        fw="$(resolve_aavmf)"
        fw_code="${fw%%:*}"
        fw_vars="${fw#*:}"
        { [ -f "$fw_code" ] && [ -f "$fw_vars" ]; } || die "missing AArch64 UEFI firmware (qemu-efi-aarch64 or edk2-aarch64)"
    fi
    v version
    v domcapabilities --virttype kvm --arch "$arch" --machine "$(machine_of "$arch")" >/dev/null \
        || die "libvirt cannot run a KVM $arch $(machine_of "$arch") guest on $CONNECT_URI"
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        if ! grep -qE '^Active:[[:space:]]+yes' <<<"$(v net-info default)"; then
            v net-start default || die "libvirt network 'default' is not active and cannot be started"
        fi
    fi
    cmd_stale_check
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        prepare_system_images_root "$IMAGES"
    else
        mkdir -p "$IMAGES"
    fi
    local free_kib
    free_kib="$(df -Pk "$IMAGES" | awk 'NR == 2 { print $4 }')"
    [ "${free_kib:-0}" -ge $((10 * 1024 * 1024)) ] || die "less than 10 GiB free under $IMAGES"
}

wait_for_guest() {
    local name="$1" log="$2" timeout="$3" start now last=0
    start="$(date +%s)"
    while :; do
        if [ -f "$log" ] && grep -q 'qeminga-e2e-guest: RESULT' "$log"; then
            return 0
        fi
        now="$(date +%s)"
        if [ $((now - start)) -ge "$timeout" ]; then
            echo "no guest verdict after ${timeout}s"
            return 1
        fi
        local state
        state="$(domain_state "$name" 2>/dev/null || echo unknown)"
        if [ "$state" != running ]; then
            echo "domain is '$state' before the guest reported"
            return 1
        fi
        if [ $((now - last)) -ge 30 ]; then
            last="$now"
            echo "[$((now - start))s] $( [ -f "$log" ] && tail -c 2000 "$log" | tr -d '\r' | grep -v '^[[:space:]]*$' | tail -n 1 || echo 'no console output yet')"
        fi
        sleep 5
    done
}

agent() { v qemu-agent-command "$1" "$2"; }

# Proves hardware KVM acceleration is actually active (never a silent TCG fallback).
prove_kvm() {
    local name="$1" info qemu_log
    qemu_log="$(qemu_log_of "$name")"
    grep -q "<domain type='kvm'" <<<"$(v dumpxml "$name")" || { echo "domain is not type='kvm'"; return 1; }
    info="$(v qemu-monitor-command "$name" --hmp 'info kvm' | tr -d '\r')" || return 1
    echo "info kvm: $info"
    case "$info" in
        *"kvm support: enabled"*) ;;
        *) echo "KVM is not enabled"; return 1 ;;
    esac
    [ -f "$qemu_log" ] || { echo "missing QEMU log at $qemu_log"; return 1; }
    grep -qE -- '-accel kvm|accel=kvm' "$qemu_log" || { echo "no KVM accelerator flag on QEMU command line"; return 1; }
    if grep -qE -- '-accel tcg|accel=tcg' "$qemu_log"; then
        echo "TCG found on QEMU command line"
        return 1
    fi
}

cmd_run() {
    parse_opts "$@"
    local arch candidate sha run_id attempt expect cache
    arch="$(need arch)"; candidate="$(need candidate)"; sha="$(need source_sha)"
    run_id="$(need run_id)"; attempt="$(need run_attempt)"; OUT="$(need out)"
    expect="$(need expect_sha256)"; cache="${opt_image_cache:-}"
    check_arch "$arch"; check_sha "$sha"
    check_number --run-id "$run_id"; check_number --run-attempt "$attempt"
    [[ "$expect" =~ ^[0-9a-f]{64}$ ]] || die "--expect-sha256 must be 64 hex digits: '$expect'"
    check_path QEMINGA_E2E_IMAGES "$IMAGES"
    local boot_timeout="${QEMINGA_E2E_BOOT_TIMEOUT_SECS:-300}"
    local shutdown_timeout="${QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS:-120}"
    check_number QEMINGA_E2E_BOOT_TIMEOUT_SECS "$boot_timeout"
    check_number QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS "$shutdown_timeout"

    mkdir -p "$OUT/tests"
    rm -f "$OUT"/tests/* "$OUT/result.json"
    RUN_ARCH="$arch" RUN_SHA="$sha" RUN_DIGEST="$NO_DIGEST" RUN_ACCEL=unknown
    RUN_NAME="$(domain_name "$run_id" "$attempt" "$arch")"
    check_name "$RUN_NAME"
    RUN_DIR="$IMAGES/$RUN_NAME"
    local name="$RUN_NAME" dir="$RUN_DIR" digest

    # shellcheck disable=SC2154 # rc is assigned inside the trap
    trap 'rc=$?; collect_diagnostics "$RUN_NAME" "$RUN_DIR" "$OUT"; write_result "$OUT" "$RUN_ARCH" "$RUN_SHA" "$RUN_DIGEST" "$RUN_ACCEL" || rc=1; exit $rc' EXIT

    preflight "$arch"
    {
        echo "runner kernel: $(uname -srm)"
        v version
        "qemu-system-$arch" --version | head -n 1
    } >"$OUT/versions.txt" 2>&1
    cat "$OUT/versions.txt"

    say "candidate"
    digest="$(cmd_verify_candidate "$candidate" "$arch" "$sha")"
    RUN_DIGEST="$digest"
    echo "candidate sha256 $digest (manifest consistent)"
    [ "$digest" = "$expect" ] || die "candidate binary $digest is not the one the build job reported ($expect)"
    echo "candidate sha256 matches the build job's reported digest"
    local version
    version="$(jq -er .version "$candidate/manifest.json")"

    say "disposable KVM guest $name in $dir"
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        create_system_run_dir "$IMAGES" "$name"
    else
        create_session_run_dir "$dir"
    fi
    (
        umask 0077
        fetch_image "$arch" "$dir/root.qcow2" "$cache"
    )
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        handoff_system_guest_file "$IMAGES" "$name" "root.qcow2" 0
        qemu-img resize -q "$dir/root.qcow2" 8G
        handoff_system_guest_file "$IMAGES" "$name" "root.qcow2" 1
    else
        chmod 0600 "$dir/root.qcow2"
        qemu-img resize -q "$dir/root.qcow2" 8G
        chmod 0600 "$dir/root.qcow2"
    fi

    local seed="$dir/seed" payload="$dir/payload"
    mkdir -p "$seed" "$payload/packaging"
    printf 'instance-id: %s\nlocal-hostname: qeminga-e2e\n' "$name" >"$seed/meta-data"
    cat >"$seed/user-data" <<'EOF'
#cloud-config
# qeminga KVM smoke guest: no network packages, no login; the payload
# disk carries the candidate and the install script, whose output goes to
# the serial console the host reads.
ssh_pwauth: false
package_update: false
package_upgrade: false
runcmd:
  - [sh, -c, "mkdir -p /run/qeminga-e2e && mount -o ro LABEL=QEMINGAE2E /run/qeminga-e2e && bash /run/qeminga-e2e/guest.sh /run/qeminga-e2e >/dev/console 2>&1 || echo 'qeminga-e2e-guest: RESULT FAIL (payload)' >/dev/console"]
EOF
    install -m 0755 "$candidate/qeminga" "$payload/qeminga"
    cp -r "$candidate/packaging/." "$payload/packaging/"
    echo "$digest" >"$payload/qeminga.sha256"
    install -m 0755 "$HERE/libvirt-tcg-guest.sh" "$payload/guest.sh"
    (
        umask 0077
        genisoimage -quiet -output "$dir/seed.iso" -volid cidata -joliet -rock "$seed"
        genisoimage -quiet -output "$dir/payload.iso" -volid QEMINGAE2E -joliet -rock "$payload"
    )
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        handoff_system_guest_file "$IMAGES" "$name" "seed.iso" 1
        handoff_system_guest_file "$IMAGES" "$name" "payload.iso" 1
    else
        chmod 0600 "$dir/seed.iso" "$dir/payload.iso"
    fi

    cmd_domain_xml --arch "$arch" --name "$name" --dir "$dir" --vcpus "$(nproc)" >"$dir/domain.xml"
    v define "$dir/domain.xml"
    v start "$name"

    say "accelerator"
    if prove_kvm "$name"; then RUN_ACCEL=kvm; mark accelerator_kvm pass; else mark accelerator_kvm fail; fi
    [ "$RUN_ACCEL" = kvm ] || exit 1

    say "boot and install under KVM (up to ${boot_timeout}s)"
    local install=fail
    if wait_for_guest "$name" "$dir/serial.log" "$boot_timeout"; then
        grep 'qeminga-e2e-guest:' "$dir/serial.log" | tr -d '\r' || true
        if grep -q 'qeminga-e2e-guest: RESULT PASS' "$dir/serial.log"; then
            local info
            if info="$(agent "$name" '{"execute":"guest-info"}')" \
                && [ "$(jq -r .return.version <<<"$info")" = "$version" ]; then
                echo "the agent answering is qeminga $version"
                install=pass
            else
                echo "guest-info does not report qeminga $version: ${info:-no answer}"
            fi
        fi
    fi
    mark production_install "$install"
    [ "$install" = pass ] || exit 1

    say "AC16: scripts/e2e-libvirt.sh"
    if bash "$REPO/scripts/e2e-libvirt.sh" --connect "$CONNECT_URI" --no-shutdown "$name" 2>&1 | tee "$OUT/e2e-libvirt.log"; then
        mark libvirt_interop pass
    else
        mark libvirt_interop fail
    fi

    say "virsh shutdown --mode agent (up to ${shutdown_timeout}s)"
    local stopped=fail i
    if v shutdown "$name" --mode agent; then
        for ((i = 0; i < shutdown_timeout; i += 2)); do
            if [ "$(domain_state "$name" 2>/dev/null || true)" = "shut off" ]; then
                stopped=pass
                break
            fi
            sleep 2
        done
        echo "domstate: $(domain_state "$name" 2>&1 || true)"
    fi
    mark agent_shutdown "$stopped"
}

# ---- dispatch -------------------------------------------------------------

usage() { awk 'NR > 1 && /^set -euo/ { exit } NR > 1 { print }' "$0"; }
[ $# -ge 1 ] || { usage; exit 64; }
sub="$1"; shift
case "$sub" in
    manifest) cmd_manifest "$@" ;;
    verify-candidate) cmd_verify_candidate "$@" ;;
    domain-xml) cmd_domain_xml "$@" ;;
    stale-check) cmd_stale_check "$@" ;;
    image-key) cmd_image_key "$@" ;;
    fetch-image) cmd_fetch_image "$@" ;;
    run) cmd_run "$@" ;;
    result) cmd_result "$@" ;;
    cleanup) cmd_cleanup "$@" ;;
    -h | --help) usage ;;
    *) die "unknown subcommand '$sub'" ;;
esac
