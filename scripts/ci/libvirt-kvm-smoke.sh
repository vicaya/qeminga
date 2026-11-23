#!/usr/bin/env bash
# libvirt + QEMU KVM smoke lane (#53, AC16) for GitHub-hosted x86_64 runners
# (.github/workflows/libvirt-kvm-hosted.yml) and self-hosted x86_64 / aarch64
# KVM runners (.github/workflows/libvirt-kvm.yml).
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
#   libvirt-kvm-smoke.sh ensure-result --out DIR --arch ARCH --source-sha SHA
#       [--expect-sha256 HEX]
#   libvirt-kvm-smoke.sh verify-pass --out DIR --arch ARCH --source-sha SHA
#       --expect-sha256 HEX
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
    if [ -n "${QEMINGA_E2E_QEMU_LOG_DIR:-}" ]; then
        echo "${QEMINGA_E2E_QEMU_LOG_DIR%/}/${name}.log"
    elif [ "$CONNECT_URI" = "qemu:///session" ]; then
        echo "${XDG_CACHE_HOME:-${HOME:?HOME must be set}/.cache}/libvirt/qemu/log/${name}.log"
    else
        echo "/var/log/libvirt/qemu/${name}.log"
    fi
}

check_out_path() {
    local p="$1"
    [ -n "$p" ] || die "--out must not be empty"
    case "$p" in
        . | .. | ./* | ../* | */. | */.. | */./* | */../*)
            die "--out must not contain '.' or '..' segments: '$p'"
            ;;
    esac
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
    stale="$(grep -E '^qeminga-e2e-' <<<"$names" || true)"
    if [ -n "$stale" ]; then
        echo "libvirt-kvm-smoke: stale qeminga test domain(s) on $CONNECT_URI:" >&2
        printf '  %s\n' "$stale" >&2
        echo "inspect them with 'virsh $CONNECT dominfo NAME', then remove each with" >&2
        echo "'$0 cleanup --arch ARCH --run-id N --run-attempt N' for its run" >&2
        exit 1
    fi
}

domain_state() {
    local ref="$1" out list_flag="--name"
    if [[ "$ref" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        list_flag="--uuid"
    fi
    if out="$(v domstate "$ref" 2>&1)"; then
        printf '%s\n' "$out" | head -n 1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        return 0
    fi
    case "$out" in
        *"failed to get domain"* | *"Domain not found"*)
            local refs
            refs="$(v list --all "$list_flag")" || return 1
            if grep -iqx -- "$ref" <<<"$refs"; then return 1; fi
            echo absent
            ;;
        *) echo "$out" >&2; return 1 ;;
    esac
}

collect_diagnostics() {
    local name="$1" dir="$2" out="$3" dir_verified="${4:-0}" domain_owned="${5:-0}" domain_ref="${6:-}" verified_xml="${7:-}" qlog_cursor="${8:-}" dir_id="${9:-}" qlog expected_uuid=""
    qlog="$(qemu_log_of "$name")"
    if [[ "$domain_ref" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        expected_uuid="$domain_ref"
    fi
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        sys_fs_ops prepare-evidence-dir "$out" 2>/dev/null || return 0
        if [ "$domain_owned" = "1" ]; then
            local dom_xml="$verified_xml"
            if [ -z "$dom_xml" ] && [ -n "$domain_ref" ]; then
                dom_xml="$(v dumpxml "$domain_ref" 2>/dev/null || true)"
            fi
            if [ -n "$dom_xml" ]; then
                printf '%s\n' "$dom_xml" | sys_fs_ops publish-evidence-stdin "$out" "domain.xml" 2>/dev/null || true
            fi
            if [ -n "$qlog_cursor" ]; then
                local c_st="" c_dev="" c_ino="" c_off=""
                IFS=$'\t' read -r c_st c_dev c_ino c_off <<<"$qlog_cursor"
                if [ -n "$c_st" ]; then
                    sys_fs_ops collect-qemu-log "$qlog" "$out" "qemu.log" "$c_st" "$c_dev" "$c_ino" "$c_off" "$expected_uuid" 2>/dev/null || true
                fi
            fi
        fi
        if { [ "$dir_verified" = "1" ] || [ "$dir_verified" = "verify" ]; } && [ -n "$dir_id" ]; then
            sys_fs_ops collect-serial-log "$IMAGES" "$name" "$out" "serial.log" "$dir_id" 2>/dev/null || true
        fi
        return 0
    fi
    sys_fs_ops prepare-session-evidence-dir "$out" 2>/dev/null || return 0
    if [ "$domain_owned" = "1" ]; then
        local dom_xml="$verified_xml"
        if [ -z "$dom_xml" ]; then
            dom_xml="$(v dumpxml "${domain_ref:-$name}" 2>/dev/null || true)"
        fi
        if [ -n "$dom_xml" ]; then
            printf '%s\n' "$dom_xml" | sys_fs_ops publish-session-evidence-stdin "$out" "domain.xml" 2>/dev/null || true
        fi
        if [ -n "$qlog_cursor" ]; then
            local c_st="" c_dev="" c_ino="" c_off=""
            IFS=$'\t' read -r c_st c_dev c_ino c_off <<<"$qlog_cursor"
            if [ -n "$c_st" ]; then
                sys_fs_ops collect-qemu-log-session "$qlog" "$out" "qemu.log" "$c_st" "$c_dev" "$c_ino" "$c_off" "$expected_uuid" 2>/dev/null || true
            fi
        fi
    fi
    if [ "$dir_verified" = "1" ] || [ "$dir_verified" = "verify" ]; then
        sys_fs_ops collect-serial-log-session "$IMAGES" "$name" "$out" "serial.log" 2>/dev/null || true
    fi
}

cmd_cleanup() {
    parse_opts "$@"
    local arch run_id attempt out
    arch="$(need arch)"; run_id="$(need run_id)"; attempt="$(need run_attempt)"
    out="${opt_out:-}"
    check_arch "$arch"
    check_number --run-id "$run_id"; check_number --run-attempt "$attempt"
    if [ -n "$out" ]; then
        check_out_path "$out"
    fi
    local name dir state
    name="$(domain_name "$run_id" "$attempt" "$arch")"
    check_name "$name"
    check_path QEMINGA_E2E_IMAGES "$IMAGES"
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        [ "$(id -u)" -eq 0 ] || die "qemu:///system cleanup requires root"
        command -v python3 >/dev/null || die "missing tool: python3"
        if [ -n "$out" ]; then
            sys_fs_ops prepare-evidence-dir "$out" || exit 1
        fi
    elif [ -n "$out" ]; then
        command -v python3 >/dev/null || die "missing tool: python3"
        sys_fs_ops prepare-session-evidence-dir "$out" || exit 1
    fi
    dir="$IMAGES/$name"
    if ! command -v virsh >/dev/null 2>&1; then
        [ ! -e "$dir" ] || die "virsh is not installed, so the state of $name cannot be established; keeping $dir"
        local note="nothing to clean up: libvirt is not installed and $dir does not exist"
        echo "$note"
        if [ -n "$out" ]; then
            if [ "$CONNECT_URI" = "qemu:///system" ]; then
                printf '%s\n' "$note" | sys_fs_ops publish-evidence-stdin "$out" "cleanup.txt"
            else
                printf '%s\n' "$note" | sys_fs_ops publish-session-evidence-stdin "$out" "cleanup.txt"
            fi
        fi
        return 0
    fi

    local dom_ref="$name" dom_is_persistent=1 target_status="present" target_dir_id=""
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        # Verify the image root, run directory identity, and same-mount tree BEFORE
        # touching libvirt or collecting diagnostics, then verify domain persistence
        # and BOTH live and (when persistent) inactive XML against this run directory
        # and pin its UUID BEFORE destroy/undefine.
        local verified_target="" expected_lexical_dir="" expected_resolved_dir=""
        verified_target="$(sys_fs_ops verify-cleanup-target "$IMAGES" "$name")" || exit 1
        IFS=$'\t' read -r target_status expected_lexical_dir expected_resolved_dir target_dir_id <<<"$verified_target"

        state="$(domain_state "$name")" \
            || die "the state of $name cannot be established; keeping $dir"
        if [ "$state" != absent ]; then
            if [ "$target_status" != "present" ] || [ -z "$target_dir_id" ]; then
                die "expected run directory '$expected_lexical_dir' is absent, so existing domain $name cannot be verified against its storage; preserving domain"
            fi
            local live_xml="" dom_uuid=""
            live_xml="$(v dumpxml "$name" 2>/dev/null)" \
                || die "cannot inspect live XML for $name before cleanup; keeping $dir"
            dom_uuid="$(printf '%s\n' "$live_xml" \
                | sys_fs_ops verify-domain-xml "$name" "$expected_lexical_dir" "$expected_resolved_dir")" \
                || exit 1
            local persistent_uuids=""
            persistent_uuids="$(v list --all --persistent --uuid)" \
                || die "cannot determine whether $name ($dom_uuid) is persistent before cleanup; preserving domain and $dir"
            if grep -iqx -- "$dom_uuid" <<<"$persistent_uuids"; then
                dom_is_persistent=1
                local inactive_xml="" inactive_uuid=""
                inactive_xml="$(v dumpxml --inactive "$dom_uuid" 2>/dev/null)" \
                    || die "cannot inspect persistent XML for $name ($dom_uuid) before cleanup; preserving domain and $dir"
                inactive_uuid="$(printf '%s\n' "$inactive_xml" \
                    | sys_fs_ops verify-domain-xml "$name" "$expected_lexical_dir" "$expected_resolved_dir")" \
                    || exit 1
                [ "$inactive_uuid" = "$dom_uuid" ] \
                    || die "persistent domain UUID '$inactive_uuid' does not match live UUID '$dom_uuid'; preserving domain and $dir"
            else
                if [ "$state" = "shut off" ]; then
                    die "shut-off domain $name ($dom_uuid) is not listed as persistent; preserving domain and $dir"
                fi
                dom_is_persistent=0
            fi
            dom_ref="$dom_uuid"
            # Omit historical qemu.log during standalone cleanup (no reliable start cursor)
            # and bind serial.log collection to the verified target_dir_id.
            [ -n "$out" ] && collect_diagnostics "$name" "$dir" "$out" verify 1 "$dom_uuid" "$live_xml" "" "$target_dir_id"
        elif [ -n "$out" ] && [ "$target_status" = "present" ]; then
            collect_diagnostics "$name" "$dir" "$out" verify 0 "" "" "" "$target_dir_id"
        fi
    else
        state="$(domain_state "$name")" \
            || die "the state of $name cannot be established; keeping $dir"
        if [ -n "$out" ]; then
            if [ "$state" != absent ]; then
                collect_diagnostics "$name" "$dir" "$out" verify 1 "$name" "" "" ""
            else
                collect_diagnostics "$name" "$dir" "$out" verify 0 "" "" "" ""
            fi
        fi
    fi

    if [ "$state" != absent ]; then
        if [ "$state" != "shut off" ]; then
            v destroy "$dom_ref" || true
            state="$(domain_state "$dom_ref")" || die "cannot establish $name ($dom_ref) state after destroy; keeping $dir"
            if [ "$dom_is_persistent" -eq 0 ]; then
                [ "$state" = absent ] || die "transient domain $name ($dom_ref) is still '$state' after destroy; keeping $dir"
            else
                [ "$state" = "shut off" ] || die "$name ($dom_ref) is still '$state'; keeping $dir"
            fi
        fi
        if [ "$dom_is_persistent" -eq 1 ]; then
            # Always use --keep-nvram so libvirt never deletes NVRAM outside our
            # FD-anchored run directory cleanup (VARS.fd lives inside $dir).
            if [ "$CONNECT_URI" = "qemu:///system" ]; then
                v undefine --keep-nvram "$dom_ref" || die "cannot undefine $name ($dom_ref); keeping $dir"
            else
                v undefine --keep-nvram "$dom_ref" || v undefine "$dom_ref" || die "cannot undefine $name ($dom_ref); keeping $dir"
            fi
            state="$(domain_state "$dom_ref")" || die "cannot confirm $name ($dom_ref) is gone; keeping $dir"
            [ "$state" = absent ] || die "$name ($dom_ref) is still defined; keeping $dir"
        fi
    fi
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        if [ "$target_status" = "present" ]; then
            local post_name_state=""
            post_name_state="$(domain_state "$name")" \
                || die "cannot verify that $name was not reassigned before removing $dir; keeping $dir"
            [ "$post_name_state" = absent ] \
                || die "a replacement domain named $name ($post_name_state) exists; preserving $dir"
            local cleanup_status=""
            cleanup_status="$(sys_fs_ops cleanup-run-dir "$IMAGES" "$name" "$target_dir_id")" || exit 1
            if [ "$cleanup_status" = "removed" ]; then
                echo "removed $dir"
            fi
        fi
    elif [ -d "$dir" ]; then
        rm -rf --one-file-system -- "$dir"
        echo "removed $dir"
    fi
    echo "cleanup of $name done"
}

# ---- result ---------------------------------------------------------------

write_result() {
    local out="$1" arch="$2" sha="$3" digest="$4" accel="$5" all_not_run="${6:-0}"
    local tests='{}' overall=pass t status machine image image_sha result_json
    machine="$(machine_of "$arch")" || return 1
    image="$(image_file_of "$arch")" || return 1
    image_sha="$(image_sha_of "$arch")" || return 1
    local read_op
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        read_op="read-evidence-stdout"
    else
        read_op="read-session-evidence-stdout"
    fi
    for t in $MANDATORY_TESTS; do
        if [ "$all_not_run" = 1 ]; then
            status=not_run
        else
            local marker_raw="" marker_rc=0
            if marker_raw="$(sys_fs_ops "$read_op" --quiet-missing "$out" "$t" "tests")"; then
                case "$(printf '%s' "$marker_raw" | tr -d '[:space:]')" in
                    pass) status=pass ;;
                    *) status=fail ;;
                esac
            else
                marker_rc=$?
                case "$marker_rc" in
                    2) status=not_run ;;
                    4) status=fail ;;
                    *) return 1 ;;
                esac
            fi
        fi
        [ "$status" = pass ] || overall=fail
        tests="$(jq -c --arg t "$t" --arg s "$status" '. + {($t): $s}' <<<"$tests")" || return 1
    done
    [ "$accel" = kvm ] || overall=fail
    result_json="$(jq -n \
        --arg suite "$SUITE" --arg repo "$SOURCE_REPOSITORY" --arg sha "$sha" \
        --arg arch "$arch" --arg digest "$digest" --arg accel "$accel" \
        --arg machine "$machine" \
        --arg image "$image" --arg image_release "$IMAGE_RELEASE" \
        --arg image_sha "$image_sha" \
        --argjson tests "$tests" --arg result "$overall" \
        '{schema: 1, suite: $suite, source_repository: $repo, source_sha: $sha,
          architecture: $arch, candidate_binary_sha256: $digest,
          virtualization: {hypervisor: "qemu", accelerator: $accel, machine: $machine},
          guest: {image: $image, image_release: $image_release, image_sha256: $image_sha},
          tests: $tests, result: $result}')" || return 1
    local publish_op="publish-session-evidence-stdin"
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        publish_op="publish-evidence-stdin"
    fi
    printf '%s\n' "$result_json" | sys_fs_ops "$publish_op" "$out" "result.json" || return 1
    printf '%s\n' "$result_json" || return 1
    [ "$overall" = pass ]
}

cmd_result() {
    parse_opts "$@"
    local out arch sha digest accel
    out="$(need out)"; arch="$(need arch)"; sha="$(need source_sha)"
    digest="$(need binary_sha256)"; accel="$(need accelerator)"
    check_out_path "$out"
    check_arch "$arch"; check_sha "$sha"
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "bad digest '$digest'"
    command -v python3 >/dev/null || die "missing tool: python3"
    write_result "$out" "$arch" "$sha" "$digest" "$accel" || return 1
}

# Validates that `$out/result.json` contains exactly one JSON object forming a
# complete `libvirt-kvm-smoke-v1` record bound to this run's architecture and
# commit SHA. Delegates to `sys_fs_ops` (`verify-result` / `verify-session-result`),
# which verifies the evidence directory, opens a regular single-link file with
# retryable handling for concurrent atomic replacement, and parses the bounded
# UTF-8 JSON explicitly in Python (avoiding jq 1.6 vs jq 1.7 exit-code drift).
#
# Exit status:
#   0: valid run-bound record (and passing when `$require_pass` is `1`)
#   1: confirmed missing, malformed/mismatched JSON, or unsafe file inside a
#      verified directory
#   2: untrusted output directory or indeterminate operational/concurrent-churn
#      failure
valid_result_json() {
    local out="$1" arch="$2" sha="$3" expect="$4" require_pass="${5:-0}"
    local machine image image_sha verify_op="verify-session-result" rc=0
    machine="$(machine_of "$arch")" || return 2
    image="$(image_file_of "$arch")" || return 2
    image_sha="$(image_sha_of "$arch")" || return 2
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        verify_op="verify-result"
    fi
    if sys_fs_ops "$verify_op" \
        "$out" "$SUITE" "$SOURCE_REPOSITORY" "$sha" "$arch" "$expect" \
        "$machine" "$image" "$IMAGE_RELEASE" "$image_sha" "$MANDATORY_TESTS" "$require_pass"; then
        return 0
    else
        rc=$?
    fi
    case "$rc" in
        2 | 4 | 5) return 1 ;;
        *) return 2 ;;
    esac
}

cmd_ensure_result() {
    parse_opts "$@"
    local out arch sha expect machine image image_sha ensure_op="ensure-session-result"
    out="$(need out)"; arch="$(need arch)"; sha="$(need source_sha)"
    expect="${opt_expect_sha256:-}"
    check_out_path "$out"
    check_arch "$arch"; check_sha "$sha"
    if [ -n "$expect" ]; then
        [[ "$expect" =~ ^[0-9a-f]{64}$ ]] || die "--expect-sha256 must be 64 hex digits: '$expect'"
    fi
    command -v python3 >/dev/null || die "missing tool: python3"
    machine="$(machine_of "$arch")" || exit 1
    image="$(image_file_of "$arch")" || exit 1
    image_sha="$(image_sha_of "$arch")" || exit 1
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        ensure_op="ensure-result"
    fi
    sys_fs_ops "$ensure_op" \
        "$out" "$SUITE" "$SOURCE_REPOSITORY" "$sha" "$arch" "$expect" \
        "$machine" "$image" "$IMAGE_RELEASE" "$image_sha" "$MANDATORY_TESTS" "$NO_DIGEST" \
        || die "cannot verify or ensure result.json at $out/result.json; preserving any existing evidence"
}

cmd_verify_pass() {
    parse_opts "$@"
    local out arch sha expect
    out="$(need out)"; arch="$(need arch)"; sha="$(need source_sha)"
    expect="${opt_expect_sha256:-}"
    check_out_path "$out"
    check_arch "$arch"; check_sha "$sha"
    [[ "$expect" =~ ^[0-9a-f]{64}$ ]] || die "--expect-sha256 must be 64 hex digits: '$expect'"
    command -v python3 >/dev/null || die "missing tool: python3"
    valid_result_json "$out" "$arch" "$sha" "$expect" 1 \
        || die "no validated passing result.json at $out/result.json for $arch @ $sha (candidate $expect)"
}

# ---- the lane -------------------------------------------------------------

mark() {
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        printf '%s\n' "$2" | sys_fs_ops publish-evidence-stdin "$OUT" "$1" "tests"
    else
        printf '%s\n' "$2" | sys_fs_ops publish-session-evidence-stdin "$OUT" "$1" "tests"
    fi
    echo "-- $1: $2"
}

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
    if ! resolved="$(python3 -IB - "$conf" "$override_user" "$override_group" 3<<<"$caps_xml" <<'PY'
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

# FD-anchored filesystem operations for the `qemu:///system` lane live in
# `scripts/ci/libvirt_kvm_sysfs.py` so both this script (under `python3 -IB`)
# and unprivileged unit tests share the exact same implementation without
# writing `__pycache__` bytecode into the checkout.
sys_fs_ops() {
    python3 -IB "$HERE/libvirt_kvm_sysfs.py" "$@"
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
    local dom_ref="$1" log="$2" timeout="$3" start now last=0
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
        state="$(domain_state "$dom_ref" 2>/dev/null || echo unknown)"
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
    local dom_ref="$1" name="$2" qlog_cursor="${3:-}" info qemu_log qlog_seg="" expected_uuid=""
    qemu_log="$(qemu_log_of "$name")"
    if [[ "$dom_ref" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        expected_uuid="$dom_ref"
    fi
    grep -q "<domain type='kvm'" <<<"$(v dumpxml "$dom_ref")" || { echo "domain is not type='kvm'"; return 1; }
    info="$(v qemu-monitor-command "$dom_ref" --hmp 'info kvm' | tr -d '\r')" || return 1
    echo "info kvm: $info"
    case "$info" in
        *"kvm support: enabled"*) ;;
        *) echo "KVM is not enabled"; return 1 ;;
    esac
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        [ -n "$qlog_cursor" ] || { echo "missing QEMU log cursor for $qemu_log"; return 1; }
        local c_st="" c_dev="" c_ino="" c_off=""
        IFS=$'\t' read -r c_st c_dev c_ino c_off <<<"$qlog_cursor"
        qlog_seg="$(sys_fs_ops read-qemu-log-segment "$qemu_log" "$c_st" "$c_dev" "$c_ino" "$c_off" "$expected_uuid")" \
            || { echo "missing current-run QEMU log segment at $qemu_log"; return 1; }
    elif [ -n "$qlog_cursor" ] && command -v python3 >/dev/null 2>&1; then
        local c_st="" c_dev="" c_ino="" c_off=""
        IFS=$'\t' read -r c_st c_dev c_ino c_off <<<"$qlog_cursor"
        qlog_seg="$(sys_fs_ops read-qemu-log-segment-session "$qemu_log" "$c_st" "$c_dev" "$c_ino" "$c_off" "$expected_uuid")" \
            || { echo "missing current-run QEMU log segment at $qemu_log"; return 1; }
    else
        [ ! -L "$qemu_log" ] && [ -f "$qemu_log" ] || { echo "missing QEMU log at $qemu_log"; return 1; }
        qlog_seg="$(cat -- "$qemu_log")" || return 1
    fi
    grep -qE -- '-accel kvm|accel=kvm' <<<"$qlog_seg" || { echo "no KVM accelerator flag on QEMU command line"; return 1; }
    if grep -qE -- '-accel tcg|accel=tcg' <<<"$qlog_seg"; then
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
    check_out_path "$OUT"
    check_arch "$arch"; check_sha "$sha"
    check_number --run-id "$run_id"; check_number --run-attempt "$attempt"
    [[ "$expect" =~ ^[0-9a-f]{64}$ ]] || die "--expect-sha256 must be 64 hex digits: '$expect'"
    check_path QEMINGA_E2E_IMAGES "$IMAGES"
    local boot_timeout="${QEMINGA_E2E_BOOT_TIMEOUT_SECS:-300}"
    local shutdown_timeout="${QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS:-120}"
    check_number QEMINGA_E2E_BOOT_TIMEOUT_SECS "$boot_timeout"
    check_number QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS "$shutdown_timeout"

    command -v python3 >/dev/null || die "missing tool: python3"
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        [ "$(id -u)" -eq 0 ] || die "qemu:///system requires root"
        sys_fs_ops prepare-evidence-dir "$OUT" init-run || exit 1
    else
        sys_fs_ops prepare-session-evidence-dir "$OUT" init-run || exit 1
    fi
    RUN_ARCH="$arch" RUN_SHA="$sha" RUN_DIGEST="$NO_DIGEST" RUN_ACCEL=unknown
    RUN_NAME="$(domain_name "$run_id" "$attempt" "$arch")"
    check_name "$RUN_NAME"
    RUN_DIR="$IMAGES/$RUN_NAME"
    RUN_DIR_VERIFIED=0
    RUN_DIR_ID=""
    RUN_DOMAIN_OWNED=0
    RUN_DOMAIN_REF=""
    RUN_QLOG_CURSOR=""
    local name="$RUN_NAME" dir="$RUN_DIR" digest

    # shellcheck disable=SC2154 # rc is assigned inside the trap
    trap 'rc=$?; collect_diagnostics "$RUN_NAME" "$RUN_DIR" "$OUT" "$RUN_DIR_VERIFIED" "$RUN_DOMAIN_OWNED" "$RUN_DOMAIN_REF" "" "$RUN_QLOG_CURSOR" "$RUN_DIR_ID"; write_result "$OUT" "$RUN_ARCH" "$RUN_SHA" "$RUN_DIGEST" "$RUN_ACCEL" || rc=1; exit $rc' EXIT

    preflight "$arch"
    local versions_txt=""
    versions_txt="$({
        echo "runner kernel: $(uname -srm)"
        v version
        "qemu-system-$arch" --version | head -n 1
    } 2>&1)"
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        printf '%s\n' "$versions_txt" | sys_fs_ops publish-evidence-stdin "$OUT" "versions.txt"
    else
        printf '%s\n' "$versions_txt" | sys_fs_ops publish-session-evidence-stdin "$OUT" "versions.txt"
    fi
    printf '%s\n' "$versions_txt"

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
        RUN_DIR_ID="$(create_system_run_dir "$IMAGES" "$name")"
        [ -n "$RUN_DIR_ID" ] || die "failed to capture verified run directory identity for $dir"
    else
        create_session_run_dir "$dir"
    fi
    RUN_DIR_VERIFIED=1
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
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        local target_info="" t_st="" t_lex="" t_res="" t_dir_id="" def_xml="" def_uuid=""
        target_info="$(sys_fs_ops verify-cleanup-target "$IMAGES" "$name")" \
            || die "cannot verify run directory '$dir' after defining $name; refusing to start"
        IFS=$'\t' read -r t_st t_lex t_res t_dir_id <<<"$target_info"
        [ "$t_st" = "present" ] && [ -n "$t_dir_id" ] && [ "$t_dir_id" = "$RUN_DIR_ID" ] \
            || die "expected run directory '$t_lex' is absent or changed after defining $name; refusing to start"
        def_xml="$(v dumpxml "$name" 2>/dev/null)" \
            || die "cannot inspect defined XML for $name before start; refusing to start"
        [ -n "$def_xml" ] \
            || die "defined XML for $name is empty; refusing to start"
        def_uuid="$(printf '%s\n' "$def_xml" | sys_fs_ops verify-domain-xml "$name" "$t_lex" "$t_res")" \
            || die "defined XML for $name failed ownership verification; refusing to start"
        RUN_DOMAIN_REF="$def_uuid"
        RUN_DOMAIN_OWNED=1
    else
        RUN_DOMAIN_REF="$name"
        RUN_DOMAIN_OWNED=1
    fi
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        RUN_QLOG_CURSOR="$(sys_fs_ops snapshot-qemu-log-cursor "$(qemu_log_of "$name")")" \
            || die "cannot inspect QEMU log path before starting $name ($RUN_DOMAIN_REF)"
    elif command -v python3 >/dev/null 2>&1; then
        RUN_QLOG_CURSOR="$(sys_fs_ops snapshot-qemu-log-cursor-session "$(qemu_log_of "$name")")" \
            || die "cannot inspect QEMU log path before starting $name ($RUN_DOMAIN_REF)"
    fi
    v start "$RUN_DOMAIN_REF"

    say "accelerator"
    if prove_kvm "$RUN_DOMAIN_REF" "$name" "$RUN_QLOG_CURSOR"; then
        RUN_ACCEL=kvm
        mark accelerator_kvm pass
        if [ -n "$RUN_QLOG_CURSOR" ]; then
            local p_st="" p_dev="" p_ino="" p_off="" p_pinned="" p_uuid=""
            IFS=$'\t' read -r p_st p_dev p_ino p_off <<<"$RUN_QLOG_CURSOR"
            if [[ "$RUN_DOMAIN_REF" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                p_uuid="$RUN_DOMAIN_REF"
            fi
            if [ "$CONNECT_URI" = "qemu:///system" ]; then
                p_pinned="$(sys_fs_ops pin-qemu-log-cursor "$(qemu_log_of "$name")" "$p_st" "$p_dev" "$p_ino" "$p_off" "$p_uuid" 2>/dev/null || true)"
            elif command -v python3 >/dev/null 2>&1; then
                p_pinned="$(sys_fs_ops pin-qemu-log-cursor-session "$(qemu_log_of "$name")" "$p_st" "$p_dev" "$p_ino" "$p_off" "$p_uuid" 2>/dev/null || true)"
            fi
            [ -n "$p_pinned" ] && RUN_QLOG_CURSOR="$p_pinned"
        fi
    else
        mark accelerator_kvm fail
    fi
    [ "$RUN_ACCEL" = kvm ] || exit 1

    say "boot and install under KVM (up to ${boot_timeout}s)"
    local install=fail
    if wait_for_guest "$RUN_DOMAIN_REF" "$dir/serial.log" "$boot_timeout"; then
        grep 'qeminga-e2e-guest:' "$dir/serial.log" | tr -d '\r' || true
        if grep -q 'qeminga-e2e-guest: RESULT PASS' "$dir/serial.log"; then
            local info
            if info="$(agent "$RUN_DOMAIN_REF" '{"execute":"guest-info"}')" \
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
    local e2e_tmp="" e2e_rc=0 e2e_publish_op="publish-session-evidence-stdin"
    if [ "$CONNECT_URI" = "qemu:///system" ]; then
        e2e_publish_op="publish-evidence-stdin"
    fi
    e2e_tmp="$(
        umask 0077
        mktemp "$dir/e2e-libvirt.XXXXXX.log"
    )"
    if bash "$REPO/scripts/e2e-libvirt.sh" --connect "$CONNECT_URI" --no-shutdown "$RUN_DOMAIN_REF" 2>&1 | tee "$e2e_tmp"; then
        e2e_rc=0
    else
        e2e_rc=$?
    fi
    sys_fs_ops "$e2e_publish_op" "$OUT" "e2e-libvirt.log" <"$e2e_tmp" || true
    rm -f "$e2e_tmp"
    if [ "$e2e_rc" -eq 0 ]; then
        mark libvirt_interop pass
    else
        mark libvirt_interop fail
    fi

    say "virsh shutdown --mode agent (up to ${shutdown_timeout}s)"
    local stopped=fail i
    if v shutdown "$RUN_DOMAIN_REF" --mode agent; then
        for ((i = 0; i < shutdown_timeout; i += 2)); do
            if [ "$(domain_state "$RUN_DOMAIN_REF" 2>/dev/null || true)" = "shut off" ]; then
                stopped=pass
                break
            fi
            sleep 2
        done
        echo "domstate: $(domain_state "$RUN_DOMAIN_REF" 2>&1 || true)"
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
    ensure-result) cmd_ensure_result "$@" ;;
    verify-pass) cmd_verify_pass "$@" ;;
    cleanup) cmd_cleanup "$@" ;;
    -h | --help) usage ;;
    *) die "unknown subcommand '$sub'" ;;
esac
