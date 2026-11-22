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
#   QEMINGA_E2E_BOOT_TIMEOUT_SECS     default 300 (5 min under KVM)
#   QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS default 120 (2 min under KVM)
#
# tests/libvirt_kvm.rs covers the logic that runs without a hypervisor.
set -euo pipefail

export LC_ALL=C LANG=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

SOURCE_REPOSITORY="vicaya/qeminga"
BUILD_COMMAND="cargo build --release --locked --features seccomp"
SUITE="libvirt-kvm-smoke-v1"
MANDATORY_TESTS="production_install accelerator_kvm libvirt_interop agent_shutdown"
PACKAGING_FILES="packaging/systemd/qeminga.service packaging/udev/99-qeminga.rules packaging/sysusers.d/qeminga.conf packaging/tmpfiles.d/qeminga.conf packaging/config.toml packaging/config-data-protection.toml"

# Pinned Ubuntu 24.04 server cloud images — kept in exact sync with
# scripts/ci/libvirt-tcg-smoke.sh (enforced by tests/libvirt_kvm.rs).
IMAGE_RELEASE="release-20261017"
IMAGE_SOURCES="https://cloud-images.ubuntu.com/releases/24.04/$IMAGE_RELEASE
https://cloud-images-archive.ubuntu.com/releases/noble/$IMAGE_RELEASE
https://cloud-images-archive.ubuntu.com/releases/24.04/$IMAGE_RELEASE"
# shellcheck disable=SC2034 # read through image_sha_of
IMAGE_SHA256_x86_64="04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94"
# shellcheck disable=SC2034 # read through image_sha_of
IMAGE_SHA256_aarch64="50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e"

NO_DIGEST="$(printf '0%.0s' {1..64})"

die() { echo "libvirt-kvm-smoke: $*" >&2; exit 1; }
say() { echo "== $*"; }

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

# ---- validation -----------------------------------------------------------

check_arch() {
    case "$1" in
        x86_64 | aarch64) ;;
        *) die "unsupported architecture '$1' (x86_64 or aarch64)" ;;
    esac
}
check_sha() { [[ "$1" =~ ^[0-9a-f]{40}$ ]] || die "not a full 40-hex commit SHA: '$1'"; }
check_number() { [[ "$2" =~ ^[0-9]+$ ]] || die "$1 must be a decimal number: '$2'"; }
check_name() {
    [[ "$1" =~ ^qeminga-e2e-[0-9]+-[0-9]+-[a-z0-9_]+$ ]] \
        || die "'$1' is outside the qeminga-e2e-<run>-<attempt>-<arch> namespace"
}
check_path() {
    [[ "$2" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "$1 must be an absolute path of [A-Za-z0-9._/-] only: '$2'"
    case "$2" in
        */../* | */.. | */./* | */. | *//*) die "$1 must not contain dot segments or '//': '$2'" ;;
    esac
}

machine_of() { case "$1" in x86_64) echo q35 ;; aarch64) echo virt ;; esac; }
debian_arch_of() { case "$1" in x86_64) echo amd64 ;; aarch64) echo arm64 ;; esac; }
image_sha_of() { local v="IMAGE_SHA256_$1"; echo "${!v}"; }
image_file_of() { echo "ubuntu-24.04-server-cloudimg-$(debian_arch_of "$1").img"; }
domain_name() { echo "qeminga-e2e-$1-$2-$3"; }

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

parse_opts() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --*)
                [ $# -ge 2 ] || die "$1 needs a value"
                local key="${1#--}"
                key="${key//-/_}"
                [[ "$key" =~ ^[a-z0-9_]+$ ]] || die "bad option $1"
                printf -v "opt_$key" '%s' "$2"
                shift 2
                ;;
            *) die "unexpected argument '$1'" ;;
        esac
    done
}
need() { local v="opt_$1"; [ -n "${!v:-}" ] || die "--${1//_/-} is required"; echo "${!v}"; }

# ---- candidate ------------------------------------------------------------

cmd_manifest() {
    parse_opts "$@"
    local out binary arch sha version run_id attempt runner
    out="$(need out)"; binary="$(need binary)"; arch="$(need arch)"
    sha="$(need source_sha)"; version="$(need version)"
    run_id="$(need run_id)"; attempt="$(need run_attempt)"; runner="$(need runner)"
    check_arch "$arch"; check_sha "$sha"
    check_number --run-id "$run_id"; check_number --run-attempt "$attempt"
    [[ "$version" =~ ^[0-9A-Za-z.+-]+$ ]] || die "bad version '$version'"
    [[ "$runner" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad runner label '$runner'"
    [ -f "$binary" ] || die "no binary at $binary"

    mkdir -p "$out"
    install -m 0755 "$binary" "$out/qeminga"
    local packaging='{}' f
    for f in $PACKAGING_FILES; do
        install -D -m 0644 "$REPO/$f" "$out/$f"
        packaging="$(jq -c --arg f "$f" --arg d "$(sha256_of "$out/$f")" '. + {($f): $d}' <<<"$packaging")"
    done
    jq -n \
        --arg repo "$SOURCE_REPOSITORY" --arg sha "$sha" --arg arch "$arch" \
        --arg version "$version" --arg digest "$(sha256_of "$out/qeminga")" \
        --argjson run_id "$run_id" --argjson attempt "$attempt" \
        --arg runner "$runner" --arg command "$BUILD_COMMAND" \
        --argjson packaging "$packaging" \
        '{schema: 1, source_repository: $repo, source_sha: $sha,
          architecture: $arch, version: $version,
          binary: {path: "qeminga", sha256: $digest},
          packaging: $packaging,
          build: {run_id: $run_id, run_attempt: $attempt, runner: $runner,
                  command: $command}}' >"$out/manifest.json"
    cat "$out/manifest.json"
}

cmd_verify_candidate() {
    [ $# -eq 3 ] || die "usage: verify-candidate DIR ARCH SHA"
    local dir="$1" arch="$2" sha="$3" m="$1/manifest.json"
    check_arch "$arch"; check_sha "$sha"
    [ -f "$m" ] || die "no manifest at $m"
    jq -e . "$m" >/dev/null 2>&1 || die "malformed manifest $m"
    field() { jq -er "$1" "$m" 2>/dev/null || die "manifest lacks $1"; }
    [ "$(field .schema)" = 1 ] || die "unknown manifest schema $(field .schema)"
    [ "$(field .source_repository)" = "$SOURCE_REPOSITORY" ] || die "candidate from another repository"
    [ "$(field .source_sha)" = "$sha" ] || die "candidate built from $(field .source_sha), expected $sha"
    [ "$(field .architecture)" = "$arch" ] || die "candidate for $(field .architecture), expected $arch"
    [ "$(field .build.command)" = "$BUILD_COMMAND" ] || die "candidate not built with '$BUILD_COMMAND'"
    [ "$(field .binary.path)" = qeminga ] || die "unexpected binary path"
    local want got f
    want="$(field .binary.sha256)"
    [ -f "$dir/qeminga" ] || die "candidate binary missing"
    got="$(sha256_of "$dir/qeminga")"
    [ "$got" = "$want" ] || die "candidate binary digest $got, manifest says $want"
    for f in $PACKAGING_FILES; do
        want="$(jq -er --arg f "$f" '.packaging[$f]' "$m" 2>/dev/null)" || die "manifest lacks $f"
        [ -f "$dir/$f" ] || die "candidate lacks $f"
        [ "$(sha256_of "$dir/$f")" = "$want" ] || die "$f differs from the manifest"
    done
    sha256_of "$dir/qeminga"
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
    mkdir -p "$IMAGES"
    local free_kib
    free_kib="$(df -Pk "$IMAGES" | awk 'NR == 2 { print $4 }')"
    [ "${free_kib:-0}" -ge $((10 * 1024 * 1024)) ] || die "less than 10 GiB free under $IMAGES"
}

cmd_fetch_image() {
    local sha="" dest="" cache=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --sha256) sha="$2"; shift 2 ;;
            --dest) dest="$2"; shift 2 ;;
            --cache) cache="$2"; shift 2 ;;
            --) shift; break ;;
            *) die "fetch-image: unexpected '$1'" ;;
        esac
    done
    [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "fetch-image needs --sha256 HEX"
    [ -n "$dest" ] || die "fetch-image needs --dest PATH"
    [ $# -ge 1 ] || die "fetch-image needs at least one source URL"
    local tmp="$dest.part" cached="" url
    if [ -n "$cache" ]; then
        cached="$cache/$sha"
        if [ -f "$cached" ] && [ "$(sha256_of "$cached")" = "$sha" ]; then
            cp "$cached" "$dest"
            echo "image sha256 $sha (cache)"
            return 0
        fi
    fi
    for url in "$@"; do
        echo "trying $url"
        if ! curl -fsSL --proto '=https,file' --tlsv1.2 --retry 3 --retry-delay 5 -o "$tmp" "$url"; then
            echo "  unavailable"
            continue
        fi
        if [ "$(sha256_of "$tmp")" != "$sha" ]; then
            echo "  digest $(sha256_of "$tmp") is not the pinned one; ignored"
            rm -f "$tmp"
            continue
        fi
        mv "$tmp" "$dest"
        echo "image sha256 $sha (from $url)"
        if [ -n "$cached" ]; then
            { mkdir -p "$cache" && cp "$dest" "$cached"; } || echo "  (could not fill the cache)"
        fi
        return 0
    done
    rm -f "$tmp"
    die "no source has the pinned image $sha"
}

cmd_image_key() {
    [ $# -eq 1 ] || die "usage: image-key ARCH"
    check_arch "$1"
    echo "ubuntu-24.04-$(debian_arch_of "$1")-$IMAGE_RELEASE-$(image_sha_of "$1")"
}

fetch_image() {
    local arch="$1" dest="$2" cache="$3" file url urls=() fetch_args=()
    file="$(image_file_of "$arch")"
    for url in $IMAGE_SOURCES; do urls+=("$url/$file"); done
    say "guest image $file ($IMAGE_RELEASE)"
    fetch_args=(--sha256 "$(image_sha_of "$arch")" --dest "$dest")
    if [ -n "$cache" ]; then
        fetch_args+=(--cache "$cache")
    fi
    cmd_fetch_image "${fetch_args[@]}" -- "${urls[@]}"
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
    [ ! -e "$dir" ] || die "$dir already exists; refusing to reuse another run's files"
    mkdir -m 0700 "$dir"
    fetch_image "$arch" "$dir/root.qcow2" "$cache"
    qemu-img resize -q "$dir/root.qcow2" 8G

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
    genisoimage -quiet -output "$dir/seed.iso" -volid cidata -joliet -rock "$seed"
    genisoimage -quiet -output "$dir/payload.iso" -volid QEMINGAE2E -joliet -rock "$payload"

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
