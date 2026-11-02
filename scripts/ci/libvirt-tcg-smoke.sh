#!/usr/bin/env bash
# libvirt + QEMU TCG smoke lane (#53, AC16) for GitHub-hosted runners.
#
# Hosted runners offer no usable nested virtualisation on arm64 and none
# is relied on for x86-64 either: the guest runs under QEMU's TCG
# accelerator (`<domain type='qemu'>`), on real libvirt, natively on each
# supported architecture. The candidate is the hosted release build of
# the same workflow run (`cargo build --release --locked --features
# seccomp`); this lane never builds qeminga, it installs that candidate
# with the shipped packaging in a disposable Ubuntu 24.04 guest and runs
# scripts/e2e-libvirt.sh against it, then shuts the guest down through
# the agent. Evidence is a versioned result.json plus the transcripts.
# This is smoke evidence on emulated CPUs, never KVM evidence, and its
# suite name (libvirt-tcg-smoke-v1) is not a release-qualifying suite.
#
#   libvirt-tcg-smoke.sh manifest --out DIR --binary PATH --arch ARCH
#       --source-sha SHA --version V --run-id N --run-attempt N --runner R
#   libvirt-tcg-smoke.sh verify-candidate DIR ARCH SHA     # prints the digest
#   libvirt-tcg-smoke.sh domain-xml --arch ARCH --name NAME --dir DIR
#       [--vcpus N]                                         # N above 8 -> 8
#   libvirt-tcg-smoke.sh stale-check
#   libvirt-tcg-smoke.sh image-key ARCH                     # cache key
#   libvirt-tcg-smoke.sh fetch-image --sha256 HEX --dest PATH [--cache DIR]
#       -- URL...                                           # first match wins
#   libvirt-tcg-smoke.sh run --arch ARCH --candidate DIR --source-sha SHA
#       --run-id N --run-attempt N --out DIR --expect-sha256 HEX
#       [--image-cache DIR]                                 (root)
#   libvirt-tcg-smoke.sh result --out DIR --arch ARCH --source-sha SHA
#       --binary-sha256 HEX --accelerator ACCEL
#   libvirt-tcg-smoke.sh cleanup --arch ARCH --run-id N --run-attempt N
#       [--out DIR]                                         (root)
#
# Every libvirt resource is named qeminga-e2e-<run id>-<attempt>-<arch>
# and lives in $QEMINGA_E2E_IMAGES/<that name>/ (default
# /var/lib/libvirt/images; a plain absolute path, since it is written into
# the domain XML unescaped); cleanup touches nothing else, and keeps the
# disks while the domain's state cannot be established. Timeouts are
# explicit and bounded (QEMINGA_E2E_BOOT_TIMEOUT_SECS, default 1800, for
# boot plus install under emulation; QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS,
# default 300). tests/libvirt_tcg_smoke.rs covers the parts that run
# without a hypervisor.
set -euo pipefail

export LC_ALL=C LANG=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

SOURCE_REPOSITORY="vicaya/qeminga"
BUILD_COMMAND="cargo build --release --locked --features seccomp"
SUITE="libvirt-tcg-smoke-v1"
MANDATORY_TESTS="production_install accelerator_tcg libvirt_interop agent_shutdown"
PACKAGING_FILES="packaging/systemd/qeminga.service packaging/udev/99-qeminga.rules packaging/sysusers.d/qeminga.conf packaging/tmpfiles.d/qeminga.conf packaging/config.toml"
CONNECT="--connect=qemu:///system"
IMAGES="${QEMINGA_E2E_IMAGES:-/var/lib/libvirt/images}"

# Guest image pin: Ubuntu 24.04 server cloud image, one dated release,
# verified by SHA-256 before every use, so where the bytes come from does
# not matter: the run's cache first, then cloud-images.ubuntu.com, then
# the archive host Canonical moves pruned serials to (both of its layouts
# are tried; a wrong guess is a 404). Bump the date and both digests
# together.
IMAGE_RELEASE="release-20261017"
IMAGE_SOURCES="https://cloud-images.ubuntu.com/releases/24.04/$IMAGE_RELEASE
https://cloud-images-archive.ubuntu.com/releases/noble/$IMAGE_RELEASE
https://cloud-images-archive.ubuntu.com/releases/24.04/$IMAGE_RELEASE"
# shellcheck disable=SC2034 # read through image_sha_of
IMAGE_SHA256_x86_64="04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94"
# shellcheck disable=SC2034 # read through image_sha_of
IMAGE_SHA256_aarch64="50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e"

NO_DIGEST="$(printf '0%.0s' {1..64})"

AAVMF_CODE=/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd
AAVMF_VARS=/usr/share/AAVMF/AAVMF_VARS.fd

die() { echo "libvirt-tcg-smoke: $*" >&2; exit 1; }
say() { echo "== $*"; }

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

# The run directory (and the images root) go into the domain XML as
# literal text: accept only characters that need no escaping there.
check_path() {
    [[ "$2" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "$1 must be an absolute path of [A-Za-z0-9._/-] only: '$2'"
}

machine_of() { case "$1" in x86_64) echo q35 ;; aarch64) echo virt ;; esac; }
debian_arch_of() { case "$1" in x86_64) echo amd64 ;; aarch64) echo arm64 ;; esac; }
image_sha_of() { local v="IMAGE_SHA256_$1"; echo "${!v}"; }
image_file_of() { echo "ubuntu-24.04-server-cloudimg-$(debian_arch_of "$1").img"; }
domain_name() { echo "qeminga-e2e-$1-$2-$3"; }

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

# Parses `--key value` pairs into opt_<key> variables (dashes become
# underscores). Unknown keys are refused by the caller's checks.
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

# The candidate is what the manifest says, for the source and architecture
# this lane was asked to test; prints the binary's digest.
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
    # Validated before the cap: `run` passes nproc, which can be any size.
    [[ "$vcpus" =~ ^[1-9][0-9]{0,8}$ ]] || die "--vcpus must be a positive whole number: '$vcpus'"
    # Multi-threaded TCG runs one host thread per vCPU; more than eight
    # buys nothing on a hosted runner.
    [ "$vcpus" -le 8 ] || vcpus=8
    local machine os cpu
    machine="$(machine_of "$arch")"
    case "$arch" in
        x86_64)
            os="    <type arch='x86_64' machine='$machine'>hvm</type>"
            # qemu64 boots this guest faster under TCG than `max`, whose
            # extra emulated features cost more than they save (measured:
            # 181 s against 219 s to an installed agent, 4 vCPUs).
            cpu="  <cpu mode='custom' match='exact' check='none'><model fallback='forbid'>qemu64</model></cpu>"
            ;;
        aarch64)
            # UEFI firmware from qemu-efi-aarch64; a fixed AArch64 model
            # (the `max` model's QARMA pointer authentication is slow
            # under TCG).
            os="    <type arch='aarch64' machine='$machine'>hvm</type>
    <loader readonly='yes' type='pflash'>$AAVMF_CODE</loader>
    <nvram template='$AAVMF_VARS'>$dir/VARS.fd</nvram>"
            cpu="  <cpu mode='custom' match='exact' check='none'><model fallback='forbid'>cortex-a57</model></cpu>"
            ;;
    esac
    cat <<EOF
<domain type='qemu'>
  <name>$name</name>
  <memory unit='MiB'>2048</memory>
  <vcpu>$vcpus</vcpu>
  <os>
$os
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
  </features>
$cpu
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
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
      <rom enabled='no'/>
    </interface>
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

# A failed listing is not evidence that no test domain exists.
cmd_stale_check() {
    local names
    names="$(v list --all --name)" || die "cannot list libvirt domains; refusing to proceed on an unknown host state"
    local stale
    stale="$(printf '%s\n' "$names" | grep -E '^qeminga-e2e-' || true)"
    if [ -n "$stale" ]; then
        echo "libvirt-tcg-smoke: stale qeminga test domain(s) on this host:" >&2
        printf '  %s\n' "$stale" >&2
        echo "inspect them with 'virsh $CONNECT dominfo NAME', then remove each with" >&2
        echo "'$0 cleanup --arch ARCH --run-id N --run-attempt N' for its run" >&2
        exit 1
    fi
}

# Prints the domain's state, "absent" when libvirt says it does not exist,
# and fails when neither can be established.
domain_state() {
    local name="$1" out
    if out="$(v domstate "$name" 2>&1)"; then
        printf '%s\n' "$out" | head -n 1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        return 0
    fi
    case "$out" in
        *"failed to get domain"* | *"Domain not found"*)
            # Confirm with a listing that itself succeeded.
            local names
            names="$(v list --all --name)" || return 1
            if printf '%s\n' "$names" | grep -qx -- "$name"; then return 1; fi
            echo absent
            ;;
        *) echo "$out" >&2; return 1 ;;
    esac
}

collect_diagnostics() {
    local name="$1" dir="$2" out="$3"
    mkdir -p "$out"
    v dumpxml "$name" >"$out/domain.xml" 2>/dev/null || true
    if [ -f "/var/log/libvirt/qemu/$name.log" ]; then cp "/var/log/libvirt/qemu/$name.log" "$out/qemu.log" || true; fi
    if [ -f "$dir/serial.log" ]; then cp "$dir/serial.log" "$out/serial.log" || true; fi
    chmod -R a+rX "$out" 2>/dev/null || true
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
    # A run that failed before libvirt was installed (artifact download,
    # apt) has neither a domain nor files: nothing to clean, and no second
    # red step. Files without a libvirt to ask about their domain are kept.
    if ! command -v virsh >/dev/null 2>&1; then
        [ ! -e "$dir" ] || die "virsh is not installed, so the state of $name cannot be established; keeping $dir"
        local note="nothing to clean up: libvirt is not installed and $dir does not exist"
        echo "$note"
        # The evidence directory still exists afterwards, saying why it is
        # nearly empty, so the always() upload has something to upload.
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
        v undefine --nvram "$name" || die "cannot undefine $name; keeping $dir"
        state="$(domain_state "$name")" || die "cannot confirm $name is gone; keeping $dir"
        [ "$state" = absent ] || die "$name is still defined; keeping $dir"
    fi
    if [ -d "$dir" ]; then
        rm -rf -- "$dir"
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
    [ "$accel" = tcg ] || overall=fail
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
    say "preflight ($arch, TCG; /dev/kvm is neither probed nor used)"
    [ "$(uname -m)" = "$arch" ] || die "this host is $(uname -m), not $arch"
    [ "$(id -u)" = 0 ] || die "run as root (libvirt system instance, image directory)"
    local tool
    for tool in virsh qemu-img genisoimage jq curl sha256sum "qemu-system-$arch"; do
        command -v "$tool" >/dev/null || die "missing tool: $tool"
    done
    if [ "$arch" = aarch64 ]; then
        { [ -f "$AAVMF_CODE" ] && [ -f "$AAVMF_VARS" ]; } || die "missing AArch64 UEFI firmware (qemu-efi-aarch64)"
    fi
    v version
    v domcapabilities --virttype qemu --arch "$arch" --machine "$(machine_of "$arch")" >/dev/null \
        || die "libvirt cannot run a TCG $arch $(machine_of "$arch") guest here"
    if ! grep -qE '^Active:[[:space:]]+yes' <<<"$(v net-info default)"; then
        v net-start default || die "libvirt network 'default' is not active and cannot be started"
    fi
    cmd_stale_check
    mkdir -p "$IMAGES"
    local free_kib
    free_kib="$(df -Pk "$IMAGES" | awk 'NR == 2 { print $4 }')"
    [ "${free_kib:-0}" -ge $((10 * 1024 * 1024)) ] || die "less than 10 GiB free under $IMAGES"
}

# The first of the cache and the sources whose bytes have the expected
# digest becomes DEST (and fills the cache); nothing else is ever used.
# A partial or rejected download stays in DEST.part, inside the run's
# directory, which cleanup removes.
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
        if ! curl -fsSL --retry 3 --retry-delay 5 -o "$tmp" "$url"; then
            echo "  unavailable"
            continue
        fi
        if [ "$(sha256_of "$tmp")" != "$sha" ]; then
            echo "  digest $(sha256_of "$tmp") is not the pinned one; ignored"
            continue
        fi
        mv "$tmp" "$dest"
        echo "image sha256 $sha (from $url)"
        if [ -n "$cached" ]; then
            { mkdir -p "$cache" && cp "$dest" "$cached"; } || echo "  (could not fill the cache)"
        fi
        return 0
    done
    die "no source has the pinned image $sha"
}

cmd_image_key() {
    [ $# -eq 1 ] || die "usage: image-key ARCH"
    check_arch "$1"
    echo "ubuntu-24.04-$(debian_arch_of "$1")-$IMAGE_RELEASE-$(image_sha_of "$1")"
}

fetch_image() {
    local arch="$1" dest="$2" cache="$3" file url urls=()
    file="$(image_file_of "$arch")"
    for url in $IMAGE_SOURCES; do urls+=("$url/$file"); done
    say "guest image $file ($IMAGE_RELEASE)"
    cmd_fetch_image --sha256 "$(image_sha_of "$arch")" --dest "$dest" \
        ${cache:+--cache "$cache"} -- "${urls[@]}"
}

# Polls the serial log for the guest-side verdict; fails early when the
# domain stops.
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
        if [ $((now - last)) -ge 60 ]; then
            last="$now"
            echo "[$((now - start))s] $( [ -f "$log" ] && tail -c 2000 "$log" | tr -d '\r' | grep -v '^[[:space:]]*$' | tail -n 1 || echo 'no console output yet')"
        fi
        sleep 10
    done
}

agent() { v qemu-agent-command "$1" "$2"; }

prove_tcg() {
    local name="$1" info qemu_log="/var/log/libvirt/qemu/$1.log"
    grep -q "<domain type='qemu'" <<<"$(v dumpxml "$name")" || { echo "domain is not type='qemu'"; return 1; }
    info="$(v qemu-monitor-command "$name" --hmp 'info kvm' | tr -d '\r')" || return 1
    echo "info kvm: $info"
    case "$info" in
        *"kvm support: disabled"* | *"kvm support: not compiled"*) ;;
        *) echo "KVM is in use"; return 1 ;;
    esac
    grep -q -- '-accel tcg' "$qemu_log" || { echo "no '-accel tcg' on the QEMU command line"; return 1; }
    if grep -qE -- '-accel kvm|accel=kvm' "$qemu_log"; then echo "KVM on the QEMU command line"; return 1; fi
    # Multi-threaded TCG (one "CPU n/TCG" thread per vCPU) is QEMU's
    # default for these guest/host pairs; libvirt has no knob for it, so
    # it is observed and reported, not configured.
    local pid threads
    pid="$(cat "/run/libvirt/qemu/$name.pid" 2>/dev/null)" || true
    if [ -n "$pid" ]; then
        threads="$(cat "/proc/$pid/task/"*/comm 2>/dev/null | grep -cE '^CPU [0-9]+/TCG$' || true)"
        if grep -qx 'ALL CPUs/TCG' "/proc/$pid/task/"*/comm 2>/dev/null; then
            echo "TCG threading: single (one thread for all vCPUs)"
        else
            echo "TCG threading: multi ($threads vCPU threads)"
        fi
    fi
}

cmd_run() {
    parse_opts "$@"
    local arch candidate sha run_id attempt expect cache
    arch="$(need arch)"; candidate="$(need candidate)"; sha="$(need source_sha)"
    run_id="$(need run_id)"; attempt="$(need run_attempt)"; OUT="$(need out)"
    # Required and non-empty: an empty value (a renamed step or output key
    # in the workflow) must not quietly skip the anchor.
    expect="$(need expect_sha256)"; cache="${opt_image_cache:-}"
    check_arch "$arch"; check_sha "$sha"
    check_number --run-id "$run_id"; check_number --run-attempt "$attempt"
    [[ "$expect" =~ ^[0-9a-f]{64}$ ]] || die "--expect-sha256 must be 64 hex digits: '$expect'"
    check_path QEMINGA_E2E_IMAGES "$IMAGES"
    local boot_timeout="${QEMINGA_E2E_BOOT_TIMEOUT_SECS:-1800}"
    local shutdown_timeout="${QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS:-300}"
    check_number QEMINGA_E2E_BOOT_TIMEOUT_SECS "$boot_timeout"
    check_number QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS "$shutdown_timeout"

    mkdir -p "$OUT/tests"
    rm -f "$OUT"/tests/* "$OUT/result.json"
    # Globals: the EXIT trap below runs after this function has returned.
    RUN_ARCH="$arch" RUN_SHA="$sha" RUN_DIGEST="$NO_DIGEST" RUN_ACCEL=unknown
    RUN_NAME="$(domain_name "$run_id" "$attempt" "$arch")"
    check_name "$RUN_NAME"
    RUN_DIR="$IMAGES/$RUN_NAME"
    local name="$RUN_NAME" dir="$RUN_DIR" digest

    # Whatever happens below, the result and the diagnostics are written.
    # shellcheck disable=SC2154 # rc is assigned inside the trap
    trap 'rc=$?; collect_diagnostics "$RUN_NAME" "$RUN_DIR" "$OUT"; write_result "$OUT" "$RUN_ARCH" "$RUN_SHA" "$RUN_DIGEST" "$RUN_ACCEL" || rc=1; chmod -R a+rX "$OUT"; exit $rc' EXIT

    preflight "$arch"
    {
        echo "runner kernel: $(uname -srm)"
        v version
        "qemu-system-$arch" --version | head -n 1
    } >"$OUT/versions.txt" 2>&1
    cat "$OUT/versions.txt"

    say "candidate"
    # The manifest travels in the same artifact as the binary, so checking
    # one against the other proves consistency only. The anchor is the
    # digest the build job reported as a job output (--expect-sha256),
    # which replacing the artifact does not change.
    digest="$(cmd_verify_candidate "$candidate" "$arch" "$sha")"
    RUN_DIGEST="$digest"
    echo "candidate sha256 $digest (manifest consistent)"
    [ "$digest" = "$expect" ] || die "candidate binary $digest is not the one the build job reported ($expect)"
    echo "candidate sha256 matches the build job's reported digest"
    local version
    version="$(jq -er .version "$candidate/manifest.json")"

    say "disposable guest $name in $dir"
    [ ! -e "$dir" ] || die "$dir already exists; refusing to reuse another run's files"
    mkdir -m 0755 "$dir"
    fetch_image "$arch" "$dir/root.qcow2" "$cache"
    qemu-img resize -q "$dir/root.qcow2" 8G

    local seed="$dir/seed" payload="$dir/payload"
    mkdir -p "$seed" "$payload/packaging"
    printf 'instance-id: %s\nlocal-hostname: qeminga-e2e\n' "$name" >"$seed/meta-data"
    cat >"$seed/user-data" <<'EOF'
#cloud-config
# qeminga TCG smoke guest: no network packages, no login; the payload
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

    # As many vCPUs as the runner has CPUs; domain-xml caps them at 8.
    cmd_domain_xml --arch "$arch" --name "$name" --dir "$dir" --vcpus "$(nproc)" >"$dir/domain.xml"
    v define "$dir/domain.xml"
    v start "$name"

    say "accelerator"
    if prove_tcg "$name"; then RUN_ACCEL=tcg; mark accelerator_tcg pass; else mark accelerator_tcg fail; fi

    say "boot and install under TCG (up to ${boot_timeout}s)"
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
    if bash "$REPO/scripts/e2e-libvirt.sh" --connect qemu:///system --no-shutdown "$name" 2>&1 | tee "$OUT/e2e-libvirt.log"; then
        mark libvirt_interop pass
    else
        mark libvirt_interop fail
    fi

    say "virsh shutdown --mode agent (up to ${shutdown_timeout}s)"
    local stopped=fail i
    if v shutdown "$name" --mode agent; then
        for ((i = 0; i < shutdown_timeout; i += 5)); do
            if [ "$(domain_state "$name" 2>/dev/null || true)" = "shut off" ]; then
                stopped=pass
                break
            fi
            sleep 5
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
