#!/usr/bin/env bash
# Secure-by-default GitHub Actions self-hosted runner setup for qeminga
# libvirt + KVM end-to-end testing on x86_64 and aarch64 (arm64) Linux servers.
#
# Designed so community members can safely donate x86_64 or arm64 KVM hosts:
#   - Dedicated locked service account (qeminga-runner): no login shell, no
#     sudo, no docker/libvirt/adm group; only supplementary group `kvm`.
#   - Unprivileged per-user libvirt (qemu:///session) with user-mode networking
#     (libslirp): zero root privileges, zero host bridges, completely isolated
#     from any qemu:///system VMs on the donor's machine.
#   - Kernel-enforced systemd sandboxing: NoNewPrivileges=yes, empty
#     CapabilityBoundingSet=, ProtectSystem=strict, ProtectHome=yes,
#     PrivateTmp=yes, ProtectProc=invisible, DevicePolicy=closed +
#     DeviceAllow=/dev/kvm rw, RestrictNamespaces=yes, RemoveIPC=yes,
#     SystemCallArchitectures=native, SystemCallFilter=@system-service, UMask=0077,
#     MemoryMax=80%, TasksMax=512, and cgroup IPAddressDeny blocking cloud
#     instance metadata (169.254.0.0/16, fe80::/10, fd00:ec2::254/128) and
#     private RFC1918/CGNAT/ULA LANs.
#   - Host-enforced root-owned runner hooks (ACTIONS_RUNNER_HOOK_JOB_STARTED /
#     COMPLETED) configured via systemd Environment= (never runner-writable):
#     exact whole-string allowlists for repository, event (workflow_dispatch by
#     default; pull_request and pull_request_target unconditionally refused),
#     ref, workflow, and optional actor; stale-domain check before each job and
#     automatic workspace + stray-domain scrub after every job.
#   - Pinned GitHub actions/runner archive verified by SHA-256 for both x64 and
#     arm64 before extraction; runner binaries stay kernel-read-only by default
#     (--disableupdate); registration tokens are never accepted on the CLI.
#
# Usage:
#   scripts/setup-kvm-runner.sh preflight [OPTIONS]
#   sudo scripts/setup-kvm-runner.sh install --repo https://github.com/OWNER/REPO [OPTIONS]
#   scripts/setup-kvm-runner.sh render-unit --repo https://github.com/OWNER/REPO [OPTIONS]
#   scripts/setup-kvm-runner.sh render-hooks --repo https://github.com/OWNER/REPO --out DIR [OPTIONS]
#   scripts/setup-kvm-runner.sh fetch-runner --arch ARCH --dest FILE [--version V --sha256 HEX] [--url URL]
#   scripts/setup-kvm-runner.sh status [OPTIONS]
#   sudo scripts/setup-kvm-runner.sh update [--version V --sha256 HEX] [OPTIONS]
#   sudo scripts/setup-kvm-runner.sh uninstall [--token-file PATH] [--purge-user] [OPTIONS]
#
# Run `<script> --help` for the full list of options.
set -euo pipefail

export LC_ALL=C LANG=C

# Pinned official GitHub actions/runner release and SHA-256 digests from
# https://github.com/actions/runner/releases/tag/v2.338.2
RUNNER_VERSION_DEFAULT="2.338.2"
# shellcheck disable=SC2034 # read via indirect expansion in pinned_runner_sha256
RUNNER_SHA256_x86_64="baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40"
# shellcheck disable=SC2034 # read via indirect expansion in pinned_runner_sha256
RUNNER_SHA256_aarch64="670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945"

DEFAULT_USER="qeminga-runner"
DEFAULT_SERVICE="qeminga-kvm-runner"
DEFAULT_INSTALL_DIR="/opt/qeminga-runner"
DEFAULT_STATE_DIR="/var/lib/qeminga-runner"
DEFAULT_HOOK_DIR="/usr/local/libexec/qeminga-runner"
DEFAULT_CONFIG_DIR="/etc/qeminga-runner"
DEFAULT_LABELS="qeminga-kvm"
DEFAULT_EVENT="workflow_dispatch"
DEFAULT_REF="refs/heads/main"
DEFAULT_WORKFLOW=".github/workflows/libvirt-kvm.yml"
DEFAULT_MEMORY_MAX="80%"
DEFAULT_TASKS_MAX="512"

die() { echo "setup-kvm-runner: $*" >&2; exit 1; }
say() { echo "== $*"; }
warn() { echo "warning: $*" >&2; }

usage() {
    cat <<'EOF'
Usage: scripts/setup-kvm-runner.sh <subcommand> [options]

Subcommands:
  preflight     Read-only host check (arch, /dev/kvm, libvirt/QEMU, AAVMF on arm64, RAM/disk, DNS)
  install       Install packages, create locked user, verify & register runner, install hardened unit
  render-unit   Print the hardened systemd unit to stdout without modifying the host
  render-hooks  Write hook-job-started.sh, hook-job-completed.sh, and policy.env into --out DIR
  fetch-runner  Download and SHA-256 verify the pinned actions/runner tarball for x86_64 or aarch64
  status        Show service status, systemd security score, KVM state, and active policy
  update        Stop service, replace actions/runner with a SHA-256-verified archive, restart
  uninstall     Stop & remove service, clean stray qeminga domains, optionally deregister & purge user

Common options:
  --repo URL             GitHub repository URL (https://github.com/OWNER/REPO)
  --arch ARCH            x86_64 (or amd64/x64) or aarch64 (or arm64); defaults to uname -m
  --name NAME            Runner name (default: qeminga-kvm-<arch>-<host>)
  --labels LIST          Comma-separated extra labels (default: qeminga-kvm)
  --user USER            Dedicated service user (default: qeminga-runner; root refused)
  --service NAME         Systemd service base name (default: qeminga-kvm-runner)
  --install-dir DIR      Runner binaries directory (default: /opt/qeminga-runner)
  --state-dir DIR        Runner work/images/cache directory (default: /var/lib/qeminga-runner)
  --hook-dir DIR         Root-owned hook scripts directory (default: /usr/local/libexec/qeminga-runner)
  --config-dir DIR       Root-owned policy directory (default: /etc/qeminga-runner)

Registration credentials (never pass --token on the CLI):
  --token-file PATH      Read registration/removal token from mode-0600 file, or '-' for stdin
  --jitconfig-file PATH  One-shot ephemeral GitHub JIT config file (mode 0600) or '-' for stdin
  (If omitted during install on a TTY, prompts with hidden input; or set QEMINGA_RUNNER_TOKEN.)

Runner binary pinning:
  --runner-version VER   actions/runner version (default: 2.338.2)
  --runner-sha256 HEX    Required whenever --runner-version differs from the pinned default
  --allow-auto-update    Opt in to GitHub self-updates (default: --disableupdate, read-only binaries)
  --ephemeral            Register for a single job only (Restart=no, auto-deregisters on exit)

Host-side job admission policy (enforced before any workflow step runs):
  --allow-event EVENT    Repeatable; default: workflow_dispatch (pull_request* always refused)
  --allow-ref REF        Repeatable exact ref; default: refs/heads/main (no wildcards)
  --allow-workflow PATH  Repeatable workflow path; default: .github/workflows/libvirt-kvm.yml
  --allow-actor LOGIN    Repeatable exact GitHub actor allowlist (optional)

Hardening & resource bounds:
  --memory-max LIMIT     Systemd MemoryMax (default: 80%; percentage 1-95% or size like 6G)
  --tasks-max N          Systemd TasksMax (default: 512)
  --cpu-quota QUOTA      Optional systemd CPUQuota (e.g. 200%)
  --allow-ip CIDR        Repeatable IPAddressAllow CIDR (e.g. private DNS; IMDS and 0.0.0.0/0 refused)
  --no-lan-deny          Do not deny RFC1918/CGNAT/ULA (IPv4 & IPv6 cloud IMDS are STILL denied)
  --skip-packages        Skip apt-get/dnf package installation during install
  --no-start             Do not enable/start the systemd service at the end of install
  --purge-user           (uninstall only) Also remove the dedicated service user and group
EOF
}

# ---- validation helpers ---------------------------------------------------

normalize_arch() {
    case "$1" in
        x86_64 | amd64 | x64) echo "x86_64" ;;
        aarch64 | arm64) echo "aarch64" ;;
        *) die "unsupported architecture '$1' (expected x86_64 or aarch64/arm64)" ;;
    esac
}

gh_runner_arch_of() {
    case "$1" in
        x86_64) echo "x64" ;;
        aarch64) echo "arm64" ;;
        *) die "unsupported architecture '$1'" ;;
    esac
}

machine_of() {
    case "$1" in
        x86_64) echo "q35" ;;
        aarch64) echo "virt" ;;
        *) die "unsupported architecture '$1'" ;;
    esac
}

pinned_runner_sha256() {
    local arch="$1" v="RUNNER_SHA256_$1"
    echo "${!v}"
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

check_sha256() {
    [[ "$2" =~ ^[0-9a-f]{64}$ ]] || die "$1 must be 64 lowercase hex digits: '$2'"
}

check_version() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid runner version '$1' (expected X.Y.Z)"
}

check_abs_path() {
    local label="$1" p="$2"
    [[ "$p" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "$label must be a plain absolute path of [A-Za-z0-9._/-]: '$p'"
    [ "$p" != "/" ] || die "$label must not be '/'"
    case "$p" in
        */../* | */.. | */./* | */. | *//*) die "$label must not contain dot segments or '//': '$p'" ;;
    esac
}

check_repo_url() {
    local url="${1%/}"
    [[ "$url" =~ ^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] \
        || die "--repo must be an HTTPS GitHub repository URL (https://github.com/OWNER/REPO): '$1'"
    case "$url" in
        *.git) die "--repo must not end in .git: '$1'" ;;
        */../* | */.. | */./* | */.) die "--repo must not contain dot segments: '$1'" ;;
    esac
    echo "$url"
}

repo_slug_of() {
    local url="$1"
    echo "${url#https://github.com/}"
}

check_user_name() {
    local u="$1"
    [ "$u" != "root" ] || die "refusing --user root; the runner must run as an unprivileged dedicated account"
    [[ "$u" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid --user '$u'"
}

check_service_name() {
    [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid --service '$1'"
}

check_runner_name() {
    [[ "$1" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "invalid --name '$1' (1-64 chars of [A-Za-z0-9._-])"
}

check_labels() {
    [[ "$1" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]] || die "invalid --labels '$1'"
}

check_event() {
    case "$1" in
        pull_request | pull_request_target | issue_comment | discussion | fork)
            die "refusing untrusted event '$1': self-hosted runners on public repositories must never run untrusted pull request or comment workflows"
            ;;
        workflow_dispatch | push | schedule | release | repository_dispatch | workflow_call)
            ;;
        *)
            die "unsupported or unsafe --allow-event '$1' (allowed: workflow_dispatch, push, schedule, release, repository_dispatch, workflow_call)"
            ;;
    esac
}

check_ref() {
    local r="$1"
    [[ "$r" =~ ^refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] \
        || die "--allow-ref must be an exact refs/heads/... or refs/tags/... ref (no wildcards): '$r'"
    case "$r" in
        */../* | */.. | *//* | *\**) die "--allow-ref must not contain '..', '//', or wildcards: '$r'" ;;
    esac
}

check_workflow() {
    local w="$1"
    [[ "$w" =~ ^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$ ]] \
        || die "--allow-workflow must be an exact .github/workflows/<name>.yml path (no wildcards): '$w'"
    case "$w" in
        *..* | *\**) die "--allow-workflow must not contain '..' or wildcards: '$w'" ;;
    esac
}

check_actor() {
    local a="$1"
    [[ "$a" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?(\[bot\])?$ ]] \
        || die "invalid --allow-actor '$a'"
}

check_memory_max() {
    local m="$1"
    if [[ "$m" =~ ^([1-9][0-9]*)%$ ]]; then
        local pct="${BASH_REMATCH[1]}"
        if [ "$pct" -lt 1 ] || [ "$pct" -gt 95 ]; then
            die "--memory-max percentage must be between 1% and 95%: '$m'"
        fi
    elif [[ "$m" =~ ^[1-9][0-9]*[KMGTP]$ ]]; then
        :
    else
        die "invalid --memory-max '$m' (expected e.g. 80% or 4G)"
    fi
}

check_tasks_max() {
    [[ "$1" =~ ^[1-9][0-9]{1,5}$ ]] || die "invalid --tasks-max '$1' (expected integer 10..999999)"
}

check_cpu_quota() {
    [[ "$1" =~ ^[1-9][0-9]*%$ ]] || die "invalid --cpu-quota '$1' (expected positive percentage like 200%)"
}

check_allow_ip() {
    local cidr="$1"
    # Reject anything with whitespace, newlines, wildcards, or magic keywords.
    [[ "$cidr" =~ ^[0-9A-Fa-f.:/]+$ ]] || die "invalid --allow-ip '$cidr'"
    # Refuse default routes, IPv4-mapped IPv6, and cloud IMDS / link-local ranges unconditionally.
    case "${cidr,,}" in
        0.0.0.0 | 0.0.0.0/* | :: | ::/0 | 169.254.* | fe8* | fe9* | fea* | feb* | fd00:ec2:* | fd00:0ec2:* | ::ffff:*)
            die "refusing --allow-ip '$cidr': cloud metadata (IMDS), link-local, IPv4-mapped IPv6, and default routes cannot be allow-listed"
            ;;
    esac
    if [[ "$cidr" == *.* ]]; then
        local ip="${cidr%%/*}" prefix="32"
        [[ "$cidr" == */* ]] && prefix="${cidr#*/}"
        [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] \
            || die "invalid IPv4 --allow-ip '$cidr'"
        local a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}" c="${BASH_REMATCH[3]}" d="${BASH_REMATCH[4]}"
        local o
        for o in "$a" "$b" "$c" "$d"; do
            [ "$((10#$o))" -le 255 ] || die "invalid IPv4 octet in --allow-ip '$cidr'"
        done
        if ! [[ "$prefix" =~ ^[1-9][0-9]?$ ]] || [ "$prefix" -lt 8 ] || [ "$prefix" -gt 32 ]; then
            die "invalid IPv4 prefix in --allow-ip '$cidr' (must be 8..32)"
        fi
        # Block any IPv4 address or supernet overlapping 169.254.0.0/16 (link-local / cloud IMDS).
        local ip_int imds_net min_p mask
        ip_int=$(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
        imds_net=$(( (169 << 24) | (254 << 16) ))
        min_p="$prefix"
        [ "$min_p" -le 16 ] || min_p=16
        mask=$(( (0xFFFFFFFF << (32 - min_p)) & 0xFFFFFFFF ))
        if [ "$((ip_int & mask))" -eq "$((imds_net & mask))" ]; then
            die "refusing --allow-ip '$cidr': overlaps link-local / cloud metadata range 169.254.0.0/16"
        fi
    elif [[ "$cidr" == *:* ]]; then
        local prefix="128"
        [[ "$cidr" == */* ]] && prefix="${cidr#*/}"
        if ! [[ "$prefix" =~ ^[1-9][0-9]{0,2}$ ]] || [ "$prefix" -lt 32 ] || [ "$prefix" -gt 128 ]; then
            die "invalid IPv6 prefix in --allow-ip '$cidr' (must be 32..128)"
        fi
    else
        die "invalid --allow-ip '$cidr'"
    fi
}

# Locate AArch64 UEFI firmware (Debian/Ubuntu qemu-efi-aarch64 or Fedora/RHEL edk2-aarch64).
find_aavmf() {
    if [ -n "${QEMINGA_AAVMF_CODE:-}" ] || [ -n "${QEMINGA_AAVMF_VARS:-}" ]; then
        if [ -f "${QEMINGA_AAVMF_CODE:-}" ] && [ -f "${QEMINGA_AAVMF_VARS:-}" ]; then
            echo "${QEMINGA_AAVMF_CODE}:${QEMINGA_AAVMF_VARS}"
            return 0
        fi
        return 1
    fi
    local pair code vars
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
    return 1
}

read_secret_file() {
    local label="$1" path="$2" val
    if [ "$path" = "-" ]; then
        IFS= read -r val || true
    else
        [ -e "$path" ] || die "$label '$path' does not exist"
        [ -r "$path" ] || die "$label '$path' is not readable"
        if [ -f "$path" ]; then
            local mode
            mode="$(stat -L -c '%a' "$path")"
            if [ "$((8#$mode & 077))" -ne 0 ]; then
                die "$label '$path' has mode $mode; refuse group/world-accessible secret file (run: chmod 600 '$path')"
            fi
        fi
        IFS= read -r val <"$path" || true
    fi
    val="${val//$'\r'/}"
    [ -n "$val" ] || die "$label is empty"
    [[ ! "$val" =~ [[:space:]] ]] || die "$label must not contain whitespace"
    printf '%s' "$val"
}

# ---- option parsing -------------------------------------------------------

OPT_REPO=""
OPT_ARCH=""
OPT_NAME=""
OPT_LABELS="$DEFAULT_LABELS"
OPT_USER="$DEFAULT_USER"
OPT_SERVICE="$DEFAULT_SERVICE"
OPT_INSTALL_DIR="$DEFAULT_INSTALL_DIR"
OPT_STATE_DIR="$DEFAULT_STATE_DIR"
OPT_HOOK_DIR="$DEFAULT_HOOK_DIR"
OPT_CONFIG_DIR="$DEFAULT_CONFIG_DIR"
OPT_TOKEN_FILE=""
OPT_JITCONFIG_FILE=""
OPT_RUNNER_VERSION="$RUNNER_VERSION_DEFAULT"
OPT_RUNNER_SHA256=""
OPT_ALLOW_AUTO_UPDATE=0
OPT_EPHEMERAL=0
OPT_MEMORY_MAX="$DEFAULT_MEMORY_MAX"
OPT_TASKS_MAX="$DEFAULT_TASKS_MAX"
OPT_CPU_QUOTA=""
OPT_NO_LAN_DENY=0
OPT_SKIP_PACKAGES=0
OPT_NO_START=0
OPT_PURGE_USER=0
OPT_OUT=""
OPT_DEST=""
OPT_URL=""
OPT_ALLOW_EVENTS=()
OPT_ALLOW_REFS=()
OPT_ALLOW_WORKFLOWS=()
OPT_ALLOW_ACTORS=()
OPT_ALLOW_IPS=()

parse_common_opts() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --token | --token=* | --jitconfig | --jitconfig=*)
                die "refusing ${1%%=*} on the command line (visible in ps and shell history); use interactive prompt, --token-file PATH (mode 0600), --token-file - (stdin), --jitconfig-file PATH, or QEMINGA_RUNNER_TOKEN"
                ;;
            --repo) [ $# -ge 2 ] || die "--repo needs a value"; OPT_REPO="$(check_repo_url "$2")"; shift 2 ;;
            --arch) [ $# -ge 2 ] || die "--arch needs a value"; OPT_ARCH="$(normalize_arch "$2")"; shift 2 ;;
            --name) [ $# -ge 2 ] || die "--name needs a value"; check_runner_name "$2"; OPT_NAME="$2"; shift 2 ;;
            --labels) [ $# -ge 2 ] || die "--labels needs a value"; check_labels "$2"; OPT_LABELS="$2"; shift 2 ;;
            --user) [ $# -ge 2 ] || die "--user needs a value"; check_user_name "$2"; OPT_USER="$2"; shift 2 ;;
            --service) [ $# -ge 2 ] || die "--service needs a value"; check_service_name "$2"; OPT_SERVICE="$2"; shift 2 ;;
            --install-dir) [ $# -ge 2 ] || die "--install-dir needs a value"; check_abs_path --install-dir "$2"; OPT_INSTALL_DIR="${2%/}"; shift 2 ;;
            --state-dir) [ $# -ge 2 ] || die "--state-dir needs a value"; check_abs_path --state-dir "$2"; OPT_STATE_DIR="${2%/}"; shift 2 ;;
            --hook-dir) [ $# -ge 2 ] || die "--hook-dir needs a value"; check_abs_path --hook-dir "$2"; OPT_HOOK_DIR="${2%/}"; shift 2 ;;
            --config-dir) [ $# -ge 2 ] || die "--config-dir needs a value"; check_abs_path --config-dir "$2"; OPT_CONFIG_DIR="${2%/}"; shift 2 ;;
            --token-file) [ $# -ge 2 ] || die "--token-file needs a value"; OPT_TOKEN_FILE="$2"; shift 2 ;;
            --jitconfig-file) [ $# -ge 2 ] || die "--jitconfig-file needs a value"; OPT_JITCONFIG_FILE="$2"; OPT_EPHEMERAL=1; shift 2 ;;
            --runner-version | --version) [ $# -ge 2 ] || die "$1 needs a value"; check_version "$2"; OPT_RUNNER_VERSION="$2"; shift 2 ;;
            --runner-sha256 | --sha256) [ $# -ge 2 ] || die "$1 needs a value"; check_sha256 "$1" "$2"; OPT_RUNNER_SHA256="$2"; shift 2 ;;
            --allow-event) [ $# -ge 2 ] || die "--allow-event needs a value"; check_event "$2"; OPT_ALLOW_EVENTS+=("$2"); shift 2 ;;
            --allow-ref) [ $# -ge 2 ] || die "--allow-ref needs a value"; check_ref "$2"; OPT_ALLOW_REFS+=("$2"); shift 2 ;;
            --allow-workflow) [ $# -ge 2 ] || die "--allow-workflow needs a value"; check_workflow "$2"; OPT_ALLOW_WORKFLOWS+=("$2"); shift 2 ;;
            --allow-actor) [ $# -ge 2 ] || die "--allow-actor needs a value"; check_actor "$2"; OPT_ALLOW_ACTORS+=("$2"); shift 2 ;;
            --allow-ip) [ $# -ge 2 ] || die "--allow-ip needs a value"; check_allow_ip "$2"; OPT_ALLOW_IPS+=("$2"); shift 2 ;;
            --memory-max) [ $# -ge 2 ] || die "--memory-max needs a value"; check_memory_max "$2"; OPT_MEMORY_MAX="$2"; shift 2 ;;
            --tasks-max) [ $# -ge 2 ] || die "--tasks-max needs a value"; check_tasks_max "$2"; OPT_TASKS_MAX="$2"; shift 2 ;;
            --cpu-quota) [ $# -ge 2 ] || die "--cpu-quota needs a value"; check_cpu_quota "$2"; OPT_CPU_QUOTA="$2"; shift 2 ;;
            --out) [ $# -ge 2 ] || die "--out needs a value"; OPT_OUT="$2"; shift 2 ;;
            --dest) [ $# -ge 2 ] || die "--dest needs a value"; OPT_DEST="$2"; shift 2 ;;
            --url) [ $# -ge 2 ] || die "--url needs a value"; OPT_URL="$2"; shift 2 ;;
            --allow-auto-update) OPT_ALLOW_AUTO_UPDATE=1; shift ;;
            --ephemeral) OPT_EPHEMERAL=1; shift ;;
            --no-lan-deny) OPT_NO_LAN_DENY=1; shift ;;
            --skip-packages) OPT_SKIP_PACKAGES=1; shift ;;
            --no-start) OPT_NO_START=1; shift ;;
            --purge-user) OPT_PURGE_USER=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die "unknown option '$1' (run with --help)" ;;
        esac
    done
}

finalize_policy_defaults() {
    [ ${#OPT_ALLOW_EVENTS[@]} -gt 0 ] || OPT_ALLOW_EVENTS=("$DEFAULT_EVENT")
    [ ${#OPT_ALLOW_REFS[@]} -gt 0 ] || OPT_ALLOW_REFS=("$DEFAULT_REF")
    [ ${#OPT_ALLOW_WORKFLOWS[@]} -gt 0 ] || OPT_ALLOW_WORKFLOWS=("$DEFAULT_WORKFLOW")
}

resolve_runner_sha256() {
    local arch="$1"
    if [ -n "$OPT_RUNNER_SHA256" ]; then
        echo "$OPT_RUNNER_SHA256"
        return 0
    fi
    if [ "$OPT_RUNNER_VERSION" = "$RUNNER_VERSION_DEFAULT" ]; then
        pinned_runner_sha256 "$arch"
        return 0
    fi
    die "--sha256 / --runner-sha256 is required when overriding runner version ($OPT_RUNNER_VERSION != pinned $RUNNER_VERSION_DEFAULT)"
}

# ---- fetch-runner ---------------------------------------------------------

cmd_fetch_runner() {
    parse_common_opts "$@"
    local arch dest ver sha gh_arch url
    arch="${OPT_ARCH:-$(normalize_arch "$(uname -m)")}"
    [ -n "$OPT_DEST" ] || die "fetch-runner requires --dest PATH"
    dest="$OPT_DEST"
    ver="$OPT_RUNNER_VERSION"
    sha="$(resolve_runner_sha256 "$arch")"
    gh_arch="$(gh_runner_arch_of "$arch")"
    if [ -n "$OPT_URL" ]; then
        url="$OPT_URL"
        case "$url" in
            https://* | file://*) ;;
            *) die "--url must use https:// or file://: '$url'" ;;
        esac
    else
        url="https://github.com/actions/runner/releases/download/v${ver}/actions-runner-linux-${gh_arch}-${ver}.tar.gz"
    fi

    local parent tmp got
    parent="$(dirname "$dest")"
    mkdir -p "$parent"
    tmp="$(mktemp "$parent/.actions-runner.XXXXXX.part")"
    # Clean up partial file on any error.
    trap 'rm -f "${tmp:-}"' RETURN

    say "downloading actions/runner v${ver} (${arch} / linux-${gh_arch})"
    if ! curl -fsSL --proto '=https,file' --tlsv1.2 --retry 3 --retry-delay 5 -o "$tmp" "$url"; then
        rm -f "$tmp"
        die "failed to download $url"
    fi
    got="$(sha256_of "$tmp")"
    if [ "$got" != "$sha" ]; then
        rm -f "$tmp"
        die "SHA-256 mismatch for $url: got $got, expected $sha"
    fi
    mv -f "$tmp" "$dest"
    trap - RETURN
    echo "verified actions/runner v${ver} (${arch}): sha256=${got}"
}

# ---- render-hooks ---------------------------------------------------------

write_policy_file() {
    local dest="$1" slug="$2"
    cat >"$dest" <<EOF
# Managed by scripts/setup-kvm-runner.sh — root-owned, read-only to runner.
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
ALLOWED_REPOSITORY=${slug}
ALLOWED_EVENTS=${OPT_ALLOW_EVENTS[*]}
ALLOWED_REFS=${OPT_ALLOW_REFS[*]}
ALLOWED_WORKFLOWS=${OPT_ALLOW_WORKFLOWS[*]}
ALLOWED_ACTORS=${OPT_ALLOW_ACTORS[*]}
STATE_DIR=${OPT_STATE_DIR}
WORK_DIR=${OPT_STATE_DIR}/work
IMAGES_DIR=${OPT_STATE_DIR}/images
IMAGE_CACHE_DIR=${OPT_STATE_DIR}/image-cache
LIBVIRT_CONNECT=qemu:///session
EOF
}

write_job_started_hook() {
    local dest="$1"
    cat >"$dest" <<'EOF'
#!/usr/bin/env bash
# Host-enforced pre-job admission guard for qeminga KVM self-hosted runners.
# Installed root-owned (0755) outside the runner directory and wired via the
# systemd unit's Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED so a workflow job
# cannot modify or bypass it. Runs BEFORE actions/checkout or any job step.
#
# Rules: exact whole-string matches only (noglob), fail closed on any missing
# or mismatched field, never print full env or enable `set -x` (job logs are
# public), bound external commands with timeout.
set -eufo pipefail
export LC_ALL=C LANG=C

POLICY="${QEMINGA_RUNNER_POLICY:-/etc/qeminga-runner/policy.env}"
KVM_DEV="${QEMINGA_KVM_DEVICE:-/dev/kvm}"

log() { echo "qeminga-runner-guard: $*"; }
deny() {
    log "DENY ($1): repo=${GITHUB_REPOSITORY:-<unset>} event=${GITHUB_EVENT_NAME:-<unset>} ref=${GITHUB_REF:-<unset>} workflow_ref=${GITHUB_WORKFLOW_REF:-<unset>} actor=${GITHUB_ACTOR:-<unset>} verdict=deny" >&2
    exit 1
}

if [ ! -f "$POLICY" ] || [ ! -r "$POLICY" ]; then
    deny "missing or unreadable policy file $POLICY"
fi

ALLOWED_REPOSITORY=""
ALLOWED_EVENTS=""
ALLOWED_REFS=""
ALLOWED_WORKFLOWS=""
ALLOWED_ACTORS=""
LIBVIRT_CONNECT="qemu:///session"

# Parse KEY=VALUE literally without sourcing/evaluating shell syntax.
while IFS='=' read -r key val; do
    case "$key" in
        '' | '#'*) continue ;;
        ALLOWED_REPOSITORY) ALLOWED_REPOSITORY="$val" ;;
        ALLOWED_EVENTS) ALLOWED_EVENTS="$val" ;;
        ALLOWED_REFS) ALLOWED_REFS="$val" ;;
        ALLOWED_WORKFLOWS) ALLOWED_WORKFLOWS="$val" ;;
        ALLOWED_ACTORS) ALLOWED_ACTORS="$val" ;;
        LIBVIRT_CONNECT) LIBVIRT_CONNECT="$val" ;;
        STATE_DIR | WORK_DIR | IMAGES_DIR | IMAGE_CACHE_DIR) ;;
        *) deny "unknown policy key '$key'" ;;
    esac
done <"$POLICY"

[ -n "$ALLOWED_REPOSITORY" ] || deny "empty ALLOWED_REPOSITORY"
[ -n "$ALLOWED_EVENTS" ] || deny "empty ALLOWED_EVENTS"
[ -n "$ALLOWED_REFS" ] || deny "empty ALLOWED_REFS"
[ -n "$ALLOWED_WORKFLOWS" ] || deny "empty ALLOWED_WORKFLOWS"
[ "$LIBVIRT_CONNECT" = "qemu:///session" ] || deny "unexpected LIBVIRT_CONNECT"

in_list() {
    local needle="$1" list="$2" item
    [ -n "$needle" ] || return 1
    for item in $list; do
        if [ "$needle" = "$item" ]; then return 0; fi
    done
    return 1
}

repo="${GITHUB_REPOSITORY:-}"
event="${GITHUB_EVENT_NAME:-}"
ref="${GITHUB_REF:-}"
wf_ref="${GITHUB_WORKFLOW_REF:-}"
actor="${GITHUB_ACTOR:-}"

# Hardcoded defense in depth: never accept pull_request* or comment events.
case "$event" in
    pull_request | pull_request_target | issue_comment | discussion | fork)
        deny "untrusted event '$event'"
        ;;
esac

[ "$repo" = "$ALLOWED_REPOSITORY" ] || deny "repository mismatch"
in_list "$event" "$ALLOWED_EVENTS" || deny "event not allowlisted"
in_list "$ref" "$ALLOWED_REFS" || deny "ref not allowlisted"

wf_ok=0
for wf in $ALLOWED_WORKFLOWS; do
    if [ "$wf_ref" = "${ALLOWED_REPOSITORY}/${wf}@${ref}" ]; then
        wf_ok=1
        break
    fi
done
[ "$wf_ok" -eq 1 ] || deny "workflow_ref not allowlisted"

if [ -n "$ALLOWED_ACTORS" ]; then
    in_list "$actor" "$ALLOWED_ACTORS" || deny "actor not allowlisted"
fi

# Verify KVM device and clean session libvirt state before starting the job.
if [ ! -c "$KVM_DEV" ] || [ ! -r "$KVM_DEV" ] || [ ! -w "$KVM_DEV" ]; then
    deny "KVM device $KVM_DEV is missing or inaccessible"
fi

if ! command -v virsh >/dev/null 2>&1; then
    deny "virsh is not installed"
fi

domains="$(timeout 30 virsh "--connect=$LIBVIRT_CONNECT" list --all --name 2>/dev/null)" \
    || deny "cannot list libvirt domains on $LIBVIRT_CONNECT"
stale="$(printf '%s\n' "$domains" | grep -E '^qeminga-e2e-' || true)"
if [ -n "$stale" ]; then
    deny "stale qeminga domain(s) present: $(printf '%s ' "$stale" | sed 's/ $//')"
fi

log "ALLOW: repo=${repo} event=${event} ref=${ref} workflow_ref=${wf_ref} actor=${actor} verdict=allow"
EOF
    chmod 0755 "$dest"
}

write_job_completed_hook() {
    local dest="$1"
    cat >"$dest" <<'EOF'
#!/usr/bin/env bash
# Host-enforced post-job cleanup hook for qeminga KVM self-hosted runners.
# Installed root-owned (0755) and wired via ACTIONS_RUNNER_HOOK_JOB_COMPLETED.
# Destroys/undefines only stray qeminga-e2e-* session domains, removes their
# run directories only after confirming the domain is absent, and scrubs the
# runner work directory while preserving the SHA-256-verified image cache.
set -uo pipefail
export LC_ALL=C LANG=C

POLICY="${QEMINGA_RUNNER_POLICY:-/etc/qeminga-runner/policy.env}"

log() { echo "qeminga-runner-cleanup: $*"; }
die() { echo "qeminga-runner-cleanup: $*" >&2; exit 1; }

if [ ! -f "$POLICY" ] || [ ! -r "$POLICY" ]; then
    die "missing or unreadable policy file $POLICY"
fi

STATE_DIR=""
WORK_DIR=""
IMAGES_DIR=""
LIBVIRT_CONNECT="qemu:///session"

while IFS='=' read -r key val; do
    case "$key" in
        '' | '#'*) continue ;;
        STATE_DIR) STATE_DIR="$val" ;;
        WORK_DIR) WORK_DIR="$val" ;;
        IMAGES_DIR) IMAGES_DIR="$val" ;;
        LIBVIRT_CONNECT) LIBVIRT_CONNECT="$val" ;;
    esac
done <"$POLICY"

safe_subdir() {
    local p="$1"
    [[ "$p" =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
    [ "$p" != "/" ] || return 1
    case "$p" in
        */../* | */.. | */./* | */. | *//*) return 1 ;;
    esac
    [ -n "$STATE_DIR" ] && [ "${p#"$STATE_DIR"/}" != "$p" ]
}

safe_subdir "$WORK_DIR" || die "refusing unsafe WORK_DIR '$WORK_DIR'"
safe_subdir "$IMAGES_DIR" || die "refusing unsafe IMAGES_DIR '$IMAGES_DIR'"
[ "$LIBVIRT_CONNECT" = "qemu:///session" ] || die "refusing unexpected LIBVIRT_CONNECT '$LIBVIRT_CONNECT'"

v() { timeout 30 virsh "--connect=$LIBVIRT_CONNECT" "$@"; }

domain_state() {
    local name="$1" out
    if out="$(v domstate "$name" 2>&1)"; then
        printf '%s\n' "$out" | head -n 1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        return 0
    fi
    case "$out" in
        *"failed to get domain"* | *"Domain not found"*)
            local names
            names="$(v list --all --name 2>/dev/null)" || return 1
            if printf '%s\n' "$names" | grep -qx -- "$name"; then return 1; fi
            echo absent
            ;;
        *) return 1 ;;
    esac
}

rc=0

if command -v virsh >/dev/null 2>&1; then
    if names="$(v list --all --name 2>/dev/null)"; then
        while IFS= read -r dom; do
            [ -n "$dom" ] || continue
            [[ "$dom" =~ ^qeminga-e2e-[0-9]+-[0-9]+-[a-z0-9_]+$ ]] || continue
            log "cleaning stray domain $dom"
            st="$(domain_state "$dom")" || { log "cannot establish state of $dom; keeping disks"; rc=1; continue; }
            if [ "$st" != absent ] && [ "$st" != "shut off" ]; then
                v destroy "$dom" >/dev/null 2>&1 || true
                st="$(domain_state "$dom")" || { log "cannot confirm $dom stopped; keeping disks"; rc=1; continue; }
                if [ "$st" != "shut off" ]; then
                    log "$dom is still '$st'; keeping disks"
                    rc=1
                    continue
                fi
            fi
            if [ "$st" != absent ]; then
                v undefine --nvram "$dom" >/dev/null 2>&1 || v undefine "$dom" >/dev/null 2>&1 || {
                    log "cannot undefine $dom; keeping disks"
                    rc=1
                    continue
                }
                st="$(domain_state "$dom")" || { log "cannot confirm $dom absent; keeping disks"; rc=1; continue; }
                if [ "$st" != absent ]; then
                    log "$dom still defined; keeping disks"
                    rc=1
                    continue
                fi
            fi
            if [ -d "${IMAGES_DIR:?}/${dom:?}" ]; then
                rm -rf --one-file-system -- "${IMAGES_DIR:?}/${dom:?}"
                log "removed ${IMAGES_DIR}/${dom}"
            fi
        done <<<"$names"
    else
        log "cannot list libvirt domains on $LIBVIRT_CONNECT; keeping any disks under $IMAGES_DIR"
        rc=1
    fi

    # Remove orphan qeminga-e2e-* run directories whose domain is confirmed absent.
    if [ -d "$IMAGES_DIR" ]; then
        shopt -s nullglob
        for dir in "$IMAGES_DIR"/qeminga-e2e-*; do
            [ -d "$dir" ] || continue
            base="$(basename "$dir")"
            [[ "$base" =~ ^qeminga-e2e-[0-9]+-[0-9]+-[a-z0-9_]+$ ]] || continue
            st="$(domain_state "$base")" || { log "cannot confirm $base absent; keeping $dir"; rc=1; continue; }
            if [ "$st" = absent ]; then
                rm -rf --one-file-system -- "$dir"
                log "removed orphan run dir $dir"
            else
                log "$base is '$st'; keeping $dir"
                rc=1
            fi
        done
        shopt -u nullglob
    fi
fi

# Scrub the runner work directory between jobs (including dotfiles) so no
# checked-out source or temporary files persist across jobs.
if [ -d "$WORK_DIR" ]; then
    find "$WORK_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf --one-file-system -- {} +
    log "scrubbed work directory $WORK_DIR"
fi

exit "$rc"
EOF
    chmod 0755 "$dest"
}

write_jit_launcher() {
    local dest="$1"
    cat >"$dest" <<EOF
#!/usr/bin/env bash
# Root-owned one-shot JIT runner launcher: reads the single-use JIT config
# from systemd LoadCredential= into ACTIONS_RUNNER_INPUT_JITCONFIG and execs
# Runner.Listener directly so no intermediate shell/Node wrapper retains the
# secret in its environment and no run-helper.sh copy is written to the root.
set -euo pipefail
cred="\${CREDENTIALS_DIRECTORY:?missing CREDENTIALS_DIRECTORY}/jitconfig"
[ -r "\$cred" ] || { echo "missing jitconfig credential" >&2; exit 1; }
ACTIONS_RUNNER_INPUT_JITCONFIG="\$(tr -d '\r\n' <"\$cred")"
export ACTIONS_RUNNER_INPUT_JITCONFIG
exec "${OPT_INSTALL_DIR}/bin/Runner.Listener" run --startuptype service
EOF
    chmod 0755 "$dest"
}

cmd_render_hooks() {
    parse_common_opts "$@"
    [ -n "$OPT_REPO" ] || die "render-hooks requires --repo URL"
    [ -n "$OPT_OUT" ] || die "render-hooks requires --out DIR"
    finalize_policy_defaults
    local slug
    slug="$(repo_slug_of "$OPT_REPO")"
    mkdir -p "$OPT_OUT"
    write_policy_file "$OPT_OUT/policy.env" "$slug"
    write_job_started_hook "$OPT_OUT/hook-job-started.sh"
    write_job_completed_hook "$OPT_OUT/hook-job-completed.sh"
    echo "wrote $OPT_OUT/policy.env, $OPT_OUT/hook-job-started.sh, $OPT_OUT/hook-job-completed.sh"
}

# ---- render-unit ----------------------------------------------------------

render_unit_text() {
    local arch="$1"
    local restart_policy="on-failure"
    [ "$OPT_EPHEMERAL" -eq 1 ] && restart_policy="no"

    # Use upstream's service launcher (bin/runsvc.sh -> RunnerService.js ->
    # Runner.Listener) rather than interactive run.sh, which tries to copy
    # run-helper.sh.template into the read-only runner root on every launch.
    local exec_start="${OPT_INSTALL_DIR}/bin/runsvc.sh"
    local kill_signal="SIGTERM"
    local cred_line=""
    local stop_post_line=""
    if [ -n "$OPT_JITCONFIG_FILE" ]; then
        exec_start="${OPT_HOOK_DIR}/run-jit.sh"
        # run-jit.sh execs Runner.Listener directly, which drains on SIGINT.
        kill_signal="SIGINT"
        cred_line="LoadCredential=jitconfig:${OPT_CONFIG_DIR}/jitconfig"
        stop_post_line="ExecStopPost=+/usr/bin/rm -f ${OPT_CONFIG_DIR}/jitconfig"
    fi

    local state_directives=""
    if [[ "$OPT_STATE_DIR" =~ ^/var/lib/([A-Za-z0-9._-]+)$ ]]; then
        state_directives="StateDirectory=${BASH_REMATCH[1]}
StateDirectoryMode=0700"
    else
        state_directives="ReadWritePaths=${OPT_STATE_DIR}"
    fi

    local runner_fs_directives=""
    if [ "$OPT_ALLOW_AUTO_UPDATE" -eq 1 ]; then
        runner_fs_directives="# Auto-update opted in: runner root is writable; hooks and policy remain read-only.
ReadWritePaths=${OPT_INSTALL_DIR}"
    elif [ "$OPT_EPHEMERAL" -eq 1 ]; then
        runner_fs_directives="# Ephemeral/JIT mode writes/deletes .runner/.credentials; binaries and .env remain read-only.
ReadWritePaths=${OPT_INSTALL_DIR}
ReadOnlyPaths=${OPT_INSTALL_DIR}/bin
ReadOnlyPaths=${OPT_INSTALL_DIR}/externals
ReadOnlyPaths=${OPT_INSTALL_DIR}/run.sh
ReadOnlyPaths=${OPT_INSTALL_DIR}/config.sh
ReadOnlyPaths=${OPT_INSTALL_DIR}/env.sh
ReadOnlyPaths=${OPT_INSTALL_DIR}/.env"
    else
        runner_fs_directives="# --disableupdate (default): bin/runsvc.sh needs no writes in ${OPT_INSTALL_DIR};
# runner binaries and credentials stay read-only and only _diag logs are writable.
ReadWritePaths=${OPT_INSTALL_DIR}/_diag"
    fi

    local cpu_line=""
    [ -n "$OPT_CPU_QUOTA" ] && cpu_line="CPUQuota=${OPT_CPU_QUOTA}"

    local ip_allow_lines="IPAddressAllow=localhost"
    local ip
    for ip in "${OPT_ALLOW_IPS[@]}"; do
        ip_allow_lines="${ip_allow_lines}
IPAddressAllow=${ip}"
    done

    local ip_deny_lines="IPAddressDeny=link-local
IPAddressDeny=multicast
IPAddressDeny=fe80::/10
IPAddressDeny=fd00:ec2::254/128"
    if [ "$OPT_NO_LAN_DENY" -eq 0 ]; then
        ip_deny_lines="${ip_deny_lines}
IPAddressDeny=10.0.0.0/8
IPAddressDeny=172.16.0.0/12
IPAddressDeny=192.168.0.0/16
IPAddressDeny=100.64.0.0/10
IPAddressDeny=fc00::/7"
    fi

    cat <<EOF
# Hardened systemd unit for a community-donated qeminga KVM GitHub Actions runner.
# Generated by scripts/setup-kvm-runner.sh for ${OPT_REPO} (${arch}).
#
# Security model:
#   - Dedicated locked service user (${OPT_USER}), zero Linux capabilities,
#     NoNewPrivileges=yes, no sudo/libvirt/docker groups; only supplementary group kvm.
#   - Unprivileged qemu:///session libvirt inside this unit's cgroup, so every
#     disposable KVM guest inherits DevicePolicy=closed (/dev/kvm only),
#     ProtectSystem=strict, MemoryMax, TasksMax, and cgroup IPAddressDeny.
#   - MemoryDenyWriteExecute is intentionally omitted because .NET (actions/runner),
#     Node.js (JS actions), and QEMU require executable JIT mappings.
[Unit]
Description=qeminga KVM GitHub Actions runner (${arch})
Documentation=https://github.com/vicaya/qeminga
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${OPT_USER}
Group=${OPT_USER}
SupplementaryGroups=kvm
WorkingDirectory=${OPT_INSTALL_DIR}
ExecStart=${exec_start}
${cred_line}
${stop_post_line}
Restart=${restart_policy}
RestartSec=5s
KillMode=control-group
KillSignal=${kill_signal}
TimeoutStopSec=120s
StandardOutput=journal
StandardError=journal

# Runner and unprivileged qemu:///session environment (set here, never in a
# runner-writable .env file).
Environment=HOME=${OPT_STATE_DIR}
Environment=XDG_RUNTIME_DIR=/run/${OPT_SERVICE}
Environment=XDG_CONFIG_HOME=${OPT_STATE_DIR}/.config
Environment=XDG_CACHE_HOME=${OPT_STATE_DIR}/.cache
Environment=XDG_DATA_HOME=${OPT_STATE_DIR}/.local/share
Environment=LIBVIRT_DEFAULT_URI=qemu:///session
Environment=QEMINGA_E2E_CONNECT=qemu:///session
Environment=QEMINGA_E2E_IMAGES=${OPT_STATE_DIR}/images
Environment=QEMINGA_E2E_IMAGE_CACHE=${OPT_STATE_DIR}/image-cache
Environment=QEMINGA_RUNNER_POLICY=${OPT_CONFIG_DIR}/policy.env
Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=${OPT_HOOK_DIR}/hook-job-started.sh
Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED=${OPT_HOOK_DIR}/hook-job-completed.sh

# Filesystem confinement
UMask=0077
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RuntimeDirectory=${OPT_SERVICE}
RuntimeDirectoryMode=0700
${state_directives}
${runner_fs_directives}

# Privilege & kernel confinement
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
ProtectProc=invisible
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RemoveIPC=yes
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @module @raw-io @clock @cpu-emulation @obsolete @debug

# Resource bounds (keep host headroom so the donor never loses SSH)
MemoryMax=${OPT_MEMORY_MAX}
TasksMax=${OPT_TASKS_MAX}
${cpu_line}

# Cgroup BPF egress firewall: unconditionally block cloud IMDS (169.254.0.0/16,
# fe80::/10, fd00:ec2::254/128) and multicast; block private LANs by default.
${ip_allow_lines}
${ip_deny_lines}

[Install]
WantedBy=multi-user.target
EOF
}

cmd_render_unit() {
    parse_common_opts "$@"
    [ -n "$OPT_REPO" ] || die "render-unit requires --repo URL"
    local arch
    arch="${OPT_ARCH:-$(normalize_arch "$(uname -m)")}"
    # Strip blank lines caused by optional directives (e.g. CPUQuota / LoadCredential).
    render_unit_text "$arch" | awk 'NF || prev_nf { print } { prev_nf = NF }'
}

# ---- preflight ------------------------------------------------------------

check_private_resolv_nameservers() {
    local resolv="${QEMINGA_RESOLV_CONF:-/etc/resolv.conf}"
    [ -r "$resolv" ] || return 0
    local ns
    while read -r kw ns _; do
        [ "$kw" = "nameserver" ] || continue
        case "$ns" in
            127.* | ::1) ;;
            169.254.169.254 | fd00:ec2::254) ;;
            10.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[0-1].* | 192.168.* | 100.6[4-9].* | 100.[7-9][0-9].* | 100.1[0-1][0-9].* | 100.12[0-7].*)
                echo "note: $resolv uses private IPv4 nameserver $ns; if this host does not use systemd-resolved (127.0.0.53), pass --allow-ip ${ns}/32"
                ;;
            fc* | fd*)
                echo "note: $resolv uses private IPv6 nameserver $ns; pass --allow-ip ${ns}/128 if needed"
                ;;
        esac
    done <"$resolv"
}

cmd_preflight() {
    parse_common_opts "$@"
    local host_arch arch fail=0
    host_arch="$(normalize_arch "$(uname -m)")"
    arch="${OPT_ARCH:-$host_arch}"
    if [ "$arch" != "$host_arch" ]; then
        die "--arch $arch does not match host architecture $host_arch"
    fi

    say "preflight (host=${host_arch}, runner_arch=$(gh_runner_arch_of "$arch"), machine=$(machine_of "$arch"))"

    local os
    os="$(uname -s)"
    if [ "$os" = "Linux" ]; then echo "  ok: OS is Linux"
    else echo "  FAIL: unsupported OS '$os' (Linux required)"; fail=1; fi

    if command -v systemctl >/dev/null 2>&1; then
        echo "  ok: systemctl present"
    else
        echo "  FAIL: systemd (systemctl) not found"; fail=1
    fi

    # KVM check: /dev/kvm is authoritative on both x86_64 and aarch64
    # (aarch64 does not report vmx/svm in /proc/cpuinfo).
    local kvm_dev="${QEMINGA_KVM_DEVICE:-/dev/kvm}"
    if [ -c "$kvm_dev" ]; then
        echo "  ok: KVM device $kvm_dev exists"
        if [ -r "$kvm_dev" ] && [ -w "$kvm_dev" ]; then
            echo "  ok: KVM device $kvm_dev is readable and writable by current user"
        else
            echo "  note: current user cannot open $kvm_dev directly (install adds ${OPT_USER} to group kvm)"
        fi
    else
        echo "  FAIL: KVM device $kvm_dev is missing (enable hardware/nested virtualization and load kvm module)"
        fail=1
    fi

    local tool
    for tool in virsh libvirtd "qemu-system-$arch" qemu-img genisoimage jq curl sha256sum tar; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  ok: tool $tool"
        else
            echo "  FAIL: missing tool '$tool' (install will install packages on Ubuntu/Debian/Fedora)"
            fail=1
        fi
    done

    if [ "$arch" = "aarch64" ]; then
        local fw
        if fw="$(find_aavmf)"; then
            echo "  ok: AArch64 UEFI firmware (${fw%%:*})"
        else
            echo "  FAIL: missing AArch64 UEFI firmware (install qemu-efi-aarch64 or edk2-aarch64)"
            fail=1
        fi
    fi

    if command -v virsh >/dev/null 2>&1; then
        if virsh --connect=qemu:///session domcapabilities \
            --virttype kvm --arch "$arch" --machine "$(machine_of "$arch")" >/dev/null 2>&1; then
            echo "  ok: libvirt qemu:///session reports KVM capability for ${arch} $(machine_of "$arch")"
        else
            echo "  FAIL: libvirt qemu:///session cannot query KVM domcapabilities for ${arch} $(machine_of "$arch")"
            fail=1
        fi
    fi

    # RAM & disk checks (bounds overrideable for tests).
    local min_ram_mib="${QEMINGA_MIN_RAM_MIB:-2048}"
    local min_disk_gib="${QEMINGA_MIN_DISK_GIB:-10}"
    if [ -r /proc/meminfo ]; then
        local mem_mib
        mem_mib="$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo)"
        if [ "${mem_mib:-0}" -ge "$min_ram_mib" ]; then
            echo "  ok: RAM ${mem_mib} MiB (>= ${min_ram_mib} MiB)"
        else
            echo "  FAIL: RAM ${mem_mib:-0} MiB is below ${min_ram_mib} MiB minimum"
            fail=1
        fi
    fi

    local probe_dir="$OPT_STATE_DIR"
    while [ ! -d "$probe_dir" ] && [ "$probe_dir" != "/" ]; do
        probe_dir="$(dirname "$probe_dir")"
    done
    local free_gib
    free_gib="$(df -Pk "$probe_dir" | awk 'NR == 2 { print int($4 / (1024 * 1024)) }')"
    if [ "${free_gib:-0}" -ge "$min_disk_gib" ]; then
        echo "  ok: free disk under $probe_dir is ${free_gib} GiB (>= ${min_disk_gib} GiB)"
    else
        echo "  FAIL: free disk under $probe_dir is ${free_gib:-0} GiB (< ${min_disk_gib} GiB)"
        fail=1
    fi

    check_private_resolv_nameservers

    if [ "$fail" -eq 0 ]; then
        echo "PREFLIGHT: PASS (${arch} KVM ready)"
    else
        echo "PREFLIGHT: FAIL" >&2
    fi
    return "$fail"
}

# ---- package & account helpers --------------------------------------------

install_packages() {
    local arch="$1"
    say "installing minimal virtualization packages for ${arch} (no system libvirtd, no docker, no Rust toolchain)"
    if command -v apt-get >/dev/null 2>&1; then
        local arch_pkgs=()
        case "$arch" in
            x86_64) arch_pkgs=(qemu-system-x86) ;;
            aarch64) arch_pkgs=(qemu-system-arm qemu-efi-aarch64) ;;
        esac
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
            libvirt-daemon libvirt-daemon-driver-qemu libvirt-clients \
            qemu-utils genisoimage jq curl ca-certificates "${arch_pkgs[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        local arch_pkgs=()
        case "$arch" in
            x86_64) arch_pkgs=(qemu-system-x86-core) ;;
            aarch64) arch_pkgs=(qemu-system-aarch64-core edk2-aarch64) ;;
        esac
        dnf install -y -q \
            libvirt-daemon-driver-qemu libvirt-client \
            qemu-img genisoimage jq curl ca-certificates "${arch_pkgs[@]}"
    else
        die "neither apt-get nor dnf found; install libvirt-daemon, qemu-system-${arch}, qemu-img, genisoimage, jq, curl manually and rerun with --skip-packages"
    fi
}

ensure_service_user() {
    say "configuring dedicated locked service user ${OPT_USER}"
    getent group kvm >/dev/null 2>&1 || die "group 'kvm' does not exist (is KVM enabled on this host?)"

    if id "$OPT_USER" >/dev/null 2>&1; then
        local uid groups g
        uid="$(id -u "$OPT_USER")"
        [ "$uid" -ne 0 ] || die "existing user $OPT_USER has uid 0"
        groups="$(id -nG "$OPT_USER")"
        for g in $groups; do
            case "$g" in
                root | sudo | wheel | admin | docker | libvirt | libvirt-qemu | adm | disk | shadow | lxd | podman | systemd-journal)
                    die "existing user $OPT_USER belongs to privileged group '$g'; refusing to reuse"
                    ;;
            esac
        done
        usermod -s /usr/sbin/nologin "$OPT_USER"
    else
        useradd --system --user-group \
            --home-dir "$OPT_STATE_DIR" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$OPT_USER"
        passwd -l "$OPT_USER" >/dev/null 2>&1 || true
    fi
    usermod -aG kvm "$OPT_USER"
}

lock_runner_permissions() {
    [ ! -L "$OPT_INSTALL_DIR" ] || die "refusing symlinked runner directory: $OPT_INSTALL_DIR"
    [ -d "$OPT_INSTALL_DIR" ] || die "runner directory does not exist: $OPT_INSTALL_DIR"
    if [ "$OPT_ALLOW_AUTO_UPDATE" -eq 1 ]; then
        chown -h -R -P "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR"
    else
        chown -h -R -P root:root "$OPT_INSTALL_DIR"
        chmod 0755 "$OPT_INSTALL_DIR"

        local diag_dir="$OPT_INSTALL_DIR/_diag"
        [ ! -L "$diag_dir" ] || die "refusing symlinked runner diag directory: $diag_dir"
        if [ -e "$diag_dir" ] && [ ! -d "$diag_dir" ]; then
            die "refusing non-directory runner diag entry: $diag_dir"
        fi
        install -d -m 0700 -o "$OPT_USER" -g "$OPT_USER" "$diag_dir"

        local f p
        for f in .runner .credentials .credentials_rsaparams .path; do
            p="$OPT_INSTALL_DIR/$f"
            [ ! -L "$p" ] || die "refusing symlinked runner file: $p"
            if [ -e "$p" ]; then
                [ -f "$p" ] || die "refusing non-regular runner file: $p"
                chown -h "${OPT_USER}:${OPT_USER}" "$p"
                chmod 0600 "$p"
            fi
        done

        # Keep .env root-owned and read-only so jobs cannot inject hooks or env vars.
        local env_file="$OPT_INSTALL_DIR/.env"
        [ ! -L "$env_file" ] || die "refusing symlinked runner env file: $env_file"
        if [ -e "$env_file" ]; then
            [ -f "$env_file" ] || die "refusing non-regular runner env file: $env_file"
            chown -h "root:${OPT_USER}" "$env_file"
            chmod 0640 "$env_file"
        else
            install -m 0640 -o root -g "$OPT_USER" /dev/null "$env_file"
        fi

        local bin_dir="$OPT_INSTALL_DIR/bin"
        local runsvc="$bin_dir/runsvc.sh"
        [ ! -L "$bin_dir" ] || die "refusing symlinked runner bin directory: $bin_dir"
        [ ! -L "$runsvc" ] || die "refusing symlinked runner launcher: $runsvc"
        if [ -f "$runsvc" ]; then
            chmod 0755 "$runsvc"
        fi

        # Ephemeral/JIT mode needs the runner user to create/remove .runner/.credentials*
        # in the root directory while bin/, externals/, scripts, and .env stay ReadOnlyPaths.
        if [ "$OPT_EPHEMERAL" -eq 1 ]; then
            chown -h "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR"
            chmod 0750 "$OPT_INSTALL_DIR"
        fi
    fi
}

run_runner_config_with_token() {
    local token="$1"
    shift
    # Pass the token solely via the inherited environment (never in argv / ps).
    (
        export ACTIONS_RUNNER_INPUT_TOKEN="$token"
        runuser -w ACTIONS_RUNNER_INPUT_TOKEN -u "$OPT_USER" -- env \
            "HOME=$OPT_STATE_DIR" \
            "$OPT_INSTALL_DIR/config.sh" "$@"
    )
}

# ---- install --------------------------------------------------------------

cmd_install() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "install must run as root (e.g. sudo $0 install ...)"
    [ -n "$OPT_REPO" ] || die "install requires --repo https://github.com/OWNER/REPO"
    if [ -n "$OPT_TOKEN_FILE" ] && [ -n "$OPT_JITCONFIG_FILE" ]; then
        die "--token-file and --jitconfig-file are mutually exclusive"
    fi

    local host_arch arch
    host_arch="$(normalize_arch "$(uname -m)")"
    arch="${OPT_ARCH:-$host_arch}"
    [ "$arch" = "$host_arch" ] || die "--arch $arch does not match host architecture $host_arch"

    local kvm_dev="${QEMINGA_KVM_DEVICE:-/dev/kvm}"
    [ -c "$kvm_dev" ] || die "KVM device $kvm_dev does not exist; refusing to register a non-KVM host as a KVM runner"

    finalize_policy_defaults
    local slug runner_name
    slug="$(repo_slug_of "$OPT_REPO")"
    if [ -n "$OPT_NAME" ]; then
        runner_name="$OPT_NAME"
    else
        local host_short
        host_short="$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-32)"
        runner_name="qeminga-kvm-${arch}-${host_short:-host}"
    fi
    check_runner_name "$runner_name"

    # Acquire registration token or JIT config before mutating the host.
    local reg_token="" jit_config=""
    if [ -n "$OPT_JITCONFIG_FILE" ]; then
        jit_config="$(read_secret_file --jitconfig-file "$OPT_JITCONFIG_FILE")"
    elif [ -n "$OPT_TOKEN_FILE" ]; then
        reg_token="$(read_secret_file --token-file "$OPT_TOKEN_FILE")"
    elif [ -n "${QEMINGA_RUNNER_TOKEN:-}" ]; then
        reg_token="$QEMINGA_RUNNER_TOKEN"
        unset QEMINGA_RUNNER_TOKEN
    elif [ -t 0 ]; then
        printf 'GitHub runner registration token for %s (input hidden): ' "$OPT_REPO" >&2
        IFS= read -r -s reg_token
        printf '\n' >&2
        [ -n "$reg_token" ] || die "registration token cannot be empty"
    else
        die "provide a registration token via --token-file PATH (mode 0600), --token-file - (stdin), --jitconfig-file PATH, QEMINGA_RUNNER_TOKEN, or an interactive terminal"
    fi

    if [ "$OPT_SKIP_PACKAGES" -eq 0 ]; then
        install_packages "$arch"
    fi

    if [ "$arch" = "aarch64" ]; then
        find_aavmf >/dev/null || die "missing AArch64 UEFI firmware (install qemu-efi-aarch64 or edk2-aarch64)"
    fi

    ensure_service_user

    # Provision state directories (mode 0700, owned by service user).
    install -d -m 0700 -o "$OPT_USER" -g "$OPT_USER" \
        "$OPT_STATE_DIR" \
        "$OPT_STATE_DIR/work" \
        "$OPT_STATE_DIR/images" \
        "$OPT_STATE_DIR/image-cache" \
        "$OPT_STATE_DIR/.config" \
        "$OPT_STATE_DIR/.cache" \
        "$OPT_STATE_DIR/.local/share"

    # Stop existing service if reinstalling/updating in place.
    if systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
        say "stopping existing ${OPT_SERVICE}.service"
        systemctl stop "${OPT_SERVICE}.service"
    fi

    # Download, SHA-256 verify, and extract actions/runner.
    local tarball fetch_args=()
    tarball="$(mktemp /tmp/qeminga-actions-runner.XXXXXX.tar.gz)"
    trap 'rm -f "${tarball:-}"' EXIT
    fetch_args=(--arch "$arch" --dest "$tarball" --version "$OPT_RUNNER_VERSION")
    if [ -n "$OPT_RUNNER_SHA256" ]; then fetch_args+=(--sha256 "$OPT_RUNNER_SHA256"); fi
    if [ -n "$OPT_URL" ]; then fetch_args+=(--url "$OPT_URL"); fi
    cmd_fetch_runner "${fetch_args[@]}"

    [ ! -L "$OPT_INSTALL_DIR" ] || die "refusing symlinked runner directory: $OPT_INSTALL_DIR"
    install -d -m 0755 -o root -g root "$OPT_INSTALL_DIR"
    rm -rf --one-file-system -- "${OPT_INSTALL_DIR:?}/bin" "${OPT_INSTALL_DIR:?}/externals"
    tar --no-same-owner -xzf "$tarball" -C "$OPT_INSTALL_DIR"
    rm -f "$tarball"
    trap - EXIT

    if [ "$OPT_SKIP_PACKAGES" -eq 0 ] && [ -x "$OPT_INSTALL_DIR/bin/installdependencies.sh" ]; then
        say "installing actions/runner runtime dependencies"
        "$OPT_INSTALL_DIR/bin/installdependencies.sh" >/dev/null
    fi

    # Install root-owned hooks and policy.
    say "installing root-owned job guard and cleanup hooks"
    install -d -m 0755 -o root -g root "$OPT_HOOK_DIR"
    install -d -m 0750 -o root -g "$OPT_USER" "$OPT_CONFIG_DIR"
    write_policy_file "$OPT_CONFIG_DIR/policy.env" "$slug"
    chown "root:${OPT_USER}" "$OPT_CONFIG_DIR/policy.env"
    chmod 0640 "$OPT_CONFIG_DIR/policy.env"
    write_job_started_hook "$OPT_HOOK_DIR/hook-job-started.sh"
    write_job_completed_hook "$OPT_HOOK_DIR/hook-job-completed.sh"
    chown root:root "$OPT_HOOK_DIR/hook-job-started.sh" "$OPT_HOOK_DIR/hook-job-completed.sh"

    if [ -n "$jit_config" ]; then
        say "installing one-shot JIT config credential"
        write_jit_launcher "$OPT_HOOK_DIR/run-jit.sh"
        chown root:root "$OPT_HOOK_DIR/run-jit.sh"
        umask 0177
        printf '%s\n' "$jit_config" >"$OPT_CONFIG_DIR/jitconfig"
        umask 0022
        chown root:root "$OPT_CONFIG_DIR/jitconfig"
        chmod 0600 "$OPT_CONFIG_DIR/jitconfig"
        unset jit_config
    else
        command -v runuser >/dev/null 2>&1 || die "runuser (util-linux) is required to register the runner as $OPT_USER"
        # Register as the unprivileged runner user, passing the token via
        # inherited ACTIONS_RUNNER_INPUT_TOKEN (never in argv / ps).
        say "registering runner '${runner_name}' (${arch}, labels=${OPT_LABELS}) against ${OPT_REPO}"
        chown -h -R -P "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR"
        local cfg_args=(
            --unattended
            --replace
            --url "$OPT_REPO"
            --name "$runner_name"
            --labels "$OPT_LABELS"
            --work "$OPT_STATE_DIR/work"
        )
        [ "$OPT_ALLOW_AUTO_UPDATE" -eq 0 ] && cfg_args+=(--disableupdate)
        [ "$OPT_EPHEMERAL" -eq 1 ] && cfg_args+=(--ephemeral)

        run_runner_config_with_token "$reg_token" "${cfg_args[@]}"
        unset reg_token
    fi

    lock_runner_permissions

    # Install and verify the hardened systemd unit.
    local unit_path="/etc/systemd/system/${OPT_SERVICE}.service"
    say "installing hardened systemd unit ${unit_path}"
    render_unit_text "$arch" | awk 'NF || prev_nf { print } { prev_nf = NF }' >"$unit_path"
    chmod 0644 "$unit_path"
    chown root:root "$unit_path"

    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze verify --man=no "$unit_path" || die "systemd-analyze verify failed for $unit_path"
    fi

    systemctl daemon-reload
    if [ "$OPT_NO_START" -eq 0 ]; then
        if [ "$OPT_EPHEMERAL" -eq 1 ]; then
            systemctl start "${OPT_SERVICE}.service"
            say "${OPT_SERVICE}.service started (ephemeral one-shot; not enabled across reboot)"
        else
            systemctl enable --now "${OPT_SERVICE}.service"
            say "${OPT_SERVICE}.service is enabled and started"
        fi
    else
        say "--no-start set; inspect ${unit_path}, then run: sudo systemctl enable --now ${OPT_SERVICE}.service"
    fi

    echo
    echo "qeminga KVM runner installed:"
    echo "  service:     ${OPT_SERVICE}.service"
    echo "  user:        ${OPT_USER} (supplementary group: kvm; zero sudo/libvirt/docker)"
    echo "  arch:        ${arch} (GitHub labels: self-hosted, linux, $(gh_runner_arch_of "$arch"), ${OPT_LABELS})"
    echo "  libvirt:     qemu:///session (unprivileged, isolated from host system VMs)"
    echo "  policy:      ${OPT_CONFIG_DIR}/policy.env"
    echo "  hooks:       ${OPT_HOOK_DIR}/hook-job-{started,completed}.sh"
    if [ "$OPT_ALLOW_AUTO_UPDATE" -eq 0 ]; then
        echo "  updates:     manual (--disableupdate, read-only binaries); GitHub requires runner updates"
        echo "               within 30 days of a new release — run: sudo $0 update"
    fi
    echo "  logs:        journalctl -u ${OPT_SERVICE}.service -f"
    check_private_resolv_nameservers
}

# ---- status ---------------------------------------------------------------

cmd_status() {
    parse_common_opts "$@"
    local arch
    arch="$(normalize_arch "$(uname -m)")"
    say "qeminga KVM runner status (${OPT_SERVICE}.service, host=${arch})"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active "${OPT_SERVICE}.service" || true
        systemctl status --no-pager -n 10 "${OPT_SERVICE}.service" || true
    fi
    if [ -f "${OPT_CONFIG_DIR}/policy.env" ]; then
        echo "-- policy (${OPT_CONFIG_DIR}/policy.env):"
        cat "${OPT_CONFIG_DIR}/policy.env"
    fi
    if command -v systemd-analyze >/dev/null 2>&1 && [ -f "/etc/systemd/system/${OPT_SERVICE}.service" ]; then
        echo "-- systemd security exposure:"
        systemd-analyze security --no-pager "${OPT_SERVICE}.service" | tail -n 5 || true
    fi
}

# ---- update ---------------------------------------------------------------

cmd_update() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "update must run as root"
    [ ! -L "$OPT_INSTALL_DIR" ] || die "refusing symlinked runner directory: $OPT_INSTALL_DIR"
    [ -d "$OPT_INSTALL_DIR" ] || die "runner directory $OPT_INSTALL_DIR does not exist"
    local arch
    arch="$(normalize_arch "$(uname -m)")"

    local tarball fetch_args=()
    tarball="$(mktemp /tmp/qeminga-actions-runner-update.XXXXXX.tar.gz)"
    trap 'rm -f "${tarball:-}"' EXIT
    fetch_args=(--arch "$arch" --dest "$tarball" --version "$OPT_RUNNER_VERSION")
    if [ -n "$OPT_RUNNER_SHA256" ]; then fetch_args+=(--sha256 "$OPT_RUNNER_SHA256"); fi
    if [ -n "$OPT_URL" ]; then fetch_args+=(--url "$OPT_URL"); fi
    cmd_fetch_runner "${fetch_args[@]}"

    local was_active=0
    if systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
        was_active=1
        say "stopping ${OPT_SERVICE}.service"
        systemctl stop "${OPT_SERVICE}.service"
    fi

    # Remove old bin/ and externals/ so renamed assemblies do not linger across versions,
    # while preserving registration files (.runner, .credentials*) and _diag/.
    rm -rf --one-file-system -- "${OPT_INSTALL_DIR:?}/bin" "${OPT_INSTALL_DIR:?}/externals"
    tar --no-same-owner -xzf "$tarball" -C "$OPT_INSTALL_DIR"
    rm -f "$tarball"
    trap - EXIT

    lock_runner_permissions

    if [ "$was_active" -eq 1 ] && [ "$OPT_NO_START" -eq 0 ]; then
        say "restarting ${OPT_SERVICE}.service"
        systemctl start "${OPT_SERVICE}.service"
    fi
    echo "updated actions/runner in ${OPT_INSTALL_DIR} to v${OPT_RUNNER_VERSION} (${arch})"
}

# ---- uninstall ------------------------------------------------------------

cmd_uninstall() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "uninstall must run as root"
    local unit_path="/etc/systemd/system/${OPT_SERVICE}.service"

    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop "${OPT_SERVICE}.service" 2>/dev/null || true
        systemctl disable "${OPT_SERVICE}.service" 2>/dev/null || true
    fi

    # Run the post-job cleanup hook as the runner user to destroy any stray
    # qeminga-e2e-* session domains before removing state files.
    if command -v runuser >/dev/null 2>&1 && id "$OPT_USER" >/dev/null 2>&1 && [ -x "$OPT_HOOK_DIR/hook-job-completed.sh" ] && [ -f "$OPT_CONFIG_DIR/policy.env" ]; then
        say "running cleanup hook to remove stray qeminga session domains"
        runuser -u "$OPT_USER" -- env \
            "HOME=$OPT_STATE_DIR" \
            "XDG_RUNTIME_DIR=/run/${OPT_SERVICE}" \
            "QEMINGA_RUNNER_POLICY=$OPT_CONFIG_DIR/policy.env" \
            "$OPT_HOOK_DIR/hook-job-completed.sh" || warn "cleanup hook reported errors; continuing uninstall"
    fi

    # Optional deregistration from GitHub if a removal token was supplied.
    if [ -n "$OPT_TOKEN_FILE" ] && [ ! -L "$OPT_INSTALL_DIR" ] && [ -x "$OPT_INSTALL_DIR/config.sh" ] && id "$OPT_USER" >/dev/null 2>&1; then
        command -v runuser >/dev/null 2>&1 || die "runuser is required to deregister the runner as $OPT_USER"
        local rm_token
        rm_token="$(read_secret_file --token-file "$OPT_TOKEN_FILE")"
        say "deregistering runner from GitHub"
        chown -h -R -P "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR"
        run_runner_config_with_token "$rm_token" remove --unattended \
            || warn "deregistration failed (remove manually in GitHub Settings -> Actions -> Runners)"
        unset rm_token
    fi

    rm -f "$unit_path"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
    fi
    rm -rf --one-file-system -- "$OPT_HOOK_DIR" "$OPT_CONFIG_DIR" "$OPT_INSTALL_DIR" "$OPT_STATE_DIR"

    if [ "$OPT_PURGE_USER" -eq 1 ] && id "$OPT_USER" >/dev/null 2>&1; then
        userdel "$OPT_USER" || warn "could not delete user $OPT_USER"
        if getent group "$OPT_USER" >/dev/null 2>&1; then
            groupdel "$OPT_USER" || true
        fi
    fi
    echo "uninstalled ${OPT_SERVICE}"
}

# ---- dispatch -------------------------------------------------------------

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    [ $# -ge 1 ] || { usage; exit 64; }
    sub="$1"; shift
    case "$sub" in
        preflight) cmd_preflight "$@" ;;
        install) cmd_install "$@" ;;
        render-unit) cmd_render_unit "$@" ;;
        render-hooks) cmd_render_hooks "$@" ;;
        fetch-runner) cmd_fetch_runner "$@" ;;
        status) cmd_status "$@" ;;
        update) cmd_update "$@" ;;
        uninstall) cmd_uninstall "$@" ;;
        -h | --help) usage ;;
        *) die "unknown subcommand '$sub' (run with --help)" ;;
    esac
fi
