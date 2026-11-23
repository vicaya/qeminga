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
#   - GitHub-side assignment restriction first, hook second: donors register
#     against a private controller repository (default, #53) or an organization
#     runner group restricted by GitHub to the reviewed workflow and ref
#     (--org + --runner-group + --allow-repo). Direct registration on the public
#     vicaya/qeminga repository is refused because actions/runner v2.338.2 runs
#     action setup before ACTIONS_RUNNER_HOOK_JOB_STARTED and still evaluates
#     `if: always()` / `if: failure()` steps after a failed hook.
#   - Host-enforced root-owned runner hooks (ACTIONS_RUNNER_HOOK_JOB_STARTED /
#     COMPLETED) and main-process launcher wrappers (run-runner.sh / run-jit.sh)
#     configured via systemd (never runner-writable): exact whole-string
#     allowlists for repository, event, ref, workflow, and optional actor;
#     startup gated inside the main service process (exit 78 ->
#     RestartPreventExitStatus=78) using isolated /usr/bin/python3 -I -S under
#     env -i to verify this unit's cgroup BPF filter blocks the unit loopback
#     sentinel, cloud IMDS, and private LANs; stale-domain check before each
#     job and automatic workspace + stray-domain scrub after every job.
#   - Pinned GitHub actions/runner archive verified by SHA-256 for both x64 and
#     arm64 before extraction; runner binaries stay kernel-read-only by default
#     (--disableupdate); registration tokens are never accepted on the CLI or
#     passed in process argv; root-owned install record scopes update & uninstall
#     and tracks managed account ownership across interrupted installs and
#     uninstalls without --purge-user.
#
# Usage:
#   scripts/setup-kvm-runner.sh preflight [OPTIONS]
#   sudo scripts/setup-kvm-runner.sh install --repo https://github.com/OWNER/PRIVATE-CONTROLLER [OPTIONS]
#   sudo scripts/setup-kvm-runner.sh install --org https://github.com/ORG --runner-group GROUP --allow-repo vicaya/qeminga [OPTIONS]
#   scripts/setup-kvm-runner.sh render-unit --repo https://github.com/OWNER/PRIVATE-CONTROLLER [OPTIONS]
#   scripts/setup-kvm-runner.sh render-hooks --repo https://github.com/OWNER/PRIVATE-CONTROLLER --out DIR [OPTIONS]
#   scripts/setup-kvm-runner.sh fetch-runner --arch ARCH --dest FILE [--version V --sha256 HEX] [--url URL]
#   scripts/setup-kvm-runner.sh status [OPTIONS]
#   sudo scripts/setup-kvm-runner.sh update [--version V --sha256 HEX] [OPTIONS]
#   sudo scripts/setup-kvm-runner.sh migrate-record [--confirm-volumes] [--confirm-account-marker] [OPTIONS]
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

PUBLIC_QEMINGA_SLUG="vicaya/qeminga"
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
  preflight      Read-only host check (arch, /dev/kvm, cgroup v2, libvirt/QEMU, AAVMF on arm64, RAM/disk, DNS)
  install        Install packages, create locked user, verify & register runner, install hardened unit
  render-unit    Print the hardened systemd unit to stdout without modifying the host
  render-hooks   Write hook scripts, egress firewall check, and policy.env into --out DIR
  fetch-runner   Download and SHA-256 verify the pinned actions/runner tarball for x86_64 or aarch64
  status         Show service status, systemd security score, KVM state, and active policy
  update         Stop service, replace actions/runner with a SHA-256-verified archive, restart
  migrate-record Upgrade legacy VOL_* fingerprints and/or stamp GECOS marker on verified pre-marker accounts
  uninstall      Stop & remove service (using install record), clean stray qeminga domains, optionally deregister & purge user

Registration target (choose ONE; direct registration on public vicaya/qeminga is refused):
  --repo URL             Private controller repository URL (https://github.com/OWNER/PRIVATE-REPO)
  --org URL              GitHub organization URL (https://github.com/ORG); requires --runner-group and --allow-repo
  --runner-group GROUP   GitHub organization runner group restricted to the reviewed workflow/ref (not Default)
  --allow-repo SLUG      Exact OWNER/REPO allowlisted in hook policy when using --org

Common options:
  --arch ARCH            x86_64 (or amd64/x64) or aarch64 (or arm64); defaults to uname -m
  --name NAME            Runner name (default: qeminga-kvm-<arch>-<host>)
  --labels LIST          Comma-separated extra labels (default: qeminga-kvm)
  --user USER            Dedicated service user (default: qeminga-runner; root refused)
  --service NAME         Systemd service base name (default: qeminga-kvm-runner)
  --install-dir DIR      Dedicated runner binaries directory (default: /opt/qeminga-runner)
  --state-dir DIR        Dedicated runner work/images/cache directory (default: /var/lib/qeminga-runner)
  --hook-dir DIR         Dedicated root-owned hook scripts directory (default: /usr/local/libexec/qeminga-runner)
  --config-dir DIR       Dedicated root-owned policy/record directory (default: /etc/qeminga-runner)

Registration credentials (never pass --token on the CLI):
  --token-file PATH      Read registration/removal token from mode-0600 file, or '-' for stdin
  --jitconfig-file PATH  One-shot ephemeral GitHub JIT config file (mode 0600) or '-' for stdin
  (If omitted during install on a TTY, prompts with hidden input; or set QEMINGA_RUNNER_TOKEN.)

Runner binary pinning:
  --runner-version VER   actions/runner version (default: 2.338.2)
  --runner-sha256 HEX    Required whenever --runner-version differs from the pinned default
  --allow-auto-update    Opt in to GitHub self-updates (default: --disableupdate, read-only binaries)
  --ephemeral            Register for a single job only (Restart=no, auto-deregisters on exit)

Host-side job admission policy (defense in depth alongside GitHub-side assignment restrictions):
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
  --purge-user           (uninstall only) Also remove the dedicated service user if created by this script
  --confirm-volumes      (migrate-record only) Upgrade matching legacy 4-field/empty VOL_* records to UUID/fsid
  --confirm-account-marker (migrate-record only) Stamp qeminga-runner-<INSTALL_ID> onto a verified legacy account with empty GECOS
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
    local slug="${url#https://github.com/}"
    if [ "${slug,,}" = "$PUBLIC_QEMINGA_SLUG" ]; then
        die "refusing direct registration on public repository '${slug}': actions/runner runs action setup before job-start hooks and evaluates 'if: always()'/'if: failure()' steps after hook denial. Register against a private controller repository (--repo https://github.com/OWNER/PRIVATE-CONTROLLER) or a GitHub-restricted organization runner group (--org https://github.com/ORG --runner-group GROUP --allow-repo ${PUBLIC_QEMINGA_SLUG})"
    fi
    echo "$url"
}

check_org_url() {
    local url="${1%/}"
    [[ "$url" =~ ^https://github\.com/[A-Za-z0-9._-]+$ ]] \
        || die "--org must be an HTTPS GitHub organization URL (https://github.com/ORG): '$1'"
    case "$url" in
        *.git | */.. | */.) die "invalid --org URL: '$1'" ;;
    esac
    echo "$url"
}

check_runner_group() {
    local g="$1"
    [[ "$g" =~ ^[A-Za-z0-9._-]([A-Za-z0-9._\ -]{0,62}[A-Za-z0-9._-])?$ ]] \
        || die "invalid --runner-group '$g'"
    if [ "${g,,}" = "default" ]; then
        die "refusing --runner-group '$g': use a dedicated GitHub runner group restricted to the reviewed workflow and ref, never Default"
    fi
}

check_repo_slug() {
    local s="$1"
    [[ "$s" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] \
        || die "--allow-repo must be OWNER/REPO: '$s'"
    case "$s" in
        *.git | *..* | */. | ./*) die "invalid --allow-repo '$s'" ;;
    esac
}

verify_private_repo() {
    local slug="$1" resp code body is_private
    command -v curl >/dev/null 2>&1 || die "curl is required to verify repository visibility"
    command -v jq >/dev/null 2>&1 || die "jq is required to verify repository visibility"
    resp="$(curl -sS --proto '=https' --tlsv1.2 --max-time 20 -H 'Accept: application/vnd.github+json' -w '\n%{http_code}' "https://api.github.com/repos/${slug}")" \
        || die "cannot query GitHub API to verify '${slug}' is a private controller repository"
    code="${resp##*$'\n'}"
    body="${resp%$'\n'*}"
    case "$code" in
        404)
            # Unauthenticated GitHub API returns 404 for private repositories.
            return 0
            ;;
        200)
            is_private="$(printf '%s' "$body" | jq -r '.private // false' 2>/dev/null || echo false)"
            if [ "$is_private" = "true" ]; then
                return 0
            fi
            die "refusing to register donor directly on public repository '${slug}': register against a private controller repository (--repo) or a GitHub-restricted organization runner group (--org ... --runner-group ... --allow-repo ...)"
            ;;
        *)
            die "cannot verify '${slug}' is private (GitHub API returned HTTP ${code}); refusing to register against unverified repository visibility"
            ;;
    esac
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
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "invalid --service '$1' (must start with an alphanumeric character and contain only [A-Za-z0-9._-])"
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
        # Block any IPv4 address or supernet overlapping 169.254.0.0/16 (link-local / cloud IMDS)
        # or our unit-policy loopback sentinel 127.255.255.254/32.
        local ip_int imds_net sentinel_net min_p mask
        ip_int=$(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
        imds_net=$(( (169 << 24) | (254 << 16) ))
        min_p="$prefix"
        [ "$min_p" -le 16 ] || min_p=16
        mask=$(( (0xFFFFFFFF << (32 - min_p)) & 0xFFFFFFFF ))
        if [ "$((ip_int & mask))" -eq "$((imds_net & mask))" ]; then
            die "refusing --allow-ip '$cidr': overlaps link-local / cloud metadata range 169.254.0.0/16"
        fi
        sentinel_net=$(( (127 << 24) | (255 << 16) | (255 << 8) | 254 ))
        mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
        if [ "$((ip_int & mask))" -eq "$((sentinel_net & mask))" ]; then
            die "refusing --allow-ip '$cidr': overlaps cgroup egress-firewall sentinel 127.255.255.254/32"
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

# Decode a GitHub JIT config payload, verify its explicit repository gitHubUrl
# binding and runner group metadata, and return the validated canonical
# direct-child workspace path (matching actions/runner HostContext.cs:
# Path.Combine(Root, workFolder)).
resolve_jit_work_dir() {
    local jit_b64="$1" expected_url="$2" outer runner_b64 runner_json gh_url pool_name wf
    command -v jq >/dev/null 2>&1 || die "jq is required to validate --jitconfig-file"
    command -v base64 >/dev/null 2>&1 || die "base64 is required to validate --jitconfig-file"
    outer="$(printf '%s' "$jit_b64" | base64 -d 2>/dev/null)" \
        || die "invalid base64 in --jitconfig-file"
    runner_b64="$(printf '%s' "$outer" | jq -er '.[".runner"] // empty' 2>/dev/null)" \
        || die "--jitconfig-file JSON is missing .runner entry"
    [ -n "$runner_b64" ] || die "--jitconfig-file .runner entry is empty"
    runner_json="$(printf '%s' "$runner_b64" | base64 -d 2>/dev/null | sed '1s/^\xef\xbb\xbf//')" \
        || die "invalid base64 in --jitconfig-file .runner entry"
    printf '%s' "$runner_json" | jq -e 'type == "object"' >/dev/null 2>&1 \
        || die "--jitconfig-file .runner entry is not a JSON object"
    wf="$(printf '%s' "$runner_json" | jq -er '.workFolder // empty' 2>/dev/null)" \
        || die "--jitconfig-file .runner lacks workFolder"

    # Refuse unbound JIT payloads with omitted or empty gitHubUrl: shared
    # actions.githubusercontent.com endpoints do not identify which repository
    # owns the enrollment, so we cannot verify it matches --repo.
    gh_url="$(printf '%s' "$runner_json" | jq -r '.gitHubUrl // empty' 2>/dev/null || true)"
    if [ -z "$gh_url" ]; then
        die "--jitconfig-file .runner omits or empties gitHubUrl, so its repository identity cannot be verified against '${expected_url}'; use --token-file (or interactive token registration) or provide a JIT config bound to '${expected_url}'"
    fi
    local norm_got="${gh_url%/}" norm_want="${expected_url%/}"
    if [ "${norm_got,,}" != "${norm_want,,}" ]; then
        die "--jitconfig-file gitHubUrl '${gh_url}' does not match registration target '${expected_url}'"
    fi

    # If a runner group is set, verify .runner poolName matches and is never Default.
    if [ -n "$OPT_RUNNER_GROUP" ]; then
        pool_name="$(printf '%s' "$runner_json" | jq -r '.poolName // empty' 2>/dev/null || true)"
        if [ -z "$pool_name" ] || [ "${pool_name,,}" = "default" ] || [ "$pool_name" != "$OPT_RUNNER_GROUP" ]; then
            die "--jitconfig-file .runner poolName '${pool_name:-<missing>}' does not match required runner group '${OPT_RUNNER_GROUP}'"
        fi
    fi

    if [[ "$wf" == /* ]]; then
        check_abs_path "JIT workFolder" "$wf"
        wf="${wf%/}"
        local work_root="${OPT_STATE_DIR}/work"
        if [ "$wf" != "$work_root" ]; then
            die "refusing JIT workFolder '$wf' (absolute JIT workspace must be exact dedicated directory '$work_root', never a nested path or protected state directory)"
        fi
        echo "$wf"
    else
        [[ "$wf" =~ ^[A-Za-z0-9._-]+$ ]] \
            || die "refusing unsafe relative JIT workFolder '$wf' (expected a single directory name like _work or exact '${OPT_STATE_DIR}/work')"
        case "$wf" in
            . | .. | .* | bin | externals | _diag | run.sh | config.sh | env.sh)
                die "refusing reserved JIT workFolder '$wf'"
                ;;
        esac
        echo "${OPT_INSTALL_DIR}/${wf}"
    fi
}

# ---- option parsing -------------------------------------------------------

OPT_REPO=""
OPT_ORG=""
OPT_RUNNER_GROUP=""
OPT_ALLOW_REPO=""
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
OPT_CONFIRM_VOLUMES=0
OPT_CONFIRM_ACCOUNT_MARKER=0
OPT_OUT=""
OPT_DEST=""
OPT_URL=""
OPT_ALLOW_EVENTS=()
OPT_ALLOW_REFS=()
OPT_ALLOW_WORKFLOWS=()
OPT_ALLOW_ACTORS=()
OPT_ALLOW_IPS=()

# Track whether paths/identities/policies were explicitly set on the CLI (for update/uninstall verification).
SET_USER=0
SET_SERVICE=0
SET_INSTALL_DIR=0
SET_STATE_DIR=0
SET_HOOK_DIR=0
SET_EPHEMERAL=0
SET_ALLOW_AUTO_UPDATE=0

TARGET_URL=""
ALLOWED_REPO_SLUG=""
RESOLVED_WORK_DIR=""

parse_common_opts() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --token | --token=* | --jitconfig | --jitconfig=*)
                die "refusing ${1%%=*} on the command line (visible in ps and shell history); use interactive prompt, --token-file PATH (mode 0600), --token-file - (stdin), --jitconfig-file PATH, or QEMINGA_RUNNER_TOKEN"
                ;;
            --repo) [ $# -ge 2 ] || die "--repo needs a value"; OPT_REPO="$(check_repo_url "$2")"; shift 2 ;;
            --org) [ $# -ge 2 ] || die "--org needs a value"; OPT_ORG="$(check_org_url "$2")"; shift 2 ;;
            --runner-group) [ $# -ge 2 ] || die "--runner-group needs a value"; check_runner_group "$2"; OPT_RUNNER_GROUP="$2"; shift 2 ;;
            --allow-repo) [ $# -ge 2 ] || die "--allow-repo needs a value"; check_repo_slug "$2"; OPT_ALLOW_REPO="$2"; shift 2 ;;
            --arch) [ $# -ge 2 ] || die "--arch needs a value"; OPT_ARCH="$(normalize_arch "$2")"; shift 2 ;;
            --name) [ $# -ge 2 ] || die "--name needs a value"; check_runner_name "$2"; OPT_NAME="$2"; shift 2 ;;
            --labels) [ $# -ge 2 ] || die "--labels needs a value"; check_labels "$2"; OPT_LABELS="$2"; shift 2 ;;
            --user) [ $# -ge 2 ] || die "--user needs a value"; check_user_name "$2"; OPT_USER="$2"; SET_USER=1; shift 2 ;;
            --service) [ $# -ge 2 ] || die "--service needs a value"; check_service_name "$2"; OPT_SERVICE="$2"; SET_SERVICE=1; shift 2 ;;
            --install-dir) [ $# -ge 2 ] || die "--install-dir needs a value"; check_abs_path --install-dir "$2"; OPT_INSTALL_DIR="${2%/}"; SET_INSTALL_DIR=1; shift 2 ;;
            --state-dir) [ $# -ge 2 ] || die "--state-dir needs a value"; check_abs_path --state-dir "$2"; OPT_STATE_DIR="${2%/}"; SET_STATE_DIR=1; shift 2 ;;
            --hook-dir) [ $# -ge 2 ] || die "--hook-dir needs a value"; check_abs_path --hook-dir "$2"; OPT_HOOK_DIR="${2%/}"; SET_HOOK_DIR=1; shift 2 ;;
            --config-dir) [ $# -ge 2 ] || die "--config-dir needs a value"; check_abs_path --config-dir "$2"; OPT_CONFIG_DIR="${2%/}"; shift 2 ;;
            --token-file) [ $# -ge 2 ] || die "--token-file needs a value"; OPT_TOKEN_FILE="$2"; shift 2 ;;
            --jitconfig-file) [ $# -ge 2 ] || die "--jitconfig-file needs a value"; OPT_JITCONFIG_FILE="$2"; OPT_EPHEMERAL=1; SET_EPHEMERAL=1; shift 2 ;;
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
            --allow-auto-update) OPT_ALLOW_AUTO_UPDATE=1; SET_ALLOW_AUTO_UPDATE=1; shift ;;
            --ephemeral) OPT_EPHEMERAL=1; SET_EPHEMERAL=1; shift ;;
            --no-lan-deny) OPT_NO_LAN_DENY=1; shift ;;
            --skip-packages) OPT_SKIP_PACKAGES=1; shift ;;
            --no-start) OPT_NO_START=1; shift ;;
            --purge-user) OPT_PURGE_USER=1; shift ;;
            --confirm-volumes) OPT_CONFIRM_VOLUMES=1; shift ;;
            --confirm-account-marker) OPT_CONFIRM_ACCOUNT_MARKER=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) die "unknown option '$1' (run with --help)" ;;
        esac
    done
}

resolve_target_registration() {
    local subcmd="$1"
    if [ -n "$OPT_REPO" ] && [ -n "$OPT_ORG" ]; then
        die "$subcmd: --repo and --org are mutually exclusive"
    fi
    if [ -n "$OPT_ORG" ]; then
        if [ -n "$OPT_JITCONFIG_FILE" ]; then
            die "$subcmd: --jitconfig-file is not supported with --org because a JIT config blob does not cryptographically bind the GitHub organization runner group; use a private --repo controller with --jitconfig-file, or use --org --runner-group with --token-file"
        fi
        [ -n "$OPT_RUNNER_GROUP" ] || die "$subcmd: --org requires --runner-group GROUP (restricted by GitHub to the reviewed workflow and ref)"
        [ -n "$OPT_ALLOW_REPO" ] || die "$subcmd: --org requires --allow-repo OWNER/REPO for the job-admission hook policy"
        TARGET_URL="$OPT_ORG"
        ALLOWED_REPO_SLUG="$OPT_ALLOW_REPO"
    elif [ -n "$OPT_REPO" ]; then
        [ -z "$OPT_RUNNER_GROUP" ] || die "$subcmd: --runner-group applies only with --org"
        [ -z "$OPT_ALLOW_REPO" ] || die "$subcmd: --allow-repo applies only with --org"
        TARGET_URL="$OPT_REPO"
        ALLOWED_REPO_SLUG="$(repo_slug_of "$OPT_REPO")"
    else
        die "$subcmd requires --repo https://github.com/OWNER/PRIVATE-CONTROLLER or --org https://github.com/ORG --runner-group GROUP --allow-repo OWNER/REPO"
    fi
}

finalize_policy_defaults() {
    [ ${#OPT_ALLOW_EVENTS[@]} -gt 0 ] || OPT_ALLOW_EVENTS=("$DEFAULT_EVENT")
    [ ${#OPT_ALLOW_REFS[@]} -gt 0 ] || OPT_ALLOW_REFS=("$DEFAULT_REF")
    [ ${#OPT_ALLOW_WORKFLOWS[@]} -gt 0 ] || OPT_ALLOW_WORKFLOWS=("$DEFAULT_WORKFLOW")
    [ -n "$RESOLVED_WORK_DIR" ] || RESOLVED_WORK_DIR="${OPT_STATE_DIR}/work"
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
    mv -T -f -- "$tmp" "$dest"
    trap - RETURN
    echo "verified actions/runner v${ver} (${arch}): sha256=${got}"
}

# ---- render-hooks ---------------------------------------------------------

# Create a private 0600 sibling staging path next to $dest (using pure bash
# path splitting so minimal PATH environments need no external dirname/basename).
stage_managed_file_path() {
    local dest="$1" parent base
    base="${dest##*/}"
    parent="${dest%/*}"
    [ -n "$parent" ] || parent="/"
    umask 0077 && mktemp "${parent}/.${base}.XXXXXX"
}

# Finalize ownership/mode on an already-complete private staging file $tmp and
# atomically replace $dest via fs_ops replace-file (checking live kernel mnt_id,
# mountinfo, non-symlink/regular-file destination, and rename(2)).
commit_managed_file() {
    local tmp="$1" dest="$2" mode="$3" owner="${4:-}" group="${5:-}"
    if [ -n "$owner" ] && [ -n "$group" ]; then
        if ! chown -h "${owner}:${group}" "$tmp"; then
            rm -f "$tmp"
            die "failed to set ownership on staging file for '$dest'"
        fi
    fi
    if ! chmod "$mode" "$tmp"; then
        rm -f "$tmp"
        die "failed to set mode $mode on staging file for '$dest'"
    fi
    if ! fs_ops replace-file "$tmp" "$dest"; then
        rm -f "$tmp"
        die "refusing to overwrite '$dest' (mount point, symlink, or unsafe destination)"
    fi
}

# Render using a producer command/function directly into a private 0600 sibling
# staging file, check the producer's exit status BEFORE finalizing ownership,
# mode, or rename(2), and remove the staging file on any failure so a failed
# producer can never replace $dest with partial output.
publish_managed_file_cmd() {
    local dest="$1" mode="$2" owner="$3" group="$4"
    shift 4
    local tmp
    tmp="$(stage_managed_file_path "$dest")" \
        || die "failed to create staging file for '$dest'"
    if ! "$@" >"$tmp"; then
        rm -f "$tmp"
        die "failed to render managed file '$dest'"
    fi
    commit_managed_file "$tmp" "$dest" "$mode" "$owner" "$group"
}

# Atomically publish a materialized heredoc/file from stdin to a managed file
# without opening or truncating the destination path. Never pipe a concurrent
# producer into this helper (use publish_managed_file_cmd or stage+commit).
publish_managed_file() {
    local dest="$1" mode="$2" owner="${3:-}" group="${4:-}"
    local tmp
    tmp="$(stage_managed_file_path "$dest")" \
        || die "failed to create staging file for '$dest'"
    if ! cat >"$tmp"; then
        rm -f "$tmp"
        die "failed to write staging file for '$dest'"
    fi
    commit_managed_file "$tmp" "$dest" "$mode" "$owner" "$group"
}

write_policy_file() {
    local dest="$1" slug="$2" mode="${3:-0644}" owner="${4:-}" group="${5:-}"
    local work_dir="${RESOLVED_WORK_DIR:-${OPT_STATE_DIR}/work}"
    local deny_lan=1
    [ "$OPT_NO_LAN_DENY" -eq 1 ] && deny_lan=0
    publish_managed_file "$dest" "$mode" "$owner" "$group" <<EOF
# Managed by scripts/setup-kvm-runner.sh — root-owned, read-only to runner.
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
ALLOWED_REPOSITORY=${slug}
ALLOWED_EVENTS=${OPT_ALLOW_EVENTS[*]}
ALLOWED_REFS=${OPT_ALLOW_REFS[*]}
ALLOWED_WORKFLOWS=${OPT_ALLOW_WORKFLOWS[*]}
ALLOWED_ACTORS=${OPT_ALLOW_ACTORS[*]}
INSTALL_DIR=${OPT_INSTALL_DIR}
STATE_DIR=${OPT_STATE_DIR}
WORK_DIR=${work_dir}
IMAGES_DIR=${OPT_STATE_DIR}/images
IMAGE_CACHE_DIR=${OPT_STATE_DIR}/image-cache
STATE_VOL=${VOL_STATE_DIR:-}
INSTALL_VOL=${VOL_INSTALL_DIR:-}
DENY_LAN=${deny_lan}
LIBVIRT_CONNECT=qemu:///session
EOF
}

write_job_started_hook() {
    local dest="$1" owner="${2:-}" group="${3:-}"
    publish_managed_file "$dest" 0755 "$owner" "$group" <<'EOF'
#!/usr/bin/env bash
# Host-enforced pre-job admission guard for qeminga KVM self-hosted runners
# (defense in depth alongside GitHub-side assignment restrictions).
# Installed root-owned (0755) outside the runner directory and wired via the
# systemd unit's Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED so a workflow job
# cannot modify or bypass it.
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
        INSTALL_DIR | STATE_DIR | WORK_DIR | IMAGES_DIR | IMAGE_CACHE_DIR | STATE_VOL | INSTALL_VOL | DENY_LAN) ;;
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
}

write_job_completed_hook() {
    local dest="$1" owner="${2:-}" group="${3:-}"
    publish_managed_file "$dest" 0755 "$owner" "$group" <<'EOF'
#!/usr/bin/env bash
# Host-enforced post-job cleanup hook for qeminga KVM self-hosted runners.
# Installed root-owned (0755) and wired via ACTIONS_RUNNER_HOOK_JOB_COMPLETED.
# Destroys/undefines only stray qeminga-e2e-* session domains, removes their
# run directories only after confirming the domain is absent, and scrubs the
# runner work directory (including validated JIT workspaces) while preserving
# the SHA-256-verified image cache.
set -uo pipefail
export LC_ALL=C LANG=C

POLICY="${QEMINGA_RUNNER_POLICY:-/etc/qeminga-runner/policy.env}"

log() { echo "qeminga-runner-cleanup: $*"; }
die() { echo "qeminga-runner-cleanup: $*" >&2; exit 1; }

DOMAINS_ONLY=0
if [ "${1:-}" = "--domains-only" ]; then
    DOMAINS_ONLY=1
    shift
fi
[ $# -eq 0 ] || die "unexpected argument '$1'"

if [ ! -f "$POLICY" ] || [ ! -r "$POLICY" ]; then
    die "missing or unreadable policy file $POLICY"
fi

INSTALL_DIR=""
STATE_DIR=""
WORK_DIR=""
IMAGES_DIR=""
STATE_VOL=""
INSTALL_VOL=""
LIBVIRT_CONNECT="qemu:///session"

while IFS='=' read -r key val; do
    case "$key" in
        '' | '#'*) continue ;;
        INSTALL_DIR) INSTALL_DIR="$val" ;;
        STATE_DIR) STATE_DIR="$val" ;;
        WORK_DIR) WORK_DIR="$val" ;;
        IMAGES_DIR) IMAGES_DIR="$val" ;;
        STATE_VOL) STATE_VOL="$val" ;;
        INSTALL_VOL) INSTALL_VOL="$val" ;;
        LIBVIRT_CONNECT) LIBVIRT_CONNECT="$val" ;;
    esac
done <"$POLICY"

if [ -n "$STATE_VOL" ] && [[ ! "$STATE_VOL" =~ ^[A-Za-z0-9._/%:,+-]+$ ]]; then
    die "refusing malformed STATE_VOL '$STATE_VOL'"
fi
if [ -n "$INSTALL_VOL" ] && [[ ! "$INSTALL_VOL" =~ ^[A-Za-z0-9._/%:,+-]+$ ]]; then
    die "refusing malformed INSTALL_VOL '$INSTALL_VOL'"
fi

safe_path_syntax() {
    local p="$1"
    [[ "$p" =~ ^/[A-Za-z0-9._/-]+$ ]] || return 1
    [ "$p" != "/" ] || return 1
    case "$p" in
        */../* | */.. | */./* | */. | *//*) return 1 ;;
    esac
}

safe_subdir() {
    local p="$1"
    safe_path_syntax "$p" || return 1
    [ -n "$STATE_DIR" ] && [ "${p#"$STATE_DIR"/}" != "$p" ]
}

safe_work_dir() {
    local p="$1" rel work_root
    safe_path_syntax "$p" || return 1
    p="${p%/}"
    if [ -n "$STATE_DIR" ] && safe_path_syntax "$STATE_DIR"; then
        work_root="${STATE_DIR%/}/work"
        if [ "$p" = "$work_root" ]; then
            return 0
        fi
    fi
    # Validated JIT workspaces (e.g. GitHub API default `_work`) live directly
    # under INSTALL_DIR as a single non-reserved component.
    if [ -n "$INSTALL_DIR" ] && safe_path_syntax "$INSTALL_DIR" && [ "${p#"$INSTALL_DIR"/}" != "$p" ]; then
        rel="${p#"$INSTALL_DIR"/}"
        [[ "$rel" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
        case "$rel" in
            . | .. | .* | bin | externals | _diag | run.sh | config.sh | env.sh) return 1 ;;
        esac
        return 0
    fi
    return 1
}

paths_overlap() {
    local a="${1%/}" b="${2%/}"
    [ -n "$a" ] && [ -n "$b" ] || return 1
    [ "$a" = "$b" ] || [ "${a#"$b"/}" != "$a" ] || [ "${b#"$a"/}" != "$b" ]
}

no_symlink_components() {
    local target="${1%/}" cur
    [ -n "$target" ] || return 1
    cur="$target"
    while [ "$cur" != "/" ]; do
        [ ! -L "$cur" ] || return 1
        cur="$(dirname "$cur")"
    done
    [ ! -L "/" ]
}

verify_work_dir_safe() {
    safe_work_dir "$WORK_DIR" || die "refusing unsafe WORK_DIR '$WORK_DIR'"
    no_symlink_components "$WORK_DIR" || die "refusing symlinked component in WORK_DIR '$WORK_DIR'"
    local protected real_work="" real_prot=""
    if [ -e "$WORK_DIR" ]; then
        [ -d "$WORK_DIR" ] || die "refusing non-directory WORK_DIR '$WORK_DIR'"
        real_work="$(readlink -f -- "$WORK_DIR" 2>/dev/null || true)"
    fi
    for protected in "$IMAGES_DIR" "${STATE_DIR%/}/images" "${STATE_DIR%/}/image-cache" "${STATE_DIR%/}/.config" "${STATE_DIR%/}/.cache" "${STATE_DIR%/}/.local"; do
        if paths_overlap "$WORK_DIR" "$protected"; then
            die "refusing WORK_DIR '$WORK_DIR' overlapping protected state path '$protected'"
        fi
        if [ -n "$real_work" ] && [ -e "$protected" ]; then
            real_prot="$(readlink -f -- "$protected" 2>/dev/null || true)"
            if [ -n "$real_prot" ] && paths_overlap "$real_work" "$real_prot"; then
                die "refusing WORK_DIR '$WORK_DIR' resolving to '$real_work' overlapping protected state path '$real_prot'"
            fi
        fi
    done
}

# Perform STATE_DIR- and INSTALL_DIR-anchored operations on $STATE_DIR/images
# (and WORK_DIR scrubbing) using kernel O_PATH | O_DIRECTORY | O_NOFOLLOW
# traversal from / down through search-only (e.g. 0711) ancestor directories,
# verifying the opened parent FD against the recorded STATE_VOL / INSTALL_VOL
# (fstype, filesystem-relative root path, block UUID or source, and f_fsid —
# tolerating systemd's own self-bind-mounts while rejecting overmounts and
# same-filesystem replacement binds), and verifying BOTH st_dev AND kernel
# mnt_id (/proc/self/fdinfo + /proc/self/mountinfo) on every traversed entry.
images_ops() {
    local op="$1"
    shift
    local py="/usr/bin/python3"
    [ -x "$py" ] || die "/usr/bin/python3 is required for safe O_NOFOLLOW image cleanup"
    env -i PATH=/usr/bin:/bin HOME=/nonexistent "$py" -I -S - \
        "$op" "$STATE_DIR" "$INSTALL_DIR" "$STATE_VOL" "$INSTALL_VOL" "$@" <<'PY'
import errno
import os
import re
import stat
import sys

RUN_RE = re.compile(r"^qeminga-e2e-[0-9]+-[0-9]+-[a-z0-9_]+$")
PATH_DIR_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
READ_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def unescape_mountinfo(field):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def pct_decode(val):
    out = bytearray()
    i = 0
    n = len(val)
    while i < n:
        if val[i] == "%" and i + 2 < n:
            try:
                out.append(int(val[i + 1 : i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.extend(val[i].encode("utf-8", errors="surrogateescape"))
        i += 1
    return out.decode("utf-8", errors="surrogateescape")


def parse_mountinfo():
    entries = []
    with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if " - " not in line:
                continue
            left, right = line.split(" - ", 1)
            lparts = left.split(" ")
            rparts = right.split(" ")
            if len(lparts) < 5 or len(rparts) < 2:
                continue
            mp = unescape_mountinfo(lparts[4])
            if mp != "/":
                mp = mp.rstrip("/")
            entries.append(
                {
                    "mount_id": int(lparts[0]),
                    "parent_id": int(lparts[1]),
                    "dev": lparts[2],
                    "root": unescape_mountinfo(lparts[3]),
                    "mp": mp,
                    "fstype": unescape_mountinfo(rparts[0]),
                    "source": unescape_mountinfo(rparts[1]),
                }
            )
    if not entries:
        raise OSError(errno.EINVAL, "empty or unreadable /proc/self/mountinfo")
    return entries


def resolve_mount_in_tree(entries, norm_path):
    by_id = {e["mount_id"]: e for e in entries}
    children = {}
    root_entry = None
    for entry in entries:
        children[(entry["parent_id"], entry["mp"])] = entry
        if entry["mp"] == "/" and entry["parent_id"] not in by_id:
            root_entry = entry
    if root_entry is None:
        for entry in entries:
            if entry["mp"] == "/":
                root_entry = entry
    if root_entry is None:
        raise OSError(errno.ENOENT, f"no root mount entry covers '{norm_path}'")

    cur = root_entry
    seen = {cur["mount_id"]}
    while (cur["mount_id"], "/") in children:
        nxt = children[(cur["mount_id"], "/")]
        if nxt["mount_id"] in seen:
            break
        seen.add(nxt["mount_id"])
        cur = nxt

    if norm_path == "/":
        return cur

    prefix = ""
    for part in [p for p in norm_path.split("/") if p]:
        prefix = f"{prefix}/{part}"
        while (cur["mount_id"], prefix) in children:
            nxt = children[(cur["mount_id"], prefix)]
            if nxt["mount_id"] in seen:
                break
            seen.add(nxt["mount_id"])
            cur = nxt
    return cur


def visible_mountpoints(entries):
    mps = set()
    for entry in entries:
        mp = entry["mp"]
        try:
            top = resolve_mount_in_tree(entries, mp)
        except OSError:
            continue
        if top["mp"] == mp:
            mps.add(mp)
    return mps


def fd_mnt_id(fd):
    with open(f"/proc/self/fdinfo/{fd}", "r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1].strip())
    raise OSError(errno.EINVAL, f"missing mnt_id in /proc/self/fdinfo/{fd}")


def parse_vol_fingerprint(vol_str):
    fields = {}
    for item in vol_str.split(","):
        if ":" not in item:
            raise OSError(errno.EINVAL, f"malformed recorded volume fingerprint '{vol_str}'")
        k, v = item.split(":", 1)
        if not k or k in fields:
            raise OSError(errno.EINVAL, f"malformed recorded volume fingerprint '{vol_str}'")
        fields[k] = pct_decode(v)
    for req in ("mp", "root", "fs"):
        if req not in fields or not fields[req]:
            raise OSError(errno.EINVAL, f"incomplete recorded volume fingerprint '{vol_str}'")
    if "uuid" not in fields and "src" not in fields:
        raise OSError(errno.EINVAL, f"recorded volume fingerprint '{vol_str}' missing uuid/src")
    return fields


def fs_rel_path(abs_path, mp, root):
    norm = "/" if abs_path == "/" else abs_path.rstrip("/")
    mp_norm = "/" if mp == "/" else mp.rstrip("/")
    if mp_norm == "/":
        rel = norm.lstrip("/")
    elif norm == mp_norm:
        rel = ""
    elif norm.startswith(mp_norm + "/"):
        rel = norm[len(mp_norm) + 1 :]
    else:
        return None
    base = root if root.startswith("/") else "/" + root
    joined = base if not rel else (base.rstrip("/") + "/" + rel)
    return os.path.normpath(joined)


def resolve_live_block_uuid(source):
    if not source.startswith("/dev/"):
        return ""
    try:
        src_st = os.stat(source)
    except OSError:
        return ""
    if not stat.S_ISBLK(src_st.st_mode):
        return ""
    by_uuid = "/dev/disk/by-uuid"
    try:
        for name in sorted(os.listdir(by_uuid)):
            try:
                lst = os.stat(os.path.join(by_uuid, name))
            except OSError:
                continue
            if stat.S_ISBLK(lst.st_mode) and lst.st_rdev == src_st.st_rdev:
                return name
    except OSError:
        pass
    return ""


def verify_parent_volume_matches(parent_fd, parent_abs, expected_vol, entries):
    exp = parse_vol_fingerprint(expected_vol)
    norm_parent = "/" if parent_abs == "/" else parent_abs.rstrip("/")
    exp_rel = fs_rel_path(norm_parent, exp["mp"], exp["root"])
    if exp_rel is None:
        raise OSError(
            errno.EXDEV,
            f"recorded volume mountpoint '{exp['mp']}' does not cover '{norm_parent}'",
        )
    actual_mnt = fd_mnt_id(parent_fd)
    by_id = {e["mount_id"]: e for e in entries}
    entry = by_id.get(actual_mnt)
    if entry is None:
        raise OSError(
            errno.EXDEV,
            f"mount_id {actual_mnt} for '{norm_parent}' not found in /proc/self/mountinfo",
        )
    if entry["fstype"] != exp["fs"]:
        raise OSError(
            errno.EXDEV,
            f"'{norm_parent}' filesystem type '{entry['fstype']}' does not match recorded '{exp['fs']}'",
        )
    act_rel = fs_rel_path(norm_parent, entry["mp"], entry["root"])
    if act_rel != exp_rel:
        raise OSError(
            errno.EXDEV,
            f"'{norm_parent}' filesystem root path '{act_rel}' does not match recorded '{exp_rel}'",
        )
    if "uuid" in exp:
        live_uuid = resolve_live_block_uuid(entry["source"])
        if live_uuid != exp["uuid"]:
            raise OSError(
                errno.EXDEV,
                f"'{norm_parent}' filesystem UUID '{live_uuid or '<none>'}' does not match recorded '{exp['uuid']}'",
            )
    else:
        if entry["source"] != exp["src"]:
            raise OSError(
                errno.EXDEV,
                f"'{norm_parent}' mount source '{entry['source']}' does not match recorded '{exp['src']}'",
            )
    if "fsid" in exp:
        try:
            fsid_num = os.fstatvfs(parent_fd).f_fsid
        except OSError as exc:
            raise OSError(
                errno.EXDEV, f"cannot read fstatvfs f_fsid for '{norm_parent}': {exc}"
            ) from exc
        live_fsid = f"{fsid_num:x}" if fsid_num else ""
        if live_fsid != exp["fsid"]:
            raise OSError(
                errno.EXDEV,
                f"'{norm_parent}' filesystem fsid '{live_fsid or '<none>'}' does not match recorded '{exp['fsid']}'",
            )


def assert_no_mount_at_or_under(abs_path, mountpoints, include_self=True):
    norm = "/" if abs_path == "/" else abs_path.rstrip("/")
    prefix = "/" if norm == "/" else norm + "/"
    for mp in mountpoints:
        if include_self and mp == norm:
            raise OSError(errno.EXDEV, f"refusing to cross mount point '{mp}'")
        if mp.startswith(prefix):
            raise OSError(errno.EXDEV, f"refusing to cross mount point '{mp}' under '{norm}'")


def open_chain_opath(abs_path):
    parts = [p for p in abs_path.split("/") if p]
    fd = os.open("/", PATH_DIR_FLAGS)
    try:
        for part in parts:
            nxt = os.open(part, PATH_DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except Exception:
        os.close(fd)
        raise


def open_child_dir_same_mount(parent_fd, name, child_abs, mountpoints):
    if child_abs in mountpoints:
        raise OSError(errno.EXDEV, f"refusing to cross mount point '{child_abs}'")
    pst = os.fstat(parent_fd)
    p_mnt = fd_mnt_id(parent_fd)
    cfd = os.open(name, READ_DIR_FLAGS, dir_fd=parent_fd)
    try:
        cst = os.fstat(cfd)
        if cst.st_dev != pst.st_dev or fd_mnt_id(cfd) != p_mnt:
            raise OSError(errno.EXDEV, f"'{child_abs}' crosses mount boundary")
        return cfd
    except Exception:
        os.close(cfd)
        raise


def open_images_fd(state_dir, expected_state_vol, entries, mountpoints):
    if not expected_state_vol:
        raise OSError(
            errno.EINVAL,
            "missing recorded STATE_VOL in policy.env; refusing cleanup (run 'migrate-record --confirm-volumes' or reinstall)",
        )
    images_root = f"{state_dir.rstrip('/')}/images"
    state_fd = open_chain_opath(state_dir)
    try:
        verify_parent_volume_matches(state_fd, state_dir, expected_state_vol, entries)
        try:
            return open_child_dir_same_mount(state_fd, "images", images_root, mountpoints)
        except FileNotFoundError:
            return None
    finally:
        os.close(state_fd)


def assert_entry_same_mount(parent_fd, name, root_dev, root_mnt_id, cur_path, mountpoints):
    if cur_path in mountpoints:
        raise OSError(errno.EXDEV, f"refusing to cross mount point '{cur_path}'")
    efd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        est = os.fstat(efd)
        if fd_mnt_id(efd) != root_mnt_id:
            raise OSError(errno.EXDEV, f"'{cur_path}' crosses mount boundary")
        if stat.S_ISDIR(est.st_mode) and est.st_dev != root_dev:
            raise OSError(errno.EXDEV, f"'{cur_path}' crosses filesystem boundary")
        return est
    finally:
        os.close(efd)


def scan_dir_same_mount(parent_fd, name, root_dev, root_mnt_id, cur_path, mountpoints):
    if cur_path in mountpoints:
        raise OSError(errno.EXDEV, f"refusing to cross mount point '{cur_path}'")
    st = os.lstat(name, dir_fd=parent_fd)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return
    if st.st_dev != root_dev:
        raise OSError(errno.EXDEV, f"'{cur_path}' crosses filesystem boundary")
    dir_fd = os.open(name, READ_DIR_FLAGS, dir_fd=parent_fd)
    try:
        if os.fstat(dir_fd).st_dev != root_dev or fd_mnt_id(dir_fd) != root_mnt_id:
            raise OSError(errno.EXDEV, f"'{cur_path}' crosses mount boundary")
        for entry in os.listdir(dir_fd):
            child_path = f"{cur_path}/{entry}"
            est = assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
            if stat.S_ISDIR(est.st_mode):
                scan_dir_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
    finally:
        os.close(dir_fd)


def rmtree_same_mount(parent_fd, name, root_dev, root_mnt_id, cur_path, mountpoints):
    if cur_path in mountpoints:
        raise OSError(errno.EXDEV, f"refusing to cross mount point '{cur_path}'")
    st = os.lstat(name, dir_fd=parent_fd)
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.ENOTDIR, f"{name} is not a real directory")
    if st.st_dev != root_dev:
        raise OSError(errno.EXDEV, f"{name} crosses filesystem boundary")
    dir_fd = os.open(name, READ_DIR_FLAGS, dir_fd=parent_fd)
    try:
        fst = os.fstat(dir_fd)
        if fst.st_dev != root_dev or fd_mnt_id(dir_fd) != root_mnt_id:
            raise OSError(errno.EXDEV, f"{name} crosses mount boundary")
        if (fst.st_mode & 0o700) != 0o700:
            os.fchmod(dir_fd, (fst.st_mode & 0o7777) | 0o700)
        for entry in os.listdir(dir_fd):
            child_path = f"{cur_path}/{entry}"
            est = assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
            if stat.S_ISDIR(est.st_mode):
                rmtree_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
            else:
                os.unlink(entry, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    os.rmdir(name, dir_fd=parent_fd)


op = sys.argv[1]
state_dir = sys.argv[2]
install_dir = sys.argv[3]
state_vol = sys.argv[4]
install_vol = sys.argv[5]

if op == "scrub-work":
    work_dir = sys.argv[6].rstrip("/")
    try:
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(work_dir, mountpoints, include_self=True)
        parent = os.path.dirname(work_dir) or "/"
        base = os.path.basename(work_dir)
        norm_state = state_dir.rstrip("/")
        norm_install = install_dir.rstrip("/") if install_dir else ""
        if parent == norm_state:
            expected_parent_vol = state_vol
            vol_key = "STATE_VOL"
        elif norm_install and parent == norm_install:
            expected_parent_vol = install_vol
            vol_key = "INSTALL_VOL"
        else:
            raise OSError(errno.EXDEV, f"unexpected WORK_DIR parent '{parent}'")
        if not expected_parent_vol:
            raise OSError(
                errno.EINVAL,
                f"missing recorded {vol_key} in policy.env; refusing work cleanup (run 'migrate-record --confirm-volumes' or reinstall)",
            )
        pfd = open_chain_opath(parent)
        try:
            verify_parent_volume_matches(pfd, parent, expected_parent_vol, entries)
            try:
                wfd = open_child_dir_same_mount(pfd, base, work_dir, mountpoints)
            except FileNotFoundError:
                sys.exit(0)
        finally:
            os.close(pfd)
        try:
            wst = os.fstat(wfd)
            w_mnt = fd_mnt_id(wfd)
            w_entries = os.listdir(wfd)
            for entry in w_entries:
                child_path = f"{work_dir}/{entry}"
                est = assert_entry_same_mount(wfd, entry, wst.st_dev, w_mnt, child_path, mountpoints)
                if stat.S_ISDIR(est.st_mode):
                    scan_dir_same_mount(wfd, entry, wst.st_dev, w_mnt, child_path, mountpoints)
            for entry in w_entries:
                child_path = f"{work_dir}/{entry}"
                est = assert_entry_same_mount(wfd, entry, wst.st_dev, w_mnt, child_path, mountpoints)
                if stat.S_ISDIR(est.st_mode):
                    rmtree_same_mount(wfd, entry, wst.st_dev, w_mnt, child_path, mountpoints)
                else:
                    os.unlink(entry, dir_fd=wfd)
        finally:
            os.close(wfd)
    except OSError as exc:
        sys.stderr.write(f"qeminga-runner-cleanup: work cleanup failed: {exc}\n")
        sys.exit(1)
    sys.exit(0)

try:
    entries = parse_mountinfo()
    mountpoints = visible_mountpoints(entries)
    img_fd = open_images_fd(state_dir, state_vol, entries, mountpoints)
except OSError as exc:
    sys.stderr.write(
        f"qeminga-runner-cleanup: refusing unsafe images directory under {state_dir}: {exc}\n"
    )
    sys.exit(1)

if img_fd is None:
    sys.exit(0)

try:
    img_st = os.fstat(img_fd)
    img_mnt = fd_mnt_id(img_fd)
    images_root = f"{state_dir.rstrip('/')}/images"
    if op == "verify":
        sys.exit(0)
    elif op == "list":
        for entry in sorted(os.listdir(img_fd)):
            if not RUN_RE.match(entry):
                continue
            try:
                est = os.lstat(entry, dir_fd=img_fd)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(est.st_mode):
                sys.stderr.write(
                    f"qeminga-runner-cleanup: refusing symlinked run entry '{entry}' under images\n"
                )
                sys.exit(1)
            print(entry)
    elif op == "remove":
        dom = sys.argv[6]
        if not RUN_RE.match(dom):
            sys.stderr.write(f"qeminga-runner-cleanup: refusing invalid run dir name '{dom}'\n")
            sys.exit(1)
        try:
            est = os.lstat(dom, dir_fd=img_fd)
        except FileNotFoundError:
            sys.exit(0)
        if stat.S_ISLNK(est.st_mode) or not stat.S_ISDIR(est.st_mode):
            sys.stderr.write(
                f"qeminga-runner-cleanup: refusing non-directory or symlinked run entry '{dom}'\n"
            )
            sys.exit(1)
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        dom_path = f"{images_root}/{dom}"
        assert_no_mount_at_or_under(dom_path, mountpoints, include_self=True)
        scan_dir_same_mount(img_fd, dom, img_st.st_dev, img_mnt, dom_path, mountpoints)
        rmtree_same_mount(img_fd, dom, img_st.st_dev, img_mnt, dom_path, mountpoints)
        print("removed")
    else:
        sys.stderr.write(f"qeminga-runner-cleanup: unknown images_ops op '{op}'\n")
        sys.exit(1)
except OSError as exc:
    sys.stderr.write(f"qeminga-runner-cleanup: image cleanup failed ({op}): {exc}\n")
    sys.exit(1)
finally:
    os.close(img_fd)
PY
}

verify_images_dir_safe() {
    safe_path_syntax "$STATE_DIR" || die "refusing unsafe STATE_DIR '$STATE_DIR'"
    safe_subdir "$IMAGES_DIR" || die "refusing unsafe IMAGES_DIR '$IMAGES_DIR'"
    [ "${IMAGES_DIR%/}" = "${STATE_DIR%/}/images" ] \
        || die "refusing IMAGES_DIR '$IMAGES_DIR' not anchored directly at '${STATE_DIR%/}/images'"
    no_symlink_components "$IMAGES_DIR" || die "refusing symlinked component in IMAGES_DIR '$IMAGES_DIR'"
    images_ops verify || die "refusing unsafe images directory '$IMAGES_DIR'"
}

verify_images_dir_safe
if [ "$DOMAINS_ONLY" -eq 0 ]; then
    verify_work_dir_safe
fi
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
            if rm_res="$(images_ops remove "$dom")"; then
                if [ "$rm_res" = "removed" ]; then
                    log "removed ${IMAGES_DIR}/${dom}"
                fi
            else
                rc=1
            fi
        done <<<"$names"
    else
        log "cannot list libvirt domains on $LIBVIRT_CONNECT; keeping any disks under $IMAGES_DIR"
        rc=1
    fi

    # Remove orphan qeminga-e2e-* run directories whose domain is confirmed absent.
    if orphan_bases="$(images_ops list)"; then
        while IFS= read -r base; do
            [ -n "$base" ] || continue
            st="$(domain_state "$base")" || { log "cannot confirm $base absent; keeping ${IMAGES_DIR}/${base}"; rc=1; continue; }
            if [ "$st" = absent ]; then
                if rm_res="$(images_ops remove "$base")"; then
                    [ "$rm_res" = "removed" ] && log "removed orphan run dir ${IMAGES_DIR}/${base}"
                else
                    rc=1
                fi
            else
                log "$base is '$st'; keeping ${IMAGES_DIR}/${base}"
                rc=1
            fi
        done <<<"$orphan_bases"
    else
        rc=1
    fi
else
    if orphan_bases="$(images_ops list)"; then
        if [ -n "$orphan_bases" ]; then
            log "virsh is unavailable while VM run directories remain under $IMAGES_DIR; keeping disks"
            rc=1
        fi
    else
        rc=1
    fi
fi

if [ "$DOMAINS_ONLY" -eq 0 ]; then
    # Re-verify WORK_DIR has no symlinks or protected-state overlap right before
    # scrubbing, and delete direct children without traversing symlinks or mounts.
    verify_work_dir_safe
    if [ -d "$WORK_DIR" ] && [ ! -L "$WORK_DIR" ]; then
        if images_ops scrub-work "$WORK_DIR"; then
            log "scrubbed work directory $WORK_DIR"
        else
            rc=1
        fi
    fi
fi

exit "$rc"
EOF
}

write_egress_firewall_check() {
    local dest="$1" owner="${2:-}" group="${3:-}"
    local py_deny_lan="True"
    [ "$OPT_NO_LAN_DENY" -eq 1 ] && py_deny_lan="False"
    local py_allow_cidrs="" ip
    for ip in "${OPT_ALLOW_IPS[@]}"; do
        py_allow_cidrs="${py_allow_cidrs}${py_allow_cidrs:+, }\"${ip}\""
    done

    local tmp
    tmp="$(stage_managed_file_path "$dest")" \
        || die "failed to create staging file for '$dest'"
    if ! {
        cat <<'EOF' \
            && printf 'DENY_LAN = %s\nALLOW_CIDRS = [%s]\n' "$py_deny_lan" "$py_allow_cidrs" \
            && cat <<'EOF2'
#!/usr/bin/env bash
# Root-owned egress firewall gate (invoked by run-runner.sh / run-jit.sh as
# the main service process before exec'ing the runner listener): verifies that
# THIS unit's systemd cgroup BPF IPAddressDeny= firewall is actively enforced.
# Exits 78 (EX_CONFIG, matched by RestartPreventExitStatus=78) on hosts or
# containers where cgroup BPF filtering is unsupported or silently skipped.
#
# Runs /usr/bin/python3 in isolated mode (-I -S) under a clean env -i so
# runner-writable HOME / user-site / PYTHONPATH / PYTHONSTARTUP / PATH cannot
# influence the check.
set -euo pipefail
export LC_ALL=C LANG=C

PY="/usr/bin/python3"
if [ ! -x "$PY" ]; then
    echo "qeminga-egress-check: /usr/bin/python3 is required to verify cgroup BPF egress filtering" >&2
    exit 78
fi

env -i PATH=/usr/bin:/bin HOME=/nonexistent "$PY" -I -S - <<'PY'
import errno
import ipaddress
import socket
import sys

EOF
ALLOW_NETS = [ipaddress.ip_network(c, strict=False) for c in ALLOW_CIDRS]

UNROUTED = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.EAFNOSUPPORT,
    errno.EADDRNOTAVAIL,
}


def is_allowed(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    return any(ip_obj in net for net in ALLOW_NETS)


def probe_must_deny(label, family, addr, allow_unrouted=True):
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as exc:
        if allow_unrouted and exc.errno in UNROUTED:
            return False
        sys.stderr.write(
            f"qeminga-egress-check: unexpected socket error probing {label} ({addr[0]}): {exc}\n"
        )
        sys.exit(78)
    try:
        sock.sendto(b"x", addr)
    except OSError as exc:
        if exc.errno == errno.EPERM:
            return True
        if allow_unrouted and exc.errno in UNROUTED:
            return False
        sys.stderr.write(
            f"qeminga-egress-check: {label} ({addr[0]}) returned unexpected errno {exc.errno} ({exc.strerror}); cgroup BPF IPAddressDeny= is not proven active\n"
        )
        sys.exit(78)
    else:
        sys.stderr.write(
            f"qeminga-egress-check: {label} ({addr[0]}) was NOT blocked by cgroup BPF IPAddressDeny= (sendto succeeded); refusing to start runner listener\n"
        )
        sys.exit(78)
    finally:
        sock.close()


# 1. Sanity check: permitted loopback (127.0.0.1 in IPAddressAllow=127.0.0.0/9)
#    must NOT be rejected with EPERM (guards against broken/deny-all filters).
try:
    lo_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except OSError as exc:
    sys.stderr.write(f"qeminga-egress-check: cannot open IPv4 loopback socket: {exc}\n")
    sys.exit(78)
try:
    lo_sock.sendto(b"x", ("127.0.0.1", 9))
except OSError as exc:
    if exc.errno == errno.EPERM:
        sys.stderr.write(
            "qeminga-egress-check: permitted loopback 127.0.0.1 returned EPERM; refusing to start runner listener\n"
        )
        sys.exit(78)
finally:
    lo_sock.close()

# 2. Controlled local unit-policy sentinel: 127.255.255.254/32 is always routed
#    on loopback and never blocked by host-wide cloud IMDS rules, so EPERM here
#    specifically proves THIS unit's cgroup BPF IPAddressDeny= is active.
probe_must_deny(
    "unit cgroup BPF loopback sentinel",
    socket.AF_INET,
    ("127.255.255.254", 9),
    allow_unrouted=False,
)

# 3. Unconditional cloud IMDS endpoints (IPAddressDeny=link-local + fd00:ec2::254/128).
IMDS_PROBES = [
    ("IPv4 IMDS", socket.AF_INET, ("169.254.169.254", 80)),
    ("IPv6 IMDS", socket.AF_INET6, ("fd00:ec2::254", 80)),
]
proved_imds = False
for label, family, addr in IMDS_PROBES:
    if probe_must_deny(label, family, addr, allow_unrouted=True):
        proved_imds = True

if not proved_imds:
    sys.stderr.write(
        "qeminga-egress-check: no IMDS probe returned EPERM (cgroup BPF IPAddressDeny= not proven active in this service cgroup); refusing to start runner listener\n"
    )
    sys.exit(78)

# 4. Private LAN / CGNAT / ULA ranges (when default LAN deny is enabled).
if DENY_LAN:
    LAN_PROBES = [
        ("RFC1918 10/8", socket.AF_INET, ("10.255.255.254", 9)),
        ("RFC1918 172.16/12", socket.AF_INET, ("172.31.255.254", 9)),
        ("RFC1918 192.168/16", socket.AF_INET, ("192.168.255.254", 9)),
        ("CGNAT 100.64/10", socket.AF_INET, ("100.127.255.254", 9)),
        ("IPv6 ULA fc00::/7", socket.AF_INET6, ("fdff::1", 9)),
    ]
    for label, family, addr in LAN_PROBES:
        if is_allowed(addr[0]):
            continue
        probe_must_deny(label, family, addr, allow_unrouted=True)

print("qeminga-egress-check: PASS (unit cgroup BPF IPAddressDeny= actively blocks sentinel, IMDS, and configured LAN ranges)")
PY
EOF2
    } >"$tmp"; then
        rm -f "$tmp"
        die "failed to render egress firewall check '$dest'"
    fi
    commit_managed_file "$tmp" "$dest" 0755 "$owner" "$group"
}

write_runner_launcher() {
    local dest="$1" owner="${2:-}" group="${3:-}"
    local tmp
    tmp="$(stage_managed_file_path "$dest")" \
        || die "failed to create staging file for '$dest'"
    if ! {
        cat <<EOF && cat <<'EOF2'
#!/usr/bin/env bash
# Root-owned main-process runner launcher: verifies this unit's cgroup BPF
# egress firewall inside the main service process (so exit 78 triggers
# RestartPreventExitStatus=78, which systemd excludes for ExecStartPre=),
# then execs /usr/bin/python3 -I -S (preserving MainPID for NotifyAccess=main)
# to signal READY=1 to systemd's NOTIFY_SOCKET, strip NOTIFY_SOCKET, and
# exec upstream's bin/runsvc.sh.
set -euo pipefail
HOOK_DIR="${OPT_HOOK_DIR}"
INSTALL_DIR="${OPT_INSTALL_DIR}"
EOF
"${HOOK_DIR}/check-egress-firewall.sh" || exit 78
target="${INSTALL_DIR}/bin/runsvc.sh"
[ -x "$target" ] || { echo "missing executable runner launcher: $target" >&2; exit 1; }
exec /usr/bin/python3 -I -S -c '
import os, socket, sys
target = sys.argv[1]
sock_path = os.environ.pop("NOTIFY_SOCKET", "")
if sock_path:
    addr = ("\0" + sock_path[1:]) if sock_path.startswith("@") else sock_path
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.sendto(b"READY=1\n", addr)
    finally:
        s.close()
os.execv(target, [target])
' "$target"
EOF2
    } >"$tmp"; then
        rm -f "$tmp"
        die "failed to render runner launcher '$dest'"
    fi
    commit_managed_file "$tmp" "$dest" 0755 "$owner" "$group"
}

write_jit_launcher() {
    local dest="$1" owner="${2:-}" group="${3:-}"
    local tmp
    tmp="$(stage_managed_file_path "$dest")" \
        || die "failed to create staging file for '$dest'"
    if ! {
        cat <<EOF && cat <<'EOF2'
#!/usr/bin/env bash
# Root-owned one-shot JIT runner launcher: verifies this unit's cgroup BPF
# egress firewall inside the main service process (so exit 78 triggers
# RestartPreventExitStatus=78), loads the single-use JIT config from systemd
# LoadCredential= into ACTIONS_RUNNER_INPUT_JITCONFIG, then execs
# /usr/bin/python3 -I -S (preserving MainPID for NotifyAccess=main) to signal
# READY=1 to systemd's NOTIFY_SOCKET, strip NOTIFY_SOCKET, and exec
# Runner.Listener directly so no intermediate shell/Node wrapper retains the
# secret in its environment and no run-helper.sh copy is written to the root.
set -euo pipefail
HOOK_DIR="${OPT_HOOK_DIR}"
INSTALL_DIR="${OPT_INSTALL_DIR}"
EOF
"${HOOK_DIR}/check-egress-firewall.sh" || exit 78
cred="${CREDENTIALS_DIRECTORY:?missing CREDENTIALS_DIRECTORY}/jitconfig"
[ -r "$cred" ] || { echo "missing jitconfig credential" >&2; exit 1; }
ACTIONS_RUNNER_INPUT_JITCONFIG="$(tr -d '\r\n' <"$cred")"
export ACTIONS_RUNNER_INPUT_JITCONFIG
target="${INSTALL_DIR}/bin/Runner.Listener"
[ -x "$target" ] || { echo "missing executable runner listener: $target" >&2; exit 1; }
exec /usr/bin/python3 -I -S -c '
import os, socket, sys
target = sys.argv[1]
sock_path = os.environ.pop("NOTIFY_SOCKET", "")
if sock_path:
    addr = ("\0" + sock_path[1:]) if sock_path.startswith("@") else sock_path
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.sendto(b"READY=1\n", addr)
    finally:
        s.close()
os.execv(target, [target, "run", "--startuptype", "service"])
' "$target"
EOF2
    } >"$tmp"; then
        rm -f "$tmp"
        die "failed to render JIT launcher '$dest'"
    fi
    commit_managed_file "$tmp" "$dest" 0755 "$owner" "$group"
}

cmd_render_hooks() {
    parse_common_opts "$@"
    resolve_target_registration render-hooks
    [ -n "$OPT_OUT" ] || die "render-hooks requires --out DIR"
    if [ -n "$OPT_JITCONFIG_FILE" ]; then
        local jit_cfg
        jit_cfg="$(read_secret_file --jitconfig-file "$OPT_JITCONFIG_FILE")"
        RESOLVED_WORK_DIR="$(resolve_jit_work_dir "$jit_cfg" "$TARGET_URL")"
        unset jit_cfg
    fi
    finalize_policy_defaults
    VOL_STATE_DIR=""
    VOL_INSTALL_DIR=""
    if [ -d "$OPT_STATE_DIR" ] && [ ! -L "$OPT_STATE_DIR" ]; then
        VOL_STATE_DIR="$(fs_ops volume-id "$OPT_STATE_DIR" 2>/dev/null || true)"
    fi
    if [ -d "$OPT_INSTALL_DIR" ] && [ ! -L "$OPT_INSTALL_DIR" ]; then
        VOL_INSTALL_DIR="$(fs_ops volume-id "$OPT_INSTALL_DIR" 2>/dev/null || true)"
    fi
    mkdir -p "$OPT_OUT"
    local out_dir="$OPT_OUT"
    if [[ "$out_dir" != /* ]]; then
        out_dir="$(realpath "$out_dir")"
    fi
    write_policy_file "$out_dir/policy.env" "$ALLOWED_REPO_SLUG"
    write_job_started_hook "$out_dir/hook-job-started.sh"
    write_job_completed_hook "$out_dir/hook-job-completed.sh"
    write_egress_firewall_check "$out_dir/check-egress-firewall.sh"
    if [ -n "$OPT_JITCONFIG_FILE" ]; then
        write_jit_launcher "$out_dir/run-jit.sh"
        echo "wrote $OPT_OUT/policy.env, $OPT_OUT/hook-job-started.sh, $OPT_OUT/hook-job-completed.sh, $OPT_OUT/check-egress-firewall.sh, $OPT_OUT/run-jit.sh"
    else
        write_runner_launcher "$out_dir/run-runner.sh"
        echo "wrote $OPT_OUT/policy.env, $OPT_OUT/hook-job-started.sh, $OPT_OUT/hook-job-completed.sh, $OPT_OUT/check-egress-firewall.sh, $OPT_OUT/run-runner.sh"
    fi
}

# ---- render-unit ----------------------------------------------------------

render_unit_text() {
    local arch="$1"
    local restart_policy="on-failure"
    [ "$OPT_EPHEMERAL" -eq 1 ] && restart_policy="no"

    # Run a root-owned main-process launcher wrapper under Type=notify so
    # systemctl start / enable --now waits until check-egress-firewall.sh
    # passes and READY=1 is sent as MainPID (or fails immediately if the
    # firewall check exits 78, which also triggers RestartPreventExitStatus=78)
    # before exec'ing upstream bin/runsvc.sh (or bin/Runner.Listener in JIT mode).
    local exec_start="${OPT_HOOK_DIR}/run-runner.sh"
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
        runner_fs_directives="# Ephemeral/JIT mode writes/deletes .runner/.credentials (and validated JIT _work); binaries and .env remain read-only.
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

    # Permit lower-half loopback (127.0.0.1, 127.0.0.53 systemd-resolved, etc.)
    # and ::1 while keeping 127.255.255.254/32 outside IPAddressAllow= so it
    # serves as a controlled unit-specific cgroup BPF sentinel.
    local ip_allow_lines="IPAddressAllow=127.0.0.0/9
IPAddressAllow=::1/128"
    local ip
    for ip in "${OPT_ALLOW_IPS[@]}"; do
        ip_allow_lines="${ip_allow_lines}
IPAddressAllow=${ip}"
    done

    local ip_deny_lines="IPAddressDeny=127.255.255.254/32
IPAddressDeny=link-local
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
# Generated by scripts/setup-kvm-runner.sh for ${TARGET_URL} (${arch}).
#
# Security model:
#   - Dedicated locked service user (${OPT_USER}), zero Linux capabilities,
#     NoNewPrivileges=yes, no sudo/libvirt/docker groups; only supplementary group kvm.
#   - Unprivileged qemu:///session libvirt inside this unit's cgroup, so every
#     disposable KVM guest inherits DevicePolicy=closed (/dev/kvm only),
#     ProtectSystem=strict, MemoryMax, TasksMax, and cgroup IPAddressDeny.
#   - Root-owned ExecStart wrapper (Type=notify, NotifyAccess=main) verifies via
#     isolated /usr/bin/python3 -I -S under env -i that THIS unit's cgroup BPF
#     IPAddressDeny= actively rejects the unit loopback sentinel
#     (127.255.255.254), IMDS, and configured private LANs with EPERM before
#     signaling READY=1 and exec'ing the runner listener (exiting 78 so
#     systemctl start fails immediately and RestartPreventExitStatus=78 prevents
#     restart loops).
#   - MemoryDenyWriteExecute is intentionally omitted because .NET (actions/runner),
#     Node.js (JS actions), and QEMU require executable JIT mappings.
[Unit]
Description=qeminga KVM GitHub Actions runner (${arch})
Documentation=https://github.com/vicaya/qeminga
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=60s
User=${OPT_USER}
Group=${OPT_USER}
SupplementaryGroups=kvm
WorkingDirectory=${OPT_INSTALL_DIR}
ExecStart=${exec_start}
${cred_line}
${stop_post_line}
Restart=${restart_policy}
RestartPreventExitStatus=78
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

# Cgroup BPF egress firewall: unconditionally block the unit loopback sentinel
# (127.255.255.254/32), cloud IMDS (169.254.0.0/16, fe80::/10, fd00:ec2::254/128),
# and multicast; block private LANs by default.
${ip_allow_lines}
${ip_deny_lines}

[Install]
WantedBy=multi-user.target
EOF
}

cmd_render_unit() {
    parse_common_opts "$@"
    check_service_lock_disjoint
    resolve_target_registration render-unit
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

    # systemd IPAddressDeny= requires cgroup v2 unified hierarchy for BPF attachment;
    # the main-process launcher wrapper also runs check-egress-firewall.sh inside the cgroup.
    local cg_ctrls="${QEMINGA_CGROUP_CONTROLLERS:-/sys/fs/cgroup/cgroup.controllers}"
    if [ -r "$cg_ctrls" ]; then
        echo "  ok: cgroup v2 unified hierarchy present ($cg_ctrls)"
    else
        echo "  FAIL: cgroup v2 unified hierarchy missing ($cg_ctrls); required for systemd IPAddressDeny= BPF firewall"
        fail=1
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

    if command -v libvirtd >/dev/null 2>&1; then
        echo "  ok: tool libvirtd"
    elif command -v virtqemud >/dev/null 2>&1; then
        echo "  ok: tool virtqemud"
    else
        echo "  FAIL: missing tool 'libvirtd' (or 'virtqemud') (install will install packages on Ubuntu/Debian/Fedora)"
        fail=1
    fi

    local tool
    for tool in virsh "qemu-system-$arch" qemu-img genisoimage git jq curl sha256sum tar python3; do
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
            qemu-utils genisoimage git jq curl ca-certificates python3 "${arch_pkgs[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        local arch_pkgs=()
        case "$arch" in
            x86_64) arch_pkgs=(qemu-system-x86-core) ;;
            aarch64) arch_pkgs=(qemu-system-aarch64-core edk2-aarch64) ;;
        esac
        dnf install -y -q \
            libvirt-daemon-driver-qemu libvirt-client \
            qemu-img genisoimage git jq curl ca-certificates python3 "${arch_pkgs[@]}"
    else
        die "neither apt-get nor dnf found; install libvirt-daemon, qemu-system-${arch}, qemu-img, genisoimage, git, jq, curl, python3 manually and rerun with --skip-packages"
    fi
}

# ---- installation record & dedicated directory guards ---------------------

HAS_INSTALL_RECORD=0
HAS_USER_RECORD=0
REC_SCHEMA=""
REC_STATE=""
REC_INSTALL_ID=""
REC_SERVICE=""
REC_USER=""
REC_USER_UID=""
REC_USER_GID=""
REC_USER_CREATED=""
REC_INSTALL_DIR=""
REC_STATE_DIR=""
REC_HOOK_DIR=""
REC_CONFIG_DIR=""
REC_TARGET_URL=""
REC_RUNNER_GROUP=""
REC_RUNNER_NAME=""
REC_LABELS=""
REC_EPHEMERAL=""
REC_ALLOW_AUTO_UPDATE=""
REC_WORK_DIR=""
REC_OWNED_CONFIG_DIR=""
REC_OWNED_STATE_DIR=""
REC_OWNED_INSTALL_DIR=""
REC_OWNED_HOOK_DIR=""
REC_OWNED_UNIT=""
REC_STAGED_UNIT=""
REC_STAGED_INSTALL_DIR=""
REC_STAGED_HOOK_DIR=""
REC_STAGED_STATE_DIR=""
REC_VOL_UNIT=""
REC_VOL_INSTALL_DIR=""
REC_VOL_HOOK_DIR=""
REC_VOL_STATE_DIR=""

MANAGED_INSTALL_ID=""
MANAGED_USER_UID=""
MANAGED_USER_GID=""
MANAGED_USER_CREATED="0"

OWNED_CONFIG_DIR=0
OWNED_STATE_DIR=0
OWNED_INSTALL_DIR=0
OWNED_HOOK_DIR=0
OWNED_UNIT=0

VOL_UNIT=""
VOL_INSTALL_DIR=""
VOL_HOOK_DIR=""
VOL_STATE_DIR=""

generate_install_id() {
    local id=""
    if [ -r /proc/sys/kernel/random/uuid ]; then
        IFS= read -r id </proc/sys/kernel/random/uuid || true
        id="${id//-/}"
    fi
    if [[ ! "$id" =~ ^[a-f0-9]{32}$ ]]; then
        id="$(/usr/bin/python3 -I -S -c 'import secrets; print(secrets.token_hex(16))')" \
            || die "failed to generate unique installation identifier"
    fi
    printf '%s' "$id"
}

# Root-side filesystem operations using kernel O_PATH|O_DIRECTORY|O_NOFOLLOW
# traversal, /proc/self/fdinfo mnt_id -> /proc/self/mountinfo resolution,
# persistent filesystem UUID/f_fsid fingerprinting, mount-bounded recursive
# chown/rmtree, and pure rename(2) without copy-and-delete fallback on EXDEV.
fs_ops() {
    local op="$1"
    shift
    local py="/usr/bin/python3"
    [ -x "$py" ] || die "/usr/bin/python3 is required for safe filesystem operations"
    local py_cmd=()
    if [ "$op" = "install-runner-archive" ]; then
        py_cmd=("$py" -I -S - "$op" "$@")
    else
        py_cmd=(
            env -i PATH=/usr/bin:/bin HOME=/nonexistent
            "QEMINGA_MOUNTINFO=${QEMINGA_MOUNTINFO:-}"
            "QEMINGA_FS_UUID_MAP=${QEMINGA_FS_UUID_MAP:-}"
            "QEMINGA_TEST_MNT_ID=${QEMINGA_TEST_MNT_ID:-}"
            "QEMINGA_BY_UUID_DIR=${QEMINGA_BY_UUID_DIR:-}"
            "QEMINGA_MIGRATE_BLKID_MAP=${QEMINGA_MIGRATE_BLKID_MAP:-}"
            "QEMINGA_TEST_FAIL_PUBLISH_AFTER=${QEMINGA_TEST_FAIL_PUBLISH_AFTER:-}"
            "QEMINGA_TEST_CRASH_PUBLISH_AFTER=${QEMINGA_TEST_CRASH_PUBLISH_AFTER:-}"
            "$py" -I -S - "$op" "$@"
        )
    fi
    "${py_cmd[@]}" <<'PY'
import errno
import json
import os
import re
import stat
import subprocess
import sys

PATH_DIR_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
READ_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
CUSTOM_MOUNTINFO = bool(os.environ.get("QEMINGA_MOUNTINFO"))


def unescape_mountinfo(field):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def pct_encode(val):
    return re.sub(
        r"[^A-Za-z0-9._/-]",
        lambda m: "".join(f"%{b:02X}" for b in m.group(0).encode("utf-8", errors="surrogateescape")),
        val,
    )


def parse_mountinfo():
    path = os.environ.get("QEMINGA_MOUNTINFO") or "/proc/self/mountinfo"
    entries = []
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if " - " not in line:
                continue
            left, right = line.split(" - ", 1)
            lparts = left.split(" ")
            rparts = right.split(" ")
            if len(lparts) < 5 or len(rparts) < 2:
                continue
            mp = unescape_mountinfo(lparts[4])
            if mp != "/":
                mp = mp.rstrip("/")
            entries.append(
                {
                    "mount_id": int(lparts[0]),
                    "parent_id": int(lparts[1]),
                    "dev": lparts[2],
                    "root": unescape_mountinfo(lparts[3]),
                    "mp": mp,
                    "fstype": unescape_mountinfo(rparts[0]),
                    "source": unescape_mountinfo(rparts[1]),
                }
            )
    if not entries:
        raise OSError(errno.EINVAL, f"empty or unreadable mountinfo '{path}'")
    return entries


def fd_mnt_id(fd):
    with open(f"/proc/self/fdinfo/{fd}", "r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1].strip())
    raise OSError(errno.EINVAL, f"missing mnt_id in /proc/self/fdinfo/{fd}")


def open_chain_opath(abs_path):
    parts = [p for p in abs_path.split("/") if p]
    fd = os.open("/", PATH_DIR_FLAGS)
    try:
        for part in parts:
            nxt = os.open(part, PATH_DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except Exception:
        os.close(fd)
        raise


def norm_abs(p):
    return "/" if p == "/" else p.rstrip("/")


def resolve_mount_in_tree(entries, norm_path):
    by_id = {e["mount_id"]: e for e in entries}
    children = {}
    root_entry = None
    for entry in entries:
        children[(entry["parent_id"], entry["mp"])] = entry
        if entry["mp"] == "/" and entry["parent_id"] not in by_id:
            root_entry = entry
    if root_entry is None:
        for entry in entries:
            if entry["mp"] == "/":
                root_entry = entry
    if root_entry is None:
        raise OSError(errno.ENOENT, f"no root mount entry covers '{norm_path}'")

    cur = root_entry
    seen = {cur["mount_id"]}
    while (cur["mount_id"], "/") in children:
        nxt = children[(cur["mount_id"], "/")]
        if nxt["mount_id"] in seen:
            break
        seen.add(nxt["mount_id"])
        cur = nxt

    if norm_path == "/":
        return cur

    prefix = ""
    for part in [p for p in norm_path.split("/") if p]:
        prefix = f"{prefix}/{part}"
        while (cur["mount_id"], prefix) in children:
            nxt = children[(cur["mount_id"], prefix)]
            if nxt["mount_id"] in seen:
                break
            seen.add(nxt["mount_id"])
            cur = nxt
    return cur


def visible_mountpoints(entries):
    mps = set()
    for entry in entries:
        mp = entry["mp"]
        try:
            top = resolve_mount_in_tree(entries, mp)
        except OSError:
            continue
        if top["mp"] == mp:
            mps.add(mp)
    return mps


def resolve_mount_for_fd(fd, norm_path, entries):
    by_id = {e["mount_id"]: e for e in entries}
    if not CUSTOM_MOUNTINFO:
        actual_mnt = fd_mnt_id(fd)
        entry = by_id.get(actual_mnt)
        if entry is None:
            raise OSError(
                errno.ENOENT,
                f"mount_id {actual_mnt} for '{norm_path}' not found in /proc/self/mountinfo",
            )
        return entry
    test_mnt = os.environ.get("QEMINGA_TEST_MNT_ID")
    if test_mnt:
        mid = int(test_mnt)
        entry = by_id.get(mid)
        if entry is None:
            raise OSError(errno.ENOENT, f"test mount_id {mid} not found in mountinfo")
        return entry
    return resolve_mount_in_tree(entries, norm_path)


def resolve_fs_uuid(entry):
    if CUSTOM_MOUNTINFO:
        raw_map = os.environ.get("QEMINGA_FS_UUID_MAP", "")
        if raw_map:
            mapping = {}
            for item in re.split(r"[\n,]", raw_map):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    mapping[k.strip()] = v.strip()
            for key in (str(entry["mount_id"]), entry["source"], entry["mp"]):
                if key in mapping and mapping[key]:
                    return mapping[key]
        return ""

    src = entry["source"]
    if not src.startswith("/dev/"):
        return ""
    try:
        src_st = os.stat(src)
    except OSError:
        return ""
    if not stat.S_ISBLK(src_st.st_mode):
        return ""

    # Only use /dev/disk/by-uuid (stat-only, available to the unprivileged
    # cleanup account under DevicePolicy=closed). Never fall back to root-only
    # raw-device probing so installer and cleanup hook always agree on a strong
    # identity (falling back to src + kernel fstatvfs f_fsid when absent).
    by_uuid = os.environ.get("QEMINGA_BY_UUID_DIR") or "/dev/disk/by-uuid"
    try:
        for name in sorted(os.listdir(by_uuid)):
            try:
                lst = os.stat(os.path.join(by_uuid, name))
            except OSError:
                continue
            if stat.S_ISBLK(lst.st_mode) and lst.st_rdev == src_st.st_rdev:
                return name
    except OSError:
        pass
    return ""


def volume_id_of_fd(fd, norm_path, entries):
    entry = resolve_mount_for_fd(fd, norm_path, entries)
    fs_uuid = resolve_fs_uuid(entry)
    try:
        fsid_num = os.fstatvfs(fd).f_fsid
    except OSError:
        fsid_num = 0
    fsid_hex = f"{fsid_num:x}" if fsid_num else ""

    parts = [
        f"mp:{pct_encode(entry['mp'])}",
        f"root:{pct_encode(entry['root'])}",
        f"fs:{pct_encode(entry['fstype'])}",
    ]
    if fs_uuid:
        parts.append(f"uuid:{pct_encode(fs_uuid)}")
        if fsid_hex:
            parts.append(f"fsid:{fsid_hex}")
    else:
        if not fsid_hex and entry["source"].startswith("/dev/") and not CUSTOM_MOUNTINFO:
            raise OSError(
                errno.EINVAL,
                f"cannot establish service-verifiable persistent filesystem identifier for block device '{entry['source']}' at '{norm_path}'",
            )
        parts.append(f"src:{pct_encode(entry['source'])}")
        if fsid_hex:
            parts.append(f"fsid:{fsid_hex}")
    return ",".join(parts)


def assert_no_mount_at_or_under(abs_path, mountpoints):
    norm = norm_abs(abs_path)
    if norm == "/":
        raise OSError(errno.EINVAL, "refusing root path '/'")
    prefix = norm + "/"
    for mp in mountpoints:
        if mp == norm:
            raise OSError(errno.EXDEV, f"refusing to cross mount point '{mp}'")
        if mp.startswith(prefix):
            raise OSError(errno.EXDEV, f"refusing to cross mount point '{mp}' under '{norm}'")


def assert_entry_same_mount(parent_fd, name, root_dev, root_mnt_id, cur_path, mountpoints):
    if cur_path in mountpoints:
        raise OSError(errno.EXDEV, f"refusing to cross mount point '{cur_path}'")
    efd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        est = os.fstat(efd)
        if fd_mnt_id(efd) != root_mnt_id:
            raise OSError(errno.EXDEV, f"'{cur_path}' crosses mount boundary")
        if stat.S_ISDIR(est.st_mode) and est.st_dev != root_dev:
            raise OSError(errno.EXDEV, f"'{cur_path}' crosses filesystem boundary")
        return est
    finally:
        os.close(efd)


def scan_dir_same_mount(parent_fd, name, root_dev, root_mnt_id, cur_path, mountpoints):
    if cur_path in mountpoints:
        raise OSError(errno.EXDEV, f"refusing to cross mount point '{cur_path}'")
    st = os.lstat(name, dir_fd=parent_fd)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return
    if st.st_dev != root_dev:
        raise OSError(errno.EXDEV, f"'{cur_path}' crosses filesystem boundary")
    dir_fd = os.open(name, READ_DIR_FLAGS, dir_fd=parent_fd)
    try:
        fst = os.fstat(dir_fd)
        if fst.st_dev != root_dev or fd_mnt_id(dir_fd) != root_mnt_id:
            raise OSError(errno.EXDEV, f"'{cur_path}' crosses mount boundary")
        for entry in os.listdir(dir_fd):
            child_path = f"{cur_path}/{entry}"
            est = assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
            if stat.S_ISDIR(est.st_mode):
                scan_dir_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
    finally:
        os.close(dir_fd)


def check_no_mounts(abs_path, mountpoints):
    norm = norm_abs(abs_path)
    assert_no_mount_at_or_under(norm, mountpoints)
    parent = os.path.dirname(norm) or "/"
    base = os.path.basename(norm)
    pfd = open_chain_opath(parent)
    try:
        pst = os.fstat(pfd)
        p_mnt = fd_mnt_id(pfd)
        st = assert_entry_same_mount(pfd, base, pst.st_dev, p_mnt, norm, mountpoints)
        if not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode):
            rfd = os.open(base, READ_DIR_FLAGS, dir_fd=pfd)
            try:
                rst = os.fstat(rfd)
                r_mnt = fd_mnt_id(rfd)
                if rst.st_dev != pst.st_dev or r_mnt != p_mnt:
                    raise OSError(errno.EXDEV, f"'{norm}' crosses mount boundary")
                for entry in os.listdir(rfd):
                    child_path = f"{norm}/{entry}"
                    est = assert_entry_same_mount(rfd, entry, rst.st_dev, r_mnt, child_path, mountpoints)
                    if stat.S_ISDIR(est.st_mode):
                        scan_dir_same_mount(rfd, entry, rst.st_dev, r_mnt, child_path, mountpoints)
            finally:
                os.close(rfd)
    finally:
        os.close(pfd)


def clear_dir_contents_same_mount(dir_fd, root_dev, root_mnt_id, cur_path, mountpoints):
    for entry in os.listdir(dir_fd):
        child_path = f"{cur_path}/{entry}"
        est = assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
        if stat.S_ISDIR(est.st_mode):
            rmtree_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
        else:
            os.unlink(entry, dir_fd=dir_fd)


def rmtree_same_mount(parent_fd, name, root_dev, root_mnt_id, cur_path, mountpoints):
    if cur_path in mountpoints:
        raise OSError(errno.EXDEV, f"refusing to cross mount point '{cur_path}'")
    st = os.lstat(name, dir_fd=parent_fd)
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(errno.ENOTDIR, f"'{cur_path}' is not a real directory")
    if st.st_dev != root_dev:
        raise OSError(errno.EXDEV, f"'{cur_path}' crosses filesystem boundary")
    dir_fd = os.open(name, READ_DIR_FLAGS, dir_fd=parent_fd)
    try:
        fst = os.fstat(dir_fd)
        if fst.st_dev != root_dev or fd_mnt_id(dir_fd) != root_mnt_id:
            raise OSError(errno.EXDEV, f"'{cur_path}' crosses mount boundary")
        clear_dir_contents_same_mount(dir_fd, root_dev, root_mnt_id, cur_path, mountpoints)
    finally:
        os.close(dir_fd)
    os.rmdir(name, dir_fd=parent_fd)


def parse_vol_fields(vol_str):
    if not vol_str:
        return None
    fields = {}
    for item in vol_str.split(","):
        if ":" not in item:
            return None
        k, v = item.split(":", 1)
        if not k or k in fields:
            return None
        fields[k] = v
    return fields


def is_legacy_four_field_vol(vol_str):
    fields = parse_vol_fields(vol_str)
    return fields is not None and set(fields.keys()) == {"mp", "root", "fs", "src"}


def legacy_vol_of_entry(entry):
    return ",".join(
        [
            f"mp:{pct_encode(entry['mp'])}",
            f"root:{pct_encode(entry['root'])}",
            f"fs:{pct_encode(entry['fstype'])}",
            f"src:{pct_encode(entry['source'])}",
        ]
    )


def probe_blkid_uuid_for_migration(entry):
    # Used ONLY during explicit root `migrate-record --confirm-volumes` to
    # independently verify an older root-only blkid UUID record before migrating
    # it to a service-readable src+fsid fingerprint. Never used in install or hooks.
    source = entry["source"]
    if CUSTOM_MOUNTINFO:
        raw_map = os.environ.get("QEMINGA_MIGRATE_BLKID_MAP", "")
        if raw_map:
            enc_src = pct_encode(source)
            for item in raw_map.split(","):
                if "=" not in item:
                    continue
                k, v = item.split("=", 1)
                if k.strip() in (source, enc_src):
                    val = v.strip()
                    if re.fullmatch(r"[A-Za-z0-9._-]+", val):
                        return val
                    return ""
        return ""
    if not source.startswith("/dev/"):
        return ""
    try:
        src_st = os.stat(source)
    except OSError:
        return ""
    if not stat.S_ISBLK(src_st.st_mode):
        return ""
    dev_mm = entry.get("dev", "")
    if dev_mm and not dev_mm.startswith("0:"):
        if f"{os.major(src_st.st_rdev)}:{os.minor(src_st.st_rdev)}" != dev_mm:
            return ""
    for blkid_bin in ("/usr/sbin/blkid", "/sbin/blkid"):
        if os.path.isfile(blkid_bin) and os.access(blkid_bin, os.X_OK):
            try:
                res = subprocess.run(
                    [blkid_bin, "-c", "/dev/null", "-o", "value", "-s", "UUID", source],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    check=False,
                )
            except OSError:
                continue
            if res.returncode == 0:
                val = res.stdout.strip()
                if re.fullmatch(r"[A-Za-z0-9._-]+", val):
                    return val
    return ""


def verify_legacy_volume_for_fd(fd, path_for_mount, display_path, expected, entries, allow_empty=True):
    actual = volume_id_of_fd(fd, path_for_mount, entries)
    if (allow_empty and not expected) or expected == actual:
        return actual
    if is_legacy_four_field_vol(expected):
        live_legacy = legacy_vol_of_entry(resolve_mount_for_fd(fd, path_for_mount, entries))
        if live_legacy == expected:
            return actual
        sys.stderr.write(
            f"setup-kvm-runner: legacy backing volume mismatch for '{display_path}': recorded '{expected}', live '{live_legacy}'\n"
        )
        sys.exit(1)
    exp_fields = parse_vol_fields(expected)
    act_fields = parse_vol_fields(actual)
    if (
        exp_fields
        and act_fields
        and set(exp_fields.keys()) <= {"mp", "root", "fs", "uuid", "fsid"}
        and bool(exp_fields.get("uuid"))
        and "src" in act_fields
    ):
        same_mount = (
            exp_fields.get("mp") == act_fields.get("mp")
            and exp_fields.get("root") == act_fields.get("root")
            and exp_fields.get("fs") == act_fields.get("fs")
        )
        fsid_ok = (
            "fsid" not in exp_fields
            or (bool(act_fields.get("fsid")) and exp_fields.get("fsid") == act_fields.get("fsid"))
        )
        if same_mount and fsid_ok:
            entry = resolve_mount_for_fd(fd, path_for_mount, entries)
            live_blkid_uuid = probe_blkid_uuid_for_migration(entry)
            if live_blkid_uuid and pct_encode(live_blkid_uuid) == exp_fields["uuid"]:
                return actual
    sys.stderr.write(
        f"setup-kvm-runner: backing volume mismatch for '{display_path}': expected '{expected}', found '{actual}' (refusing to overwrite mismatched UUID/fsid record)\n"
    )
    sys.exit(1)


def scan_tree_for_chown(dir_fd, root_dev, root_mnt_id, cur_path, mountpoints, skip_children=None):
    for entry in os.listdir(dir_fd):
        if skip_children and entry in skip_children:
            continue
        child_path = f"{cur_path}/{entry}"
        est = assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
        if stat.S_ISDIR(est.st_mode):
            cfd = os.open(entry, READ_DIR_FLAGS, dir_fd=dir_fd)
            try:
                cst = os.fstat(cfd)
                if cst.st_dev != root_dev or fd_mnt_id(cfd) != root_mnt_id:
                    raise OSError(errno.EXDEV, f"'{child_path}' crosses mount boundary")
                scan_tree_for_chown(cfd, root_dev, root_mnt_id, child_path, mountpoints)
            finally:
                os.close(cfd)
        elif stat.S_ISLNK(est.st_mode):
            continue
        elif stat.S_ISREG(est.st_mode):
            if est.st_nlink != 1:
                raise OSError(
                    errno.EMLINK,
                    f"refusing ownership change on multiply-linked file '{child_path}' (st_nlink={est.st_nlink})",
                )
        else:
            raise OSError(errno.EINVAL, f"refusing unexpected special file '{child_path}'")


def apply_chown_tree(dir_fd, uid, gid, root_dev, root_mnt_id, cur_path, mountpoints, apply_chown, skip_children=None):
    if apply_chown:
        os.fchown(dir_fd, uid, gid)
    for entry in os.listdir(dir_fd):
        if skip_children and entry in skip_children:
            continue
        child_path = f"{cur_path}/{entry}"
        est = assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path, mountpoints)
        if stat.S_ISDIR(est.st_mode):
            cfd = os.open(entry, READ_DIR_FLAGS, dir_fd=dir_fd)
            try:
                cst = os.fstat(cfd)
                if cst.st_dev != root_dev or fd_mnt_id(cfd) != root_mnt_id:
                    raise OSError(errno.EXDEV, f"'{child_path}' crosses mount boundary")
                apply_chown_tree(cfd, uid, gid, root_dev, root_mnt_id, child_path, mountpoints, apply_chown)
            finally:
                os.close(cfd)
        elif stat.S_ISLNK(est.st_mode):
            continue
        elif stat.S_ISREG(est.st_mode):
            ffd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            try:
                fst = os.fstat(ffd)
                if not stat.S_ISREG(fst.st_mode):
                    raise OSError(errno.EINVAL, f"'{child_path}' changed file type during chown")
                if fd_mnt_id(ffd) != root_mnt_id:
                    raise OSError(errno.EXDEV, f"'{child_path}' crosses mount boundary")
                if fst.st_nlink != 1:
                    raise OSError(
                        errno.EMLINK,
                        f"refusing ownership change on multiply-linked file '{child_path}' (st_nlink={fst.st_nlink})",
                    )
                if apply_chown:
                    os.fchown(ffd, uid, gid)
            finally:
                os.close(ffd)
        else:
            raise OSError(errno.EINVAL, f"refusing unexpected special file '{child_path}'")


def sanitize_staged_tree(dir_fd, root_dev, root_mnt_id, cur_path, apply_root_chown):
    if apply_root_chown:
        os.fchown(dir_fd, 0, 0)
    for entry in os.listdir(dir_fd):
        child_path = f"{cur_path}/{entry}"
        efd = os.open(entry, os.O_PATH | os.O_NOFOLLOW, dir_fd=dir_fd)
        try:
            est = os.fstat(efd)
            if fd_mnt_id(efd) != root_mnt_id:
                raise OSError(errno.EXDEV, f"staged '{child_path}' crosses mount boundary")
        finally:
            os.close(efd)
        if stat.S_ISDIR(est.st_mode):
            if est.st_dev != root_dev:
                raise OSError(errno.EXDEV, f"staged '{child_path}' crosses filesystem boundary")
            cfd = os.open(entry, READ_DIR_FLAGS, dir_fd=dir_fd)
            try:
                cst = os.fstat(cfd)
                if cst.st_dev != root_dev or fd_mnt_id(cfd) != root_mnt_id:
                    raise OSError(errno.EXDEV, f"staged '{child_path}' crosses mount boundary")
                sanitize_staged_tree(cfd, root_dev, root_mnt_id, child_path, apply_root_chown)
            finally:
                os.close(cfd)
        elif stat.S_ISLNK(est.st_mode):
            continue
        elif stat.S_ISREG(est.st_mode):
            ffd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            try:
                fst = os.fstat(ffd)
                if not stat.S_ISREG(fst.st_mode):
                    raise OSError(errno.EINVAL, f"staged '{child_path}' changed file type")
                if fst.st_nlink > 1:
                    # Break internal archive hard links into independent st_nlink==1 copies
                    # inside the private 0700 staging tree before publishing.
                    counter = 0
                    while True:
                        cand = f".qeminga-dedup-{os.getpid()}-{fst.st_ino}-{counter}"
                        try:
                            nfd = os.open(
                                cand,
                                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600,
                                dir_fd=dir_fd,
                            )
                            break
                        except FileExistsError:
                            counter += 1
                    try:
                        while True:
                            chunk = os.read(ffd, 65536)
                            if not chunk:
                                break
                            view = memoryview(chunk)
                            while view:
                                written = os.write(nfd, view)
                                view = view[written:]
                        os.fchmod(nfd, fst.st_mode & 0o7777)
                        if apply_root_chown:
                            os.fchown(nfd, 0, 0)
                    except Exception:
                        os.close(nfd)
                        try:
                            os.unlink(cand, dir_fd=dir_fd)
                        except OSError:
                            pass
                        raise
                    os.close(nfd)
                    os.rename(cand, entry, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                elif apply_root_chown:
                    os.fchown(ffd, 0, 0)
            finally:
                os.close(ffd)
        else:
            raise OSError(errno.EINVAL, f"refusing unexpected special file '{child_path}' in archive")


RESERVED_LIVE_RUNNER_ENTRIES = {
    ".runner",
    ".credentials",
    ".credentials_rsaparams",
    ".path",
    ".env",
    "_diag",
    "_work",
}


def build_reserved_runner_names(extra_work_child=""):
    names = set(RESERVED_LIVE_RUNNER_ENTRIES)
    if extra_work_child:
        if "/" in extra_work_child or extra_work_child in (".", ".."):
            raise OSError(errno.EINVAL, f"invalid workspace child name '{extra_work_child}'")
        names.add(extra_work_child)
    return names


def validate_staged_runner_bundle(p_sfd, root_dev, root_mnt_id, stage_dir, reserved_names):
    staged_names = sorted(os.listdir(p_sfd))
    if not staged_names:
        raise OSError(errno.EINVAL, "refusing empty runner archive")
    for name in staged_names:
        if name in reserved_names:
            raise OSError(
                errno.EINVAL,
                f"refusing runner archive overwriting reserved live state entry '{name}'",
            )
    for req_dir in ("bin", "externals"):
        try:
            dfd = os.open(req_dir, READ_DIR_FLAGS, dir_fd=p_sfd)
        except OSError as exc:
            raise OSError(
                errno.EINVAL,
                f"runner archive missing required directory '{req_dir}': {exc}",
            ) from exc
        try:
            dst = os.fstat(dfd)
            if dst.st_dev != root_dev or fd_mnt_id(dfd) != root_mnt_id:
                raise OSError(errno.EXDEV, f"staged '{req_dir}' crosses mount boundary")
        finally:
            os.close(dfd)

    def check_exec_entry(parent_fd, rel_label, entry_name):
        try:
            ffd = os.open(entry_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        except OSError as exc:
            raise OSError(
                errno.EINVAL,
                f"runner archive missing required executable '{rel_label}': {exc}",
            ) from exc
        try:
            fst = os.fstat(ffd)
            if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                raise OSError(errno.EINVAL, f"runner archive entry '{rel_label}' is not a regular single-link file")
            if fd_mnt_id(ffd) != root_mnt_id:
                raise OSError(errno.EXDEV, f"runner archive entry '{rel_label}' crosses mount boundary")
            if (fst.st_mode & 0o111) == 0:
                raise OSError(errno.EINVAL, f"runner archive entry '{rel_label}' is not executable")
        finally:
            os.close(ffd)

    bin_fd = os.open("bin", READ_DIR_FLAGS, dir_fd=p_sfd)
    try:
        check_exec_entry(bin_fd, "bin/Runner.Listener", "Runner.Listener")
        check_exec_entry(bin_fd, "bin/runsvc.sh", "runsvc.sh")
    finally:
        os.close(bin_fd)
    check_exec_entry(p_sfd, "config.sh", "config.sh")
    check_exec_entry(p_sfd, "run.sh", "run.sh")
    return staged_names


def extract_tarball_into_stage(tfd, sfd, sst, s_mnt, stage_dir, reserved_names):
    # Extract into a nested `payload` dir so an archive's `.` entry
    # can never alter the enclosing private 0700 stage_dir mode.
    os.mkdir("payload", 0o700, dir_fd=sfd)
    p_sfd = os.open("payload", READ_DIR_FLAGS, dir_fd=sfd)
    try:
        os.fchdir(p_sfd)
        tar_bin = "/usr/bin/tar" if os.path.isfile("/usr/bin/tar") else "/bin/tar"
        tar_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}
        res = subprocess.run([tar_bin, "--no-same-owner", "-xz"], stdin=tfd, env=tar_env, check=False)
        if res.returncode != 0:
            raise OSError(errno.EIO, f"tar extraction exited with status {res.returncode}")
        pst_sub = os.fstat(p_sfd)
        if pst_sub.st_dev != sst.st_dev or fd_mnt_id(p_sfd) != s_mnt:
            raise OSError(errno.EXDEV, f"staging payload '{stage_dir}/payload' crosses mount boundary")
        sanitize_staged_tree(p_sfd, sst.st_dev, s_mnt, f"{stage_dir}/payload", os.geteuid() == 0)
        validate_staged_runner_bundle(p_sfd, sst.st_dev, s_mnt, stage_dir, reserved_names)
        if (os.fstat(sfd).st_mode & 0o777) != 0o700:
            raise OSError(errno.EACCES, f"staging dir '{stage_dir}' mode changed during extraction")
        return p_sfd
    except Exception:
        os.close(p_sfd)
        raise


def run_staged_installdependencies(p_sfd, sfd, sst, s_mnt, stage_dir):
    if (os.fstat(sfd).st_mode & 0o777) != 0o700 or os.fstat(sfd).st_uid != os.geteuid():
        raise OSError(errno.EACCES, f"staging dir '{stage_dir}' permissions changed before dependency setup")
    try:
        bfd = os.open("bin", READ_DIR_FLAGS, dir_fd=p_sfd)
    except FileNotFoundError:
        return
    try:
        bst = os.fstat(bfd)
        if bst.st_dev != sst.st_dev or fd_mnt_id(bfd) != s_mnt:
            raise OSError(errno.EXDEV, f"staging dir '{stage_dir}/payload/bin' crosses mount boundary")
        try:
            dfd = os.open("installdependencies.sh", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=bfd)
        except FileNotFoundError:
            return
        try:
            dst = os.fstat(dfd)
            if not stat.S_ISREG(dst.st_mode):
                raise OSError(errno.EINVAL, "staged bin/installdependencies.sh is not a regular file")
            if fd_mnt_id(dfd) != s_mnt or dst.st_nlink != 1:
                raise OSError(errno.EINVAL, "staged bin/installdependencies.sh failed safety checks")
            if (dst.st_mode & 0o111) == 0:
                return
        finally:
            os.close(dfd)
    finally:
        os.close(bfd)
    # cwd is pinned directly to the open, verified p_sfd directory descriptor so
    # ./bin/installdependencies.sh executes strictly from the verified archive
    # without reopening any pathname above the staging container.
    os.fchdir(p_sfd)
    sys.stdout.write("== installing actions/runner runtime dependencies\n")
    sys.stdout.flush()
    res = subprocess.run(
        ["./bin/installdependencies.sh"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        close_fds=True,
        check=False,
    )
    if res.returncode != 0:
        raise OSError(errno.EIO, f"installdependencies.sh exited with status {res.returncode}")
    sanitize_staged_tree(p_sfd, sst.st_dev, s_mnt, f"{stage_dir}/payload", os.geteuid() == 0)
    if (os.fstat(sfd).st_mode & 0o777) != 0o700:
        raise OSError(errno.EACCES, f"staging dir '{stage_dir}' mode changed during dependency setup")


def _parse_nonneg_env_int(name):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return 0
    try:
        val = int(raw)
        return val if val > 0 else 0
    except ValueError:
        return 0


def publish_staged_payload(rfd, rst, r_mnt, target, p_sfd, stage_dir, mountpoints, reserved_names, bfd=None):
    staged_names = validate_staged_runner_bundle(p_sfd, rst.st_dev, r_mnt, stage_dir, reserved_names)
    live_names = set(os.listdir(rfd))
    to_check = sorted(set(staged_names) | {"bin", "externals"})
    for sub in to_check:
        if sub not in live_names:
            continue
        sub_path = f"{target}/{sub}"
        est = assert_entry_same_mount(rfd, sub, rst.st_dev, r_mnt, sub_path, mountpoints)
        if stat.S_ISDIR(est.st_mode):
            scan_dir_same_mount(rfd, sub, rst.st_dev, r_mnt, sub_path, mountpoints)

    if bfd is None:
        for sub in ("bin", "externals"):
            if sub not in live_names:
                continue
            sub_path = f"{target}/{sub}"
            est = assert_entry_same_mount(rfd, sub, rst.st_dev, r_mnt, sub_path, mountpoints)
            if stat.S_ISDIR(est.st_mode):
                rmtree_same_mount(rfd, sub, rst.st_dev, r_mnt, sub_path, mountpoints)
            else:
                os.unlink(sub, dir_fd=rfd)
        for name in staged_names:
            dst_path = f"{target}/{name}"
            sst_entry = os.lstat(name, dir_fd=p_sfd)
            try:
                est = assert_entry_same_mount(rfd, name, rst.st_dev, r_mnt, dst_path, mountpoints)
            except FileNotFoundError:
                est = None
            if est is not None:
                if stat.S_ISDIR(est.st_mode):
                    rmtree_same_mount(rfd, name, rst.st_dev, r_mnt, dst_path, mountpoints)
                elif stat.S_ISDIR(sst_entry.st_mode):
                    os.unlink(name, dir_fd=rfd)
            os.rename(name, name, src_dir_fd=p_sfd, dst_dir_fd=rfd)
        return

    # Transactional update publish: write and fsync manifest.json.tmp, rename
    # atomically into manifest.json, and fsync the backup container BEFORE
    # creating old/ or displacing live entries so neither a write error nor an
    # abrupt crash during preparation can ever leave a partial manifest.json.
    if os.listdir(bfd):
        raise OSError(errno.ENOTEMPTY, "update backup directory is not empty")
    to_displace = sorted((set(staged_names) | {"bin", "externals"}) & live_names)
    manifest_bytes = json.dumps({"displaced": to_displace, "staged": staged_names}).encode("utf-8")
    mfd = os.open("manifest.json.tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=bfd)
    try:
        view = memoryview(manifest_bytes)
        while view:
            written = os.write(mfd, view)
            view = view[written:]
        os.fsync(mfd)
    finally:
        os.close(mfd)
    os.rename("manifest.json.tmp", "manifest.json", src_dir_fd=bfd, dst_dir_fd=bfd)
    os.fsync(bfd)
    os.mkdir("old", 0o700, dir_fd=bfd)
    os.fsync(bfd)

    fail_after = _parse_nonneg_env_int("QEMINGA_TEST_FAIL_PUBLISH_AFTER")
    crash_after = _parse_nonneg_env_int("QEMINGA_TEST_CRASH_PUBLISH_AFTER")
    old_bfd = os.open("old", READ_DIR_FLAGS, dir_fd=bfd)
    moved_new = []
    try:
        for name in to_displace:
            os.rename(name, name, src_dir_fd=rfd, dst_dir_fd=old_bfd)
        for idx, name in enumerate(staged_names, start=1):
            os.rename(name, name, src_dir_fd=p_sfd, dst_dir_fd=rfd)
            moved_new.append(name)
            if crash_after > 0 and idx >= crash_after:
                os._exit(99)
            if fail_after > 0 and idx >= fail_after:
                raise OSError(errno.EIO, f"simulated publish failure after {idx} replacement(s)")
    except BaseException:
        for name in reversed(moved_new):
            try:
                os.rename(name, name, src_dir_fd=rfd, dst_dir_fd=p_sfd)
            except OSError:
                try:
                    est = os.lstat(name, dir_fd=rfd)
                    if stat.S_ISDIR(est.st_mode):
                        rmtree_same_mount(rfd, name, rst.st_dev, r_mnt, f"{target}/{name}", mountpoints)
                    else:
                        os.unlink(name, dir_fd=rfd)
                except OSError:
                    pass
        for name in sorted(os.listdir(old_bfd)):
            os.rename(name, name, src_dir_fd=old_bfd, dst_dir_fd=rfd)
        raise
    finally:
        os.close(old_bfd)


def restore_runner_backup_into_rfd(rfd, rst, r_mnt, target, bfd, backup_dir, mountpoints, reserved_names):
    b_entries = set(os.listdir(bfd))
    if not b_entries:
        return
    if "manifest.json" not in b_entries:
        # Before manifest.json is atomically renamed into place, zero live
        # entries have moved. Clean up interrupted preparation artifacts
        # (manifest.json.tmp and/or an empty old/ directory) safely.
        if b_entries <= {"manifest.json.tmp", "old"}:
            if "old" in b_entries:
                old_bfd = os.open("old", READ_DIR_FLAGS, dir_fd=bfd)
                try:
                    ost = os.fstat(old_bfd)
                    if ost.st_dev != rst.st_dev or fd_mnt_id(old_bfd) != r_mnt:
                        raise OSError(errno.EXDEV, f"backup '{backup_dir}/old' crosses mount boundary")
                    if os.listdir(old_bfd):
                        raise OSError(
                            errno.EINVAL,
                            f"update backup directory '{backup_dir}' has non-empty old/ without manifest.json",
                        )
                finally:
                    os.close(old_bfd)
                os.rmdir("old", dir_fd=bfd)
            if "manifest.json.tmp" in b_entries:
                tfd = os.open("manifest.json.tmp", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=bfd)
                try:
                    tst = os.fstat(tfd)
                    if not stat.S_ISREG(tst.st_mode) or tst.st_nlink != 1 or fd_mnt_id(tfd) != r_mnt:
                        raise OSError(errno.EINVAL, f"unsafe manifest.json.tmp in '{backup_dir}'")
                finally:
                    os.close(tfd)
                os.unlink("manifest.json.tmp", dir_fd=bfd)
            return
        raise OSError(errno.EINVAL, f"update backup directory '{backup_dir}' is missing manifest.json")
    unexpected_b = sorted(b_entries - {"manifest.json", "old"})
    if unexpected_b:
        raise OSError(
            errno.EINVAL,
            f"unexpected entries {unexpected_b!r} in update backup directory '{backup_dir}'",
        )
    mfd = os.open("manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=bfd)
    try:
        mst = os.fstat(mfd)
        if not stat.S_ISREG(mst.st_mode) or mst.st_nlink != 1 or fd_mnt_id(mfd) != r_mnt:
            raise OSError(errno.EINVAL, f"unsafe manifest.json in '{backup_dir}'")
        raw = b""
        while True:
            chunk = os.read(mfd, 65536)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(mfd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise OSError(errno.EINVAL, f"corrupt manifest.json in '{backup_dir}': {exc}") from exc
    if not isinstance(data, dict):
        raise OSError(errno.EINVAL, f"malformed manifest.json in '{backup_dir}'")
    displaced = data.get("displaced", [])
    staged = data.get("staged", [])
    if not isinstance(displaced, list) or not isinstance(staged, list):
        raise OSError(errno.EINVAL, f"malformed manifest.json in '{backup_dir}'")
    for name in displaced + staged:
        if not isinstance(name, str) or not name or "/" in name or name in (".", "..") or name in reserved_names:
            raise OSError(errno.EINVAL, f"unsafe entry name '{name}' in '{backup_dir}/manifest.json'")
    displaced_set = set(displaced)

    old_bfd = None
    old_present = set()
    if "old" in b_entries:
        old_bfd = os.open("old", READ_DIR_FLAGS, dir_fd=bfd)
        try:
            ost = os.fstat(old_bfd)
            if ost.st_dev != rst.st_dev or fd_mnt_id(old_bfd) != r_mnt:
                raise OSError(errno.EXDEV, f"backup '{backup_dir}/old' crosses mount boundary")
            old_present = set(os.listdir(old_bfd))
            for name in old_present:
                if name not in displaced_set:
                    raise OSError(errno.EINVAL, f"unexpected entry '{name}' in '{backup_dir}/old'")
            # Only remove staged entries from rfd when either:
            # - they were brand-new (not in displaced_set), OR
            # - the displaced original is verified present in old_present.
            for name in staged:
                if name in displaced_set and name not in old_present:
                    continue
                dst_path = f"{target}/{name}"
                try:
                    est = assert_entry_same_mount(rfd, name, rst.st_dev, r_mnt, dst_path, mountpoints)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(est.st_mode):
                    rmtree_same_mount(rfd, name, rst.st_dev, r_mnt, dst_path, mountpoints)
                else:
                    os.unlink(name, dir_fd=rfd)
            for name in sorted(old_present):
                dst_path = f"{target}/{name}"
                try:
                    est = assert_entry_same_mount(rfd, name, rst.st_dev, r_mnt, dst_path, mountpoints)
                except FileNotFoundError:
                    est = None
                if est is not None:
                    if stat.S_ISDIR(est.st_mode):
                        rmtree_same_mount(rfd, name, rst.st_dev, r_mnt, dst_path, mountpoints)
                    else:
                        os.unlink(name, dir_fd=rfd)
                os.rename(name, name, src_dir_fd=old_bfd, dst_dir_fd=rfd)
        finally:
            os.close(old_bfd)
        os.rmdir("old", dir_fd=bfd)
    os.unlink("manifest.json", dir_fd=bfd)


def assert_sibling_dir_path(target, sibling, label, disallow_names=()):
    parent = os.path.dirname(target) or "/"
    base = os.path.basename(target)
    sib_parent = os.path.dirname(sibling) or "/"
    sib_base = os.path.basename(sibling)
    if sib_parent != parent or sib_base == base or sib_base in disallow_names:
        raise OSError(
            errno.EINVAL,
            f"{label} '{sibling}' must be a distinct sibling of runner directory '{target}'",
        )
    return parent, base, sib_base


def open_verified_runner_dir(pfd, pst, p_mnt, target, base, expected_vol, entries):
    rfd = os.open(base, READ_DIR_FLAGS, dir_fd=pfd)
    try:
        rst = os.fstat(rfd)
        r_mnt = fd_mnt_id(rfd)
        if rst.st_dev != pst.st_dev or r_mnt != p_mnt:
            raise OSError(errno.EXDEV, f"'{target}' crosses mount boundary")
        actual = volume_id_of_fd(rfd, target, entries)
        if actual != expected_vol:
            raise OSError(
                errno.EXDEV,
                f"backing volume mismatch for '{target}': expected '{expected_vol}', found '{actual}'",
            )
        return rfd, rst, r_mnt
    except Exception:
        os.close(rfd)
        raise


def open_verified_private_sibling(pfd, ref_dev, ref_mnt, sibling_path, sibling_base, label, must_be_empty=False, allow_missing=False):
    try:
        dfd = os.open(sibling_base, READ_DIR_FLAGS, dir_fd=pfd)
    except FileNotFoundError:
        if allow_missing:
            return None, None, None
        raise
    try:
        dst = os.fstat(dfd)
        d_mnt = fd_mnt_id(dfd)
        if dst.st_dev != ref_dev or d_mnt != ref_mnt:
            raise OSError(errno.EXDEV, f"{label} '{sibling_path}' is not on same mount as runner directory")
        if dst.st_uid != os.geteuid() or (dst.st_mode & 0o777) != 0o700:
            raise OSError(
                errno.EACCES,
                f"{label} '{sibling_path}' must be owned by current user with mode 0700",
            )
        if must_be_empty and os.listdir(dfd):
            raise OSError(errno.ENOTEMPTY, f"{label} '{sibling_path}' is not empty")
        return dfd, dst, d_mnt
    except Exception:
        os.close(dfd)
        raise


def format_path_identity(pst, p_mnt, tst, t_mnt, t_vol):
    return (
        f"p_dev:{pst.st_dev};p_ino:{pst.st_ino};p_mnt:{p_mnt};"
        f"t_dev:{tst.st_dev};t_ino:{tst.st_ino};t_mnt:{t_mnt};vol:{t_vol}"
    )


def parse_path_identity(raw_ident, label):
    if not raw_ident:
        raise OSError(errno.EINVAL, f"missing path identity token for '{label}'")
    parts = raw_ident.split(";")
    if len(parts) != 7:
        raise OSError(errno.EINVAL, f"invalid path identity token for '{label}'")
    parsed = {}
    for item in parts:
        if ":" not in item:
            raise OSError(errno.EINVAL, f"invalid path identity field for '{label}'")
        k, v = item.split(":", 1)
        if not k or k in parsed or not v:
            raise OSError(errno.EINVAL, f"invalid path identity field '{k}' for '{label}'")
        parsed[k] = v
    int_keys = ("p_dev", "p_ino", "p_mnt", "t_dev", "t_ino", "t_mnt")
    if set(parsed.keys()) != set(int_keys) | {"vol"}:
        raise OSError(errno.EINVAL, f"unexpected path identity fields for '{label}'")
    ident = {}
    for k in int_keys:
        if not re.fullmatch(r"[0-9]+", parsed[k]):
            raise OSError(errno.EINVAL, f"invalid integer identity field '{k}' for '{label}'")
        ident[k] = int(parsed[k])
    if not re.fullmatch(r"[A-Za-z0-9._/%:,+-]+", parsed["vol"]):
        raise OSError(errno.EINVAL, f"invalid volume identity field for '{label}'")
    ident["vol"] = parsed["vol"]
    return ident


def verify_parent_identity(pfd, pst, p_mnt, parent, expected_ident, entries, label, target):
    if (
        pst.st_dev != expected_ident["p_dev"]
        or pst.st_ino != expected_ident["p_ino"]
        or p_mnt != expected_ident["p_mnt"]
    ):
        raise OSError(
            errno.EXDEV,
            f"refusing {label} '{target}': parent directory identity changed (leaving for inspection)",
        )
    p_vol = volume_id_of_fd(pfd, parent, entries)
    if p_vol != expected_ident["vol"]:
        raise OSError(
            errno.EXDEV,
            f"refusing {label} '{target}': parent backing volume changed from '{expected_ident['vol']}' to '{p_vol}' (leaving for inspection)",
        )


def verify_dir_identity(pfd, pst, p_mnt, parent, dfd, dst, d_mnt, target, expected_ident, entries, label):
    verify_parent_identity(pfd, pst, p_mnt, parent, expected_ident, entries, label, target)
    if (
        dst.st_dev != expected_ident["t_dev"]
        or dst.st_ino != expected_ident["t_ino"]
        or d_mnt != expected_ident["t_mnt"]
    ):
        raise OSError(
            errno.EXDEV,
            f"refusing {label} '{target}': directory identity changed (leaving for inspection)",
        )
    d_vol = volume_id_of_fd(dfd, target, entries)
    if d_vol != expected_ident["vol"]:
        raise OSError(
            errno.EXDEV,
            f"refusing {label} '{target}': backing volume changed from '{expected_ident['vol']}' to '{d_vol}' (leaving for inspection)",
        )


op = sys.argv[1]
try:
    if op == "volume-id":
        target = norm_abs(sys.argv[2])
        entries = parse_mountinfo()
        if target == "/":
            tfd = os.open("/", PATH_DIR_FLAGS)
            try:
                print(volume_id_of_fd(tfd, "/", entries))
            finally:
                os.close(tfd)
        else:
            parent = os.path.dirname(target) or "/"
            base = os.path.basename(target)
            pfd = open_chain_opath(parent)
            try:
                tfd = os.open(base, os.O_PATH | os.O_NOFOLLOW, dir_fd=pfd)
                try:
                    print(volume_id_of_fd(tfd, target, entries))
                finally:
                    os.close(tfd)
            finally:
                os.close(pfd)
    elif op == "verify-volume":
        target = norm_abs(sys.argv[2])
        expected = sys.argv[3]
        entries = parse_mountinfo()
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        try:
            pfd = open_chain_opath(parent)
        except OSError as exc:
            sys.stderr.write(
                f"setup-kvm-runner: backing volume parent '{parent}' for '{target}' is unavailable: {exc}\n"
            )
            sys.exit(1)
        try:
            tfd = None
            try:
                tfd = os.open(base, os.O_PATH | os.O_NOFOLLOW, dir_fd=pfd)
            except FileNotFoundError:
                tfd = None
            if tfd is not None:
                try:
                    if not expected:
                        sys.exit(0)
                    actual = volume_id_of_fd(tfd, target, entries)
                    if actual != expected:
                        if is_legacy_four_field_vol(expected):
                            live_legacy = legacy_vol_of_entry(resolve_mount_for_fd(tfd, target, entries))
                            if live_legacy == expected:
                                sys.stderr.write(
                                    f"setup-kvm-runner: legacy backing volume record for '{target}' lacks persistent UUID/fsid fingerprint (recorded '{expected}', current '{actual}'); after verifying the expected storage is mounted, run 'migrate-record --confirm-volumes'\n"
                                )
                                sys.exit(1)
                        sys.stderr.write(
                            f"setup-kvm-runner: backing volume mismatch for '{target}': expected '{expected}', found '{actual}'\n"
                        )
                        sys.exit(1)
                    sys.exit(0)
                finally:
                    os.close(tfd)
            if not expected:
                sys.stderr.write(
                    f"setup-kvm-runner: refusing to treat absent path '{target}' as deleted without a recorded backing volume\n"
                )
                sys.exit(1)
            actual = volume_id_of_fd(pfd, parent, entries)
            if actual != expected:
                sys.stderr.write(
                    f"setup-kvm-runner: recorded backing volume for absent path '{target}' is unavailable (expected '{expected}', parent '{parent}' is on '{actual}')\n"
                )
                sys.exit(1)
        finally:
            os.close(pfd)
    elif op == "verify-legacy-volume":
        target = norm_abs(sys.argv[2])
        expected = sys.argv[3]
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        check_no_mounts(target, mountpoints)
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        pfd = open_chain_opath(parent)
        try:
            p_mnt = fd_mnt_id(pfd)
            tfd = os.open(base, os.O_PATH | os.O_NOFOLLOW, dir_fd=pfd)
            try:
                if fd_mnt_id(tfd) != p_mnt:
                    raise OSError(errno.EXDEV, f"'{target}' crosses mount boundary")
                print(verify_legacy_volume_for_fd(tfd, target, target, expected, entries, allow_empty=True))
                sys.exit(0)
            finally:
                os.close(tfd)
        finally:
            os.close(pfd)
    elif op == "verify-legacy-volume-absent":
        target = norm_abs(sys.argv[2])
        expected = sys.argv[3]
        if not expected:
            sys.stderr.write(
                f"setup-kvm-runner: refusing to migrate absent staged path '{target}' without a recorded backing volume\n"
            )
            sys.exit(1)
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(target, mountpoints)
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        pfd = open_chain_opath(parent)
        try:
            try:
                os.lstat(base, dir_fd=pfd)
                raise OSError(errno.EEXIST, f"expected absent staged path '{target}' now exists")
            except FileNotFoundError:
                pass
            print(verify_legacy_volume_for_fd(pfd, parent, target, expected, entries, allow_empty=False))
            sys.exit(0)
        finally:
            os.close(pfd)
    elif op == "check-no-mounts":
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        check_no_mounts(sys.argv[2], mountpoints)
    elif op == "replace-file":
        src = norm_abs(sys.argv[2])
        dst = norm_abs(sys.argv[3])
        src_parent = os.path.dirname(src) or "/"
        dst_parent = os.path.dirname(dst) or "/"
        if src_parent != dst_parent or src == dst:
            raise OSError(errno.EINVAL, f"replace-file requires distinct sibling paths: '{src}' -> '{dst}'")
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        if dst in mountpoints:
            raise OSError(errno.EXDEV, f"refusing to overwrite mounted file '{dst}'")
        if src in mountpoints:
            raise OSError(errno.EXDEV, f"refusing mounted staging file '{src}'")
        src_base = os.path.basename(src)
        dst_base = os.path.basename(dst)
        pfd = open_chain_opath(dst_parent)
        try:
            p_mnt = fd_mnt_id(pfd)
            sfd = os.open(src_base, os.O_PATH | os.O_NOFOLLOW, dir_fd=pfd)
            try:
                sst = os.fstat(sfd)
                if not stat.S_ISREG(sst.st_mode) or sst.st_nlink != 1:
                    raise OSError(errno.EINVAL, f"unsafe staging file '{src}'")
                if fd_mnt_id(sfd) != p_mnt:
                    raise OSError(errno.EXDEV, f"staging file '{src}' crosses mount boundary")
            finally:
                os.close(sfd)
            dfd = None
            try:
                dfd = os.open(dst_base, os.O_PATH | os.O_NOFOLLOW, dir_fd=pfd)
            except FileNotFoundError:
                dfd = None
            if dfd is not None:
                try:
                    dst_st = os.fstat(dfd)
                    if fd_mnt_id(dfd) != p_mnt:
                        raise OSError(errno.EXDEV, f"refusing to overwrite bind-mounted destination '{dst}'")
                    if not stat.S_ISREG(dst_st.st_mode):
                        raise OSError(errno.EINVAL, f"refusing to overwrite non-regular destination '{dst}'")
                finally:
                    os.close(dfd)
            os.rename(src_base, dst_base, src_dir_fd=pfd, dst_dir_fd=pfd)
        finally:
            os.close(pfd)
    elif op == "install-runner-archive":
        target = norm_abs(sys.argv[2])
        expected_vol = sys.argv[3]
        tarball = norm_abs(sys.argv[4])
        stage_dir = norm_abs(sys.argv[5])
        stage_id = sys.argv[6]
        run_deps = sys.argv[7] == "1"
        extra_work = sys.argv[8] if len(sys.argv) > 8 else ""
        reserved_names = build_reserved_runner_names(extra_work)
        if not expected_vol:
            raise OSError(
                errno.EINVAL,
                f"refusing to install runner archive into '{target}' without a recorded backing volume fingerprint",
            )
        stage_ident = parse_path_identity(stage_id, stage_dir)
        if stage_ident["vol"] != expected_vol:
            raise OSError(
                errno.EXDEV,
                f"staging dir '{stage_dir}' identity volume '{stage_ident['vol']}' differs from runner volume '{expected_vol}'",
            )
        parent, base, stage_base = assert_sibling_dir_path(target, stage_dir, "stage directory")
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(target, mountpoints)
        assert_no_mount_at_or_under(stage_dir, mountpoints)
        tfd = os.open(tarball, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(tfd).st_mode):
                raise OSError(errno.EINVAL, f"runner archive '{tarball}' is not a regular file")
            pfd = open_chain_opath(parent)
            try:
                pst = os.fstat(pfd)
                p_mnt = fd_mnt_id(pfd)
                rfd, _, _ = open_verified_runner_dir(pfd, pst, p_mnt, target, base, expected_vol, entries)
                os.close(rfd)
                sfd, sst, s_mnt = open_verified_private_sibling(
                    pfd, pst.st_dev, p_mnt, stage_dir, stage_base, "staging dir", must_be_empty=True
                )
                try:
                    verify_dir_identity(pfd, pst, p_mnt, parent, sfd, sst, s_mnt, stage_dir, stage_ident, entries, "staging dir")
                    p_sfd = extract_tarball_into_stage(tfd, sfd, sst, s_mnt, stage_dir, reserved_names)
                    try:
                        if run_deps:
                            run_staged_installdependencies(p_sfd, sfd, sst, s_mnt, stage_dir)
                        entries_pub = parse_mountinfo()
                        mountpoints_pub = visible_mountpoints(entries_pub)
                        assert_no_mount_at_or_under(target, mountpoints_pub)
                        assert_no_mount_at_or_under(stage_dir, mountpoints_pub)
                        verify_dir_identity(pfd, pst, p_mnt, parent, sfd, sst, s_mnt, stage_dir, stage_ident, entries_pub, "staging dir")
                        if os.listdir(sfd) != ["payload"]:
                            raise OSError(errno.EINVAL, f"staging dir '{stage_dir}' has unexpected entries")
                        rfd_pub, rst_pub, r_mnt_pub = open_verified_runner_dir(
                            pfd, pst, p_mnt, target, base, expected_vol, entries_pub
                        )
                        try:
                            if sst.st_dev != rst_pub.st_dev or s_mnt != r_mnt_pub:
                                raise OSError(errno.EXDEV, f"staging dir '{stage_dir}' is not on same mount as '{target}'")
                            publish_staged_payload(
                                rfd_pub, rst_pub, r_mnt_pub, target, p_sfd, stage_dir, mountpoints_pub, reserved_names
                            )
                        finally:
                            os.close(rfd_pub)
                    finally:
                        os.close(p_sfd)
                    os.rmdir("payload", dir_fd=sfd)
                finally:
                    os.close(sfd)
                lst = os.lstat(stage_base, dir_fd=pfd)
                if lst.st_dev != stage_ident["t_dev"] or lst.st_ino != stage_ident["t_ino"]:
                    raise OSError(errno.EXDEV, f"refusing to remove staging dir '{stage_dir}': inode changed before rmdir")
                os.rmdir(stage_base, dir_fd=pfd)
            finally:
                os.close(pfd)
        finally:
            os.close(tfd)
    elif op == "stage-runner-archive":
        target = norm_abs(sys.argv[2])
        expected_vol = sys.argv[3]
        tarball = norm_abs(sys.argv[4])
        stage_dir = norm_abs(sys.argv[5])
        stage_id = sys.argv[6]
        run_deps = (sys.argv[7] == "1") if len(sys.argv) > 7 else False
        extra_work = sys.argv[8] if len(sys.argv) > 8 else ""
        reserved_names = build_reserved_runner_names(extra_work)
        if not expected_vol:
            raise OSError(
                errno.EINVAL,
                f"refusing to stage runner archive for '{target}' without a recorded backing volume fingerprint",
            )
        stage_ident = parse_path_identity(stage_id, stage_dir)
        if stage_ident["vol"] != expected_vol:
            raise OSError(
                errno.EXDEV,
                f"staging dir '{stage_dir}' identity volume '{stage_ident['vol']}' differs from runner volume '{expected_vol}'",
            )
        parent, base, stage_base = assert_sibling_dir_path(target, stage_dir, "stage directory")
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(target, mountpoints)
        assert_no_mount_at_or_under(stage_dir, mountpoints)
        tfd = os.open(tarball, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(tfd).st_mode):
                raise OSError(errno.EINVAL, f"runner archive '{tarball}' is not a regular file")
            pfd = open_chain_opath(parent)
            try:
                pst = os.fstat(pfd)
                p_mnt = fd_mnt_id(pfd)
                rfd, _, _ = open_verified_runner_dir(pfd, pst, p_mnt, target, base, expected_vol, entries)
                os.close(rfd)
                sfd, sst, s_mnt = open_verified_private_sibling(
                    pfd, pst.st_dev, p_mnt, stage_dir, stage_base, "staging dir", must_be_empty=True
                )
                try:
                    verify_dir_identity(pfd, pst, p_mnt, parent, sfd, sst, s_mnt, stage_dir, stage_ident, entries, "staging dir")
                    p_sfd = extract_tarball_into_stage(tfd, sfd, sst, s_mnt, stage_dir, reserved_names)
                    try:
                        if run_deps:
                            run_staged_installdependencies(p_sfd, sfd, sst, s_mnt, stage_dir)
                            entries_after = parse_mountinfo()
                            verify_dir_identity(
                                pfd, pst, p_mnt, parent, sfd, sst, s_mnt, stage_dir, stage_ident, entries_after, "staging dir"
                            )
                    finally:
                        os.close(p_sfd)
                finally:
                    os.close(sfd)
            finally:
                os.close(pfd)
        finally:
            os.close(tfd)
    elif op == "publish-runner-stage":
        target = norm_abs(sys.argv[2])
        expected_vol = sys.argv[3]
        stage_dir = norm_abs(sys.argv[4])
        stage_id = sys.argv[5]
        backup_dir = norm_abs(sys.argv[6]) if len(sys.argv) > 6 and sys.argv[6] else ""
        backup_id = sys.argv[7] if len(sys.argv) > 7 else ""
        extra_work = sys.argv[8] if len(sys.argv) > 8 else ""
        reserved_names = build_reserved_runner_names(extra_work)
        if not expected_vol:
            raise OSError(
                errno.EINVAL,
                f"refusing to publish staged runner payload into '{target}' without a recorded backing volume fingerprint",
            )
        stage_ident = parse_path_identity(stage_id, stage_dir)
        if stage_ident["vol"] != expected_vol:
            raise OSError(
                errno.EXDEV,
                f"staging dir '{stage_dir}' identity volume '{stage_ident['vol']}' differs from runner volume '{expected_vol}'",
            )
        parent, base, stage_base = assert_sibling_dir_path(target, stage_dir, "stage directory")
        backup_base = ""
        backup_ident = None
        if backup_dir:
            backup_ident = parse_path_identity(backup_id, backup_dir)
            if backup_ident["vol"] != expected_vol:
                raise OSError(
                    errno.EXDEV,
                    f"backup dir '{backup_dir}' identity volume '{backup_ident['vol']}' differs from runner volume '{expected_vol}'",
                )
            _, _, backup_base = assert_sibling_dir_path(
                target, backup_dir, "backup directory", disallow_names=(stage_base,)
            )
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(target, mountpoints)
        assert_no_mount_at_or_under(stage_dir, mountpoints)
        if backup_dir:
            assert_no_mount_at_or_under(backup_dir, mountpoints)
        pfd = open_chain_opath(parent)
        try:
            pst = os.fstat(pfd)
            p_mnt = fd_mnt_id(pfd)
            rfd, rst, r_mnt = open_verified_runner_dir(pfd, pst, p_mnt, target, base, expected_vol, entries)
            try:
                sfd, sst, s_mnt = open_verified_private_sibling(
                    pfd, rst.st_dev, r_mnt, stage_dir, stage_base, "staging dir"
                )
                try:
                    verify_dir_identity(pfd, pst, p_mnt, parent, sfd, sst, s_mnt, stage_dir, stage_ident, entries, "staging dir")
                    if os.listdir(sfd) != ["payload"]:
                        raise OSError(errno.EINVAL, f"staging dir '{stage_dir}' has unexpected entries")
                    p_sfd = os.open("payload", READ_DIR_FLAGS, dir_fd=sfd)
                    try:
                        p_sst = os.fstat(p_sfd)
                        if p_sst.st_dev != rst.st_dev or fd_mnt_id(p_sfd) != r_mnt:
                            raise OSError(errno.EXDEV, f"staging payload '{stage_dir}/payload' is not on same mount as '{target}'")
                        if backup_base:
                            bfd, bst, b_mnt = open_verified_private_sibling(
                                pfd, rst.st_dev, r_mnt, backup_dir, backup_base, "backup dir", must_be_empty=True
                            )
                            try:
                                verify_dir_identity(
                                    pfd, pst, p_mnt, parent, bfd, bst, b_mnt, backup_dir, backup_ident, entries, "backup dir"
                                )
                                publish_staged_payload(
                                    rfd, rst, r_mnt, target, p_sfd, stage_dir, mountpoints, reserved_names, bfd=bfd
                                )
                            finally:
                                os.close(bfd)
                        else:
                            publish_staged_payload(
                                rfd, rst, r_mnt, target, p_sfd, stage_dir, mountpoints, reserved_names
                            )
                    finally:
                        os.close(p_sfd)
                    os.rmdir("payload", dir_fd=sfd)
                finally:
                    os.close(sfd)
                lst = os.lstat(stage_base, dir_fd=pfd)
                if lst.st_dev != stage_ident["t_dev"] or lst.st_ino != stage_ident["t_ino"]:
                    raise OSError(errno.EXDEV, f"refusing to remove staging dir '{stage_dir}': inode changed before rmdir")
                os.rmdir(stage_base, dir_fd=pfd)
            finally:
                os.close(rfd)
        finally:
            os.close(pfd)
    elif op == "restore-runner-backup":
        target = norm_abs(sys.argv[2])
        expected_vol = sys.argv[3]
        backup_dir = norm_abs(sys.argv[4])
        backup_id = sys.argv[5]
        extra_work = sys.argv[6] if len(sys.argv) > 6 else ""
        allow_missing = (sys.argv[7] == "1") if len(sys.argv) > 7 else False
        reserved_names = build_reserved_runner_names(extra_work)
        if not expected_vol:
            raise OSError(
                errno.EINVAL,
                f"refusing to restore runner backup for '{target}' without a recorded backing volume fingerprint",
            )
        backup_ident = parse_path_identity(backup_id, backup_dir)
        if backup_ident["vol"] != expected_vol:
            raise OSError(
                errno.EXDEV,
                f"backup dir '{backup_dir}' identity volume '{backup_ident['vol']}' differs from runner volume '{expected_vol}'",
            )
        parent, base, backup_base = assert_sibling_dir_path(target, backup_dir, "backup directory")
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(target, mountpoints)
        assert_no_mount_at_or_under(backup_dir, mountpoints)
        pfd = open_chain_opath(parent)
        try:
            pst = os.fstat(pfd)
            p_mnt = fd_mnt_id(pfd)
            verify_parent_identity(pfd, pst, p_mnt, parent, backup_ident, entries, "backup dir", backup_dir)
            rfd, rst, r_mnt = open_verified_runner_dir(pfd, pst, p_mnt, target, base, expected_vol, entries)
            try:
                bfd, bst, b_mnt = open_verified_private_sibling(
                    pfd, rst.st_dev, r_mnt, backup_dir, backup_base, "backup dir", allow_missing=allow_missing
                )
                if bfd is None:
                    sys.exit(0)
                try:
                    verify_dir_identity(
                        pfd, pst, p_mnt, parent, bfd, bst, b_mnt, backup_dir, backup_ident, entries, "backup dir"
                    )
                    restore_runner_backup_into_rfd(
                        rfd, rst, r_mnt, target, bfd, backup_dir, mountpoints, reserved_names
                    )
                finally:
                    os.close(bfd)
                lst = os.lstat(backup_base, dir_fd=pfd)
                if lst.st_dev != backup_ident["t_dev"] or lst.st_ino != backup_ident["t_ino"]:
                    raise OSError(errno.EXDEV, f"refusing to remove backup dir '{backup_dir}': inode changed before rmdir")
                os.rmdir(backup_base, dir_fd=pfd)
            finally:
                os.close(rfd)
        finally:
            os.close(pfd)
    elif op == "safe-chown-tree":
        target = norm_abs(sys.argv[2])
        uid = int(sys.argv[3])
        gid = int(sys.argv[4])
        expected_vol = sys.argv[5] if len(sys.argv) > 5 else ""
        raw_skip = sys.argv[6] if len(sys.argv) > 6 else ""
        skip_children = set()
        if raw_skip:
            for item in raw_skip.split(","):
                if not item:
                    continue
                if "/" in item or item in (".", ".."):
                    raise OSError(errno.EINVAL, f"invalid skip_child '{item}'")
                skip_children.add(item)
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(target, mountpoints)
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        pfd = open_chain_opath(parent)
        try:
            pst = os.fstat(pfd)
            p_mnt = fd_mnt_id(pfd)
            rfd = os.open(base, READ_DIR_FLAGS, dir_fd=pfd)
            try:
                rst = os.fstat(rfd)
                r_mnt = fd_mnt_id(rfd)
                if rst.st_dev != pst.st_dev or r_mnt != p_mnt:
                    raise OSError(errno.EXDEV, f"'{target}' crosses mount boundary")
                if expected_vol:
                    actual = volume_id_of_fd(rfd, target, entries)
                    if actual != expected_vol:
                        raise OSError(
                            errno.EXDEV,
                            f"backing volume mismatch for '{target}': expected '{expected_vol}', found '{actual}'",
                        )
                scan_tree_for_chown(rfd, rst.st_dev, r_mnt, target, mountpoints, skip_children=skip_children)
                apply_chown = os.geteuid() == 0
                apply_chown_tree(
                    rfd, uid, gid, rst.st_dev, r_mnt, target, mountpoints, apply_chown, skip_children=skip_children
                )
            finally:
                os.close(rfd)
        finally:
            os.close(pfd)
    elif op == "safe-chown-file":
        target = norm_abs(sys.argv[2])
        uid = int(sys.argv[3])
        gid = int(sys.argv[4])
        mode_val = int(sys.argv[5], 8)
        expected_vol = sys.argv[6] if len(sys.argv) > 6 else ""
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        if target in mountpoints:
            raise OSError(errno.EXDEV, f"refusing mounted file '{target}'")
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        pfd = open_chain_opath(parent)
        try:
            p_mnt = fd_mnt_id(pfd)
            ffd = os.open(base, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
            try:
                fst = os.fstat(ffd)
                if not stat.S_ISREG(fst.st_mode):
                    raise OSError(errno.EINVAL, f"'{target}' is not a regular file")
                if fd_mnt_id(ffd) != p_mnt:
                    raise OSError(errno.EXDEV, f"'{target}' crosses mount boundary")
                if expected_vol:
                    actual = volume_id_of_fd(ffd, target, entries)
                    if actual != expected_vol:
                        raise OSError(
                            errno.EXDEV,
                            f"backing volume mismatch for '{target}': expected '{expected_vol}', found '{actual}'",
                        )
                if fst.st_nlink != 1:
                    raise OSError(
                        errno.EMLINK,
                        f"refusing ownership change on hard-linked file '{target}' (st_nlink={fst.st_nlink})",
                    )
                if os.geteuid() == 0:
                    os.fchown(ffd, uid, gid)
                os.fchmod(ffd, mode_val)
            finally:
                os.close(ffd)
        finally:
            os.close(pfd)
    elif op == "rename-only":
        src = norm_abs(sys.argv[2])
        dst = norm_abs(sys.argv[3])
        src_parent = os.path.dirname(src) or "/"
        src_base = os.path.basename(src)
        dst_parent = os.path.dirname(dst) or "/"
        dst_base = os.path.basename(dst)
        spfd = open_chain_opath(src_parent)
        try:
            dpfd = open_chain_opath(dst_parent)
            try:
                os.lstat(src_base, dir_fd=spfd)
                try:
                    os.lstat(dst_base, dir_fd=dpfd)
                    raise OSError(errno.EEXIST, f"staging destination '{dst}' already exists")
                except FileNotFoundError:
                    pass
                os.rename(src_base, dst_base, src_dir_fd=spfd, dst_dir_fd=dpfd)
            finally:
                os.close(dpfd)
        finally:
            os.close(spfd)
    elif op == "path-identity":
        target = norm_abs(sys.argv[2])
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        assert_no_mount_at_or_under(target, mountpoints)
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        pfd = open_chain_opath(parent)
        try:
            pst = os.fstat(pfd)
            p_mnt = fd_mnt_id(pfd)
            p_vol = volume_id_of_fd(pfd, parent, entries)
            tfd = os.open(base, READ_DIR_FLAGS, dir_fd=pfd)
            try:
                tst = os.fstat(tfd)
                t_mnt = fd_mnt_id(tfd)
                if tst.st_dev != pst.st_dev or t_mnt != p_mnt:
                    raise OSError(errno.EXDEV, f"'{target}' crosses mount boundary")
                t_vol = volume_id_of_fd(tfd, target, entries)
                if t_vol != p_vol:
                    raise OSError(errno.EXDEV, f"'{target}' backing volume differs from parent '{parent}'")
                print(format_path_identity(pst, p_mnt, tst, t_mnt, t_vol))
            finally:
                os.close(tfd)
        finally:
            os.close(pfd)
    elif op == "safe-rmtree-id":
        target = norm_abs(sys.argv[2])
        ident = parse_path_identity(sys.argv[3], target)
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        pfd = open_chain_opath(parent)
        try:
            entries = parse_mountinfo()
            mountpoints = visible_mountpoints(entries)
            pst = os.fstat(pfd)
            p_mnt = fd_mnt_id(pfd)
            verify_parent_identity(pfd, pst, p_mnt, parent, ident, entries, "delete", target)
            try:
                os.lstat(base, dir_fd=pfd)
            except FileNotFoundError:
                sys.exit(0)
            check_no_mounts(target, mountpoints)
            tfd = os.open(base, READ_DIR_FLAGS, dir_fd=pfd)
            try:
                tst = os.fstat(tfd)
                t_mnt = fd_mnt_id(tfd)
                verify_dir_identity(pfd, pst, p_mnt, parent, tfd, tst, t_mnt, target, ident, entries, "delete")
                if tst.st_dev != pst.st_dev or t_mnt != p_mnt:
                    raise OSError(errno.EXDEV, f"'{target}' crosses mount boundary")
                clear_dir_contents_same_mount(tfd, tst.st_dev, t_mnt, target, mountpoints)
            finally:
                os.close(tfd)
            lst = os.lstat(base, dir_fd=pfd)
            if lst.st_dev != ident["t_dev"] or lst.st_ino != ident["t_ino"]:
                raise OSError(
                    errno.EXDEV,
                    f"refusing to remove '{target}': directory inode changed before rmdir (leaving for inspection)",
                )
            os.rmdir(base, dir_fd=pfd)
        finally:
            os.close(pfd)
    elif op == "safe-rmtree":
        target = norm_abs(sys.argv[2])
        parent = os.path.dirname(target) or "/"
        base = os.path.basename(target)
        pfd = open_chain_opath(parent)
        try:
            try:
                os.lstat(base, dir_fd=pfd)
            except FileNotFoundError:
                sys.exit(0)
            entries = parse_mountinfo()
            mountpoints = visible_mountpoints(entries)
            check_no_mounts(target, mountpoints)
            pst = os.fstat(pfd)
            p_mnt = fd_mnt_id(pfd)
            st = assert_entry_same_mount(pfd, base, pst.st_dev, p_mnt, target, mountpoints)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                os.unlink(base, dir_fd=pfd)
            else:
                rmtree_same_mount(pfd, base, pst.st_dev, p_mnt, target, mountpoints)
        finally:
            os.close(pfd)
    elif op == "verify-images-fallback":
        state_dir = norm_abs(sys.argv[2])
        entries = parse_mountinfo()
        mountpoints = visible_mountpoints(entries)
        images_root = f"{state_dir}/images"
        if images_root in mountpoints:
            raise OSError(errno.EXDEV, f"refusing mounted images directory '{images_root}'")
        sfd = open_chain_opath(state_dir)
        try:
            s_st = os.fstat(sfd)
            s_mnt = fd_mnt_id(sfd)
            try:
                ifd = os.open("images", READ_DIR_FLAGS, dir_fd=sfd)
            except FileNotFoundError:
                sys.exit(0)
            try:
                i_st = os.fstat(ifd)
                if i_st.st_dev != s_st.st_dev or fd_mnt_id(ifd) != s_mnt:
                    raise OSError(errno.EXDEV, f"'{images_root}' crosses mount boundary")
                for entry in sorted(os.listdir(ifd)):
                    if entry.startswith("qeminga-e2e-"):
                        sys.stderr.write(
                            f"setup-kvm-runner: VM run entry '{entry}' remains under '{state_dir}/images' while cleanup hook is unavailable\n"
                        )
                        sys.exit(1)
            finally:
                os.close(ifd)
        finally:
            os.close(sfd)
    else:
        sys.stderr.write(f"setup-kvm-runner: unknown fs_ops op '{op}'\n")
        sys.exit(1)
except OSError as exc:
    sys.stderr.write(f"setup-kvm-runner: fs_ops {op} failed: {exc}\n")
    sys.exit(1)
PY
}

# Return the validated direct-child workspace name when <work_dir> lives inside
# <install_dir> (for example "_work" or a custom relative JIT workFolder), or
# empty string when <work_dir> is outside <install_dir>.
runner_workspace_child_name() {
    local install_dir="${1%/}" work_dir="${2%/}"
    [ -n "$install_dir" ] && [ -n "$work_dir" ] || return 0
    case "$work_dir" in
        "${install_dir}/"*)
            local child="${work_dir#"${install_dir}/"}"
            [[ "$child" =~ ^[A-Za-z0-9._-]+$ ]] \
                || die "refusing unsafe recorded workspace path '$work_dir' inside '$install_dir'"
            case "$child" in
                . | .. | .* | bin | externals | _diag | run.sh | config.sh | env.sh)
                    die "refusing reserved recorded workspace path '$work_dir' inside '$install_dir'"
                    ;;
            esac
            printf '%s' "$child"
            ;;
        "$install_dir")
            die "refusing recorded workspace path '$work_dir' equal to runner directory '$install_dir'"
            ;;
    esac
}

# Build the comma-separated top-level workspace exclusion list passed to
# `fs_ops safe-chown-tree` for runner directories so ordinary hard-linked job
# files in `_work` or a custom JIT workspace are excluded from package ownership
# changes while all runner package files keep strict single-link enforcement.
runner_workspace_skip_list() {
    local install_dir="$1" work_dir="${2:-}"
    local work_child=""
    if [ -n "$work_dir" ]; then
        work_child="$(runner_workspace_child_name "$install_dir" "$work_dir")"
    fi
    if [ -n "$work_child" ] && [ "$work_child" != "_work" ]; then
        printf '_work,%s' "$work_child"
    else
        printf '_work'
    fi
}

# Recursively change ownership of a managed directory strictly within its own
# mount boundary and optional recorded backing volume, rejecting any regular
# file hard-linked outside the managed directory and applying os.fchown directly
# on still-open verified FDs. Under real root (euid == 0), fs_ops performs every
# os.fchown directly over open FDs.
safe_chown_runner_dir() {
    local target_spec="$1" dir="$2" expected_vol="${3:-}" skip_children="${4:-}"
    local uid gid
    if [ "$target_spec" = "root:root" ]; then
        uid=0
        gid=0
    else
        uid="${REC_USER_UID:-${MANAGED_USER_UID:-$(id -u "$OPT_USER")}}"
        gid="${REC_USER_GID:-${MANAGED_USER_GID:-$(id -g "$OPT_USER")}}"
    fi
    fs_ops safe-chown-tree "$dir" "$uid" "$gid" "$expected_vol" "$skip_children" \
        || die "refusing recursive ownership change on '$dir' (mount boundary, outside hard link, volume mismatch, or unsafe entry)"
    if [ "$(/usr/bin/id -u)" -ne 0 ]; then
        chown -h "${target_spec}" "$dir"
    fi
}

is_reserved_system_dir() {
    case "$1" in
        / | /bin | /boot | /dev | /etc | /home | /lib | /lib64 | /mnt | /opt | /proc | /root | /run | /sbin | /srv | /sys | /tmp | /usr | /usr/bin | /usr/lib | /usr/local | /usr/local/bin | /usr/local/libexec | /usr/sbin | /var | /var/lib | /var/log | /var/tmp)
            return 0
            ;;
        *) return 1 ;;
    esac
}

# Walk EVERY ancestor component from / down to dirname "$target" and refuse any
# symlink (including dangling symlinks), non-directory, non-root owner, or
# group-/world-writable mode. Prevents a root-owned immediate parent under an
# untrusted or symlinked ancestor from redirecting later privileged operations.
check_trusted_parent_dir() {
    local target="$1" parent
    check_abs_path "target path" "$target"
    parent="$(dirname "$target")"

    local parts=() cur="$parent"
    while [ "$cur" != "/" ]; do
        parts=("$cur" "${parts[@]}")
        cur="$(dirname "$cur")"
    done
    parts=("/" "${parts[@]}")

    local anc info owner mode
    for anc in "${parts[@]}"; do
        [ ! -L "$anc" ] || die "refusing symlinked ancestor directory '$anc' for '$target'"
        if [ ! -e "$anc" ]; then
            continue
        fi
        [ -d "$anc" ] || die "ancestor '$anc' of '$target' is not a directory"
        info="$(stat -c '%u:%a' "$anc")" || die "cannot stat ancestor directory '$anc'"
        owner="${info%%:*}"
        mode="${info#*:}"
        [ "$owner" -eq 0 ] || die "ancestor directory '$anc' of '$target' is owned by uid $owner (must be root)"
        if [ "$((8#$mode & 022))" -ne 0 ]; then
            die "ancestor directory '$anc' of '$target' has mode $mode (must not be group- or world-writable)"
        fi
    done
}

# Resolve the root-only installer lock directory. Defaults to a dot-prefixed
# path under runtime root (`<rt_root>/.qeminga-runner.locks`), which cannot
# collide with any valid systemd RuntimeDirectory=<service> name.
resolve_lock_dir() {
    local rt_root="${QEMINGA_RUNTIME_ROOT:-/run}"
    rt_root="${rt_root%/}"
    local lock_dir="${QEMINGA_LOCK_DIR:-${rt_root}/.qeminga-runner.locks}"
    printf '%s' "${lock_dir%/}"
}

check_service_lock_disjoint() {
    local rt_root="${QEMINGA_RUNTIME_ROOT:-/run}"
    rt_root="${rt_root%/}"
    local lock_dir svc_rt
    lock_dir="$(resolve_lock_dir)"
    [ -n "${OPT_SERVICE:-}" ] || return 0
    svc_rt="${rt_root}/${OPT_SERVICE}"
    if [ "$svc_rt" = "$lock_dir" ] \
        || [ "${svc_rt#"$lock_dir"/}" != "$svc_rt" ] \
        || [ "${lock_dir#"$svc_rt"/}" != "$lock_dir" ]; then
        die "refusing --service '${OPT_SERVICE}': systemd RuntimeDirectory '${svc_rt}' collides with installer lock directory '${lock_dir}'"
    fi
}

# Serialize install, update, and uninstall invocations targeting the same
# OPT_CONFIG_DIR using a stable root-owned flock outside service-managed
# RuntimeDirectory paths and the removable config directory, acquired BEFORE
# reading install.env. Lock files are never unlinked (so every process locks
# the same inode); FD 9 is closed in child runuser/systemctl calls.
acquire_install_lock() {
    command -v flock >/dev/null 2>&1 || die "flock (util-linux) is required to serialize runner lifecycle operations"
    command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to compute the installation lock key"
    check_service_lock_disjoint
    local lock_dir
    lock_dir="$(resolve_lock_dir)"
    check_abs_path "lock directory" "$lock_dir"
    [ ! -L "$lock_dir" ] || die "refusing symlinked lock directory '$lock_dir'"
    check_trusted_parent_dir "$lock_dir"
    if [ ! -e "$lock_dir" ]; then
        (
            umask 0077
            mkdir -p -- "$lock_dir"
        )
    fi
    [ ! -L "$lock_dir" ] && [ -d "$lock_dir" ] || die "lock directory '$lock_dir' is missing or unsafe"
    check_trusted_parent_dir "${lock_dir}/lock"
    chmod 0700 "$lock_dir"

    local norm_cfg="${OPT_CONFIG_DIR%/}"
    check_abs_path "config directory" "$norm_cfg"
    local lock_key lock_file
    lock_key="$(printf '%s' "$norm_cfg" | sha256sum | awk '{ print $1 }')"
    lock_file="${lock_dir}/${lock_key}.lock"
    [ ! -L "$lock_file" ] || die "refusing symlinked lock file '$lock_file'"
    if [ -e "$lock_file" ] && [ ! -f "$lock_file" ]; then
        die "lock path '$lock_file' exists and is not a regular file"
    fi

    local old_umask
    old_umask="$(umask)"
    umask 0077
    exec 9>>"$lock_file"
    umask "$old_umask"
    local lock_owner
    lock_owner="$(stat -c '%u' "$lock_file")" || die "cannot stat lock file '$lock_file'"
    [ "$lock_owner" -eq 0 ] || die "refusing lock file '$lock_file' owned by uid $lock_owner (must be root)"
    chmod 0600 "$lock_file"
    flock -x 9
}

# Validate a STAGED_* directory path recorded in install.env. A staged removal
# directory must live directly in the same trusted root-owned parent directory
# as its corresponding managed target and carry the `.qeminga-removing.*` name.
validate_staged_path() {
    local label="$1" target="$2" staged_dir="$3"
    check_abs_path "staged ${label} directory" "$staged_dir"
    local exp_parent stage_parent stage_name
    exp_parent="$(dirname "$target")"
    stage_parent="$(dirname "$staged_dir")"
    stage_name="$(basename "$staged_dir")"
    [ "$stage_parent" = "$exp_parent" ] \
        || die "refusing staged ${label} path '$staged_dir' outside expected parent '$exp_parent'"
    [[ "$stage_name" =~ ^\.qeminga-removing\.[A-Za-z0-9_-]{6,}$ ]] \
        || die "refusing unexpected staged ${label} directory name '$stage_name'"
    check_trusted_parent_dir "$staged_dir"
    [ ! -L "$staged_dir" ] || die "refusing symlinked staged ${label} directory '$staged_dir'"
    if [ -e "$staged_dir" ]; then
        [ -d "$staged_dir" ] || die "staged ${label} path '$staged_dir' is not a directory"
        local owner
        owner="$(stat -c '%u' "$staged_dir")" || die "cannot stat staged ${label} directory '$staged_dir'"
        [ "$owner" -eq 0 ] || die "refusing staged ${label} directory '$staged_dir' owned by uid $owner (must be root)"
    fi
}

_validate_update_sibling_path() {
    local label="$1" name_re="$2" target="$3" sibling_dir="$4"
    check_abs_path "$label" "$sibling_dir"
    local exp_parent sib_parent sib_name
    exp_parent="$(dirname "$target")"
    sib_parent="$(dirname "$sibling_dir")"
    sib_name="$(basename "$sibling_dir")"
    [ "$sib_parent" = "$exp_parent" ] \
        || die "refusing ${label} path '$sibling_dir' outside expected parent '$exp_parent'"
    [[ "$sib_name" =~ $name_re ]] \
        || die "refusing unexpected ${label} name '$sib_name'"
    check_trusted_parent_dir "$sibling_dir"
    [ ! -L "$sibling_dir" ] || die "refusing symlinked ${label} '$sibling_dir'"
    if [ -e "$sibling_dir" ]; then
        [ -d "$sibling_dir" ] || die "${label} path '$sibling_dir' is not a directory"
        local owner
        owner="$(stat -c '%u' "$sibling_dir")" || die "cannot stat ${label} '$sibling_dir'"
        [ "$owner" -eq 0 ] || die "refusing ${label} '$sibling_dir' owned by uid $owner (must be root)"
    fi
}

# Validate an UPDATE_BACKUP_DIR path recorded in install.env during an
# in-progress runner update. Must live directly in the same trusted root-owned
# parent directory as INSTALL_DIR and carry the `.qeminga-update-backup.*` name.
validate_update_backup_path() {
    _validate_update_sibling_path "update backup directory" '^\.qeminga-update-backup\.[A-Za-z0-9_-]{6,}$' "$1" "$2"
}

# Validate an UPDATE_STAGE_DIR path recorded in install.env during an
# in-progress runner update. Must live directly in the same trusted root-owned
# parent directory as INSTALL_DIR and carry the `.qeminga-extract.*` name.
validate_update_stage_path() {
    _validate_update_sibling_path "update stage directory" '^\.qeminga-extract\.[A-Za-z0-9_-]{6,}$' "$1" "$2"
}

staged_payload_exists() {
    local label="$1" target="$2" staged_dir="$3"
    [ -n "$staged_dir" ] || return 1
    validate_staged_path "$label" "$target" "$staged_dir"
    local base payload
    base="$(basename "$target")"
    payload="${staged_dir}/${base}"
    [ -e "$payload" ] || [ -L "$payload" ]
}

# allow_existing:
#   0      = fresh install (none of the four managed dirs may exist)
#   1      = active install record (all four managed dirs may exist)
#   2      = user-only / user-pending record (only CONFIG_DIR may exist,
#            and it may contain only install.env)
#   record = interrupted install recovery (each dir may exist ONLY if its
#            corresponding REC_OWNED_* flag is 1)
#   owned  = uninstall mode (validate only dirs with REC_OWNED_* = 1 whose
#            payload has not already been moved to a private staging dir;
#            ignore unowned paths so foreign paths cannot block cleanup)
check_dedicated_managed_dirs() {
    local allow_existing="$1"
    local dirs=("$OPT_INSTALL_DIR" "$OPT_STATE_DIR" "$OPT_HOOK_DIR" "$OPT_CONFIG_DIR")
    local labels=("runner" "state" "hook" "config")
    local owned=("${REC_OWNED_INSTALL_DIR:-0}" "${REC_OWNED_STATE_DIR:-0}" "${REC_OWNED_HOOK_DIR:-0}" "${REC_OWNED_CONFIG_DIR:-0}")
    local staged=("${REC_STAGED_INSTALL_DIR:-}" "${REC_STAGED_STATE_DIR:-}" "${REC_STAGED_HOOK_DIR:-}" "")
    local i j a b
    for i in 0 1 2 3; do
        a="${dirs[$i]}"
        check_abs_path "managed directory" "$a"
        if is_reserved_system_dir "$a"; then
            die "refusing shared system directory '$a' as a managed runner directory"
        fi
        if [ "$allow_existing" = "owned" ]; then
            if [ "${owned[$i]}" != "1" ] || staged_payload_exists "${labels[$i]}" "$a" "${staged[$i]}"; then
                continue
            fi
        fi
        [ ! -L "$a" ] || die "refusing symlinked managed directory '$a'"
        check_trusted_parent_dir "$a"
        if [ "$allow_existing" = "0" ] && [ -e "$a" ]; then
            die "refusing to adopt existing unmanaged path '$a' (no installation record at $OPT_CONFIG_DIR/install.env); choose a dedicated path or remove it first"
        fi
        if [ "$allow_existing" = "2" ] && [ "$i" -ne 3 ] && [ -e "$a" ]; then
            die "refusing to adopt existing unmanaged path '$a' while $OPT_CONFIG_DIR/install.env records only a surviving service user; choose a dedicated path or remove it first"
        fi
        if [ "$allow_existing" = "record" ] && [ "${owned[$i]}" != "1" ] && [ -e "$a" ]; then
            die "refusing to adopt existing unowned path '$a' (not created by the interrupted installation recorded at $OPT_CONFIG_DIR/install.env); remove it or uninstall first"
        fi
        if [ -e "$a" ] && [ ! -d "$a" ]; then
            die "managed path '$a' exists and is not a directory"
        fi
    done
    if [ "$allow_existing" = "2" ] && [ -d "$OPT_CONFIG_DIR" ]; then
        local extra
        extra="$(find "$OPT_CONFIG_DIR" -mindepth 1 -maxdepth 1 ! -name 'install.env' -print -quit 2>/dev/null || true)"
        if [ -n "$extra" ]; then
            die "refusing unexpected entry '$extra' in '$OPT_CONFIG_DIR' alongside ${REC_STATE:-user-only} install.env"
        fi
    fi
    for i in 0 1 2 3; do
        for j in 0 1 2 3; do
            [ "$i" -lt "$j" ] || continue
            a="${dirs[$i]}"
            b="${dirs[$j]}"
            if [ "$a" = "$b" ] || [ "${a#"$b"/}" != "$a" ] || [ "${b#"$a"/}" != "$b" ]; then
                die "managed directories must be distinct and non-overlapping: '$a' vs '$b'"
            fi
        done
    done
}

# Refuse to stop or overwrite an existing systemd service (including vendor
# units under /usr/lib/systemd/system or /lib/systemd/system, drop-ins, or
# systemd-known loaded/masked/static units) when no matching installation
# record owns that unit.
check_unit_not_occupied() {
    local unit="${OPT_SERVICE}.service"
    local primary_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    primary_dir="${primary_dir%/}"
    local unit_dirs="${QEMINGA_SYSTEMD_UNIT_DIRS:-/etc/systemd/system:/run/systemd/system:/usr/local/lib/systemd/system:/usr/lib/systemd/system:/lib/systemd/system}"
    local dirs=() d
    IFS=':' read -r -a dirs <<<"${primary_dir}:${unit_dirs}"
    for d in "${dirs[@]}"; do
        [ -n "$d" ] || continue
        d="${d%/}"
        if [ -e "${d}/${unit}" ] || [ -L "${d}/${unit}" ] || [ -e "${d}/${unit}.d" ]; then
            die "systemd unit '${unit}' already exists at '${d}/${unit}' without a matching unit ownership record at $OPT_CONFIG_DIR/install.env; refusing to overwrite an unmanaged service (pass --service <new-name>)"
        fi
    done

    if command -v systemctl >/dev/null 2>&1; then
        local load_state
        load_state="$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)"
        if [ -n "$load_state" ] && [ "$load_state" != "not-found" ]; then
            die "systemd already knows unit '${unit}' (LoadState=${load_state}) without a matching unit ownership record at $OPT_CONFIG_DIR/install.env; refusing to replace an unmanaged service (pass --service <new-name>)"
        fi
        local listed
        listed="$(systemctl list-unit-files --no-legend --no-pager "$unit" 2>/dev/null | awk 'NF { print $1 }' || true)"
        if [ -n "$listed" ]; then
            die "systemd unit '${unit}' is already registered (${listed}) without a matching unit ownership record at $OPT_CONFIG_DIR/install.env; refusing to replace an unmanaged service (pass --service <new-name>)"
        fi
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            die "systemd unit '${unit}' is currently active without a matching unit ownership record at $OPT_CONFIG_DIR/install.env; refusing to stop or replace an unmanaged service (pass --service <new-name>)"
        fi
    fi
}

read_install_record() {
    local rec="$1"
    check_trusted_parent_dir "$rec"
    [ ! -L "$rec" ] || die "refusing symlinked installation record '$rec'"
    [ -f "$rec" ] || die "missing installation record '$rec'"
    local owner
    owner="$(stat -c '%u' "$rec")" || die "cannot stat installation record '$rec'"
    [ "$owner" -eq 0 ] || die "refusing installation record '$rec' owned by uid $owner (must be root)"

    HAS_INSTALL_RECORD=0
    HAS_USER_RECORD=0
    REC_SCHEMA="" REC_STATE="" REC_INSTALL_ID="" REC_SERVICE="" REC_USER="" REC_USER_UID="" REC_USER_GID=""
    REC_USER_CREATED="" REC_INSTALL_DIR="" REC_STATE_DIR="" REC_HOOK_DIR=""
    REC_CONFIG_DIR="" REC_TARGET_URL="" REC_RUNNER_GROUP="" REC_RUNNER_NAME=""
    REC_LABELS="" REC_EPHEMERAL="" REC_ALLOW_AUTO_UPDATE="" REC_WORK_DIR=""
    REC_OWNED_CONFIG_DIR="" REC_OWNED_STATE_DIR="" REC_OWNED_INSTALL_DIR=""
    REC_OWNED_HOOK_DIR="" REC_OWNED_UNIT=""
    REC_STAGED_UNIT="" REC_STAGED_INSTALL_DIR="" REC_STAGED_HOOK_DIR="" REC_STAGED_STATE_DIR=""
    REC_UPDATE_PHASE="" REC_UPDATE_STAGE_DIR="" REC_UPDATE_STAGE_ID=""
    REC_UPDATE_BACKUP_DIR="" REC_UPDATE_BACKUP_ID="" REC_UPDATE_WAS_ACTIVE=""
    REC_VOL_UNIT="" REC_VOL_INSTALL_DIR="" REC_VOL_HOOK_DIR="" REC_VOL_STATE_DIR=""

    local key val
    while IFS='=' read -r key val; do
        case "$key" in
            '' | '#'*) continue ;;
            RECORD_SCHEMA) REC_SCHEMA="$val" ;;
            RECORD_STATE) REC_STATE="$val" ;;
            INSTALL_ID) REC_INSTALL_ID="$val" ;;
            SERVICE) REC_SERVICE="$val" ;;
            USER) REC_USER="$val" ;;
            USER_UID) REC_USER_UID="$val" ;;
            USER_GID) REC_USER_GID="$val" ;;
            USER_CREATED) REC_USER_CREATED="$val" ;;
            INSTALL_DIR) REC_INSTALL_DIR="$val" ;;
            STATE_DIR) REC_STATE_DIR="$val" ;;
            HOOK_DIR) REC_HOOK_DIR="$val" ;;
            CONFIG_DIR) REC_CONFIG_DIR="$val" ;;
            TARGET_URL) REC_TARGET_URL="$val" ;;
            RUNNER_GROUP) REC_RUNNER_GROUP="$val" ;;
            RUNNER_NAME) REC_RUNNER_NAME="$val" ;;
            LABELS) REC_LABELS="$val" ;;
            EPHEMERAL) REC_EPHEMERAL="$val" ;;
            ALLOW_AUTO_UPDATE) REC_ALLOW_AUTO_UPDATE="$val" ;;
            WORK_DIR) REC_WORK_DIR="$val" ;;
            OWNED_CONFIG_DIR) REC_OWNED_CONFIG_DIR="$val" ;;
            OWNED_STATE_DIR) REC_OWNED_STATE_DIR="$val" ;;
            OWNED_INSTALL_DIR) REC_OWNED_INSTALL_DIR="$val" ;;
            OWNED_HOOK_DIR) REC_OWNED_HOOK_DIR="$val" ;;
            OWNED_UNIT) REC_OWNED_UNIT="$val" ;;
            STAGED_UNIT) REC_STAGED_UNIT="$val" ;;
            STAGED_INSTALL_DIR) REC_STAGED_INSTALL_DIR="$val" ;;
            STAGED_HOOK_DIR) REC_STAGED_HOOK_DIR="$val" ;;
            STAGED_STATE_DIR) REC_STAGED_STATE_DIR="$val" ;;
            UPDATE_PHASE) REC_UPDATE_PHASE="$val" ;;
            UPDATE_STAGE_DIR) REC_UPDATE_STAGE_DIR="$val" ;;
            UPDATE_STAGE_ID) REC_UPDATE_STAGE_ID="$val" ;;
            UPDATE_BACKUP_DIR) REC_UPDATE_BACKUP_DIR="$val" ;;
            UPDATE_BACKUP_ID) REC_UPDATE_BACKUP_ID="$val" ;;
            UPDATE_WAS_ACTIVE) REC_UPDATE_WAS_ACTIVE="$val" ;;
            VOL_UNIT) REC_VOL_UNIT="$val" ;;
            VOL_INSTALL_DIR) REC_VOL_INSTALL_DIR="$val" ;;
            VOL_HOOK_DIR) REC_VOL_HOOK_DIR="$val" ;;
            VOL_STATE_DIR) REC_VOL_STATE_DIR="$val" ;;
            *) die "unknown key '$key' in installation record '$rec'" ;;
        esac
    done <"$rec"

    [ "$REC_SCHEMA" = "1" ] || die "unsupported installation record schema '${REC_SCHEMA:-<empty>}' in '$rec'"
    REC_STATE="${REC_STATE:-installed}"
    case "$REC_STATE" in
        installed | installing | updating | partial-uninstall | user-only | user-pending) ;;
        *) die "unsupported installation record state '$REC_STATE' in '$rec'" ;;
    esac
    [ -n "$REC_USER" ] && [ -n "$REC_CONFIG_DIR" ] \
        || die "incomplete installation record '$rec'"

    if [ -n "$REC_INSTALL_ID" ]; then
        [[ "$REC_INSTALL_ID" =~ ^[A-Za-z0-9._-]{16,128}$ ]] \
            || die "invalid INSTALL_ID '$REC_INSTALL_ID' in '$rec'"
    fi
    local vol_val
    for vol_val in "$REC_VOL_UNIT" "$REC_VOL_INSTALL_DIR" "$REC_VOL_HOOK_DIR" "$REC_VOL_STATE_DIR"; do
        if [ -n "$vol_val" ]; then
            [[ "$vol_val" =~ ^[A-Za-z0-9._/%:,+-]+$ ]] \
                || die "invalid VOL_* fingerprint '$vol_val' in '$rec'"
        fi
    done

    if [ "$REC_STATE" != "partial-uninstall" ]; then
        if [ -n "$REC_STAGED_UNIT" ] || [ -n "$REC_STAGED_INSTALL_DIR" ] \
            || [ -n "$REC_STAGED_HOOK_DIR" ] || [ -n "$REC_STAGED_STATE_DIR" ]; then
            die "unexpected STAGED_* entry in $REC_STATE installation record '$rec'"
        fi
    fi
    if [ "$REC_STATE" != "updating" ]; then
        if [ -n "$REC_UPDATE_PHASE" ] || [ -n "$REC_UPDATE_STAGE_DIR" ] || [ -n "$REC_UPDATE_STAGE_ID" ] \
            || [ -n "$REC_UPDATE_BACKUP_DIR" ] || [ -n "$REC_UPDATE_BACKUP_ID" ] || [ -n "$REC_UPDATE_WAS_ACTIVE" ]; then
            die "unexpected UPDATE_* entry in $REC_STATE installation record '$rec'"
        fi
    else
        case "$REC_UPDATE_PHASE" in
            publishing | restored | committed) ;;
            *) die "invalid UPDATE_PHASE '${REC_UPDATE_PHASE:-<empty>}' in updating installation record '$rec'" ;;
        esac
        case "$REC_UPDATE_WAS_ACTIVE" in
            0 | 1) ;;
            *) die "invalid UPDATE_WAS_ACTIVE '${REC_UPDATE_WAS_ACTIVE:-<empty>}' in updating installation record '$rec'" ;;
        esac
        local id_re='^p_dev:[0-9]+;p_ino:[0-9]+;p_mnt:[0-9]+;t_dev:[0-9]+;t_ino:[0-9]+;t_mnt:[0-9]+;vol:[A-Za-z0-9._/%:,+-]+$'
        if [ -n "$REC_UPDATE_STAGE_ID" ]; then
            [[ "$REC_UPDATE_STAGE_ID" =~ $id_re ]] \
                || die "invalid UPDATE_STAGE_ID '$REC_UPDATE_STAGE_ID' in '$rec'"
        fi
        if [ -n "$REC_UPDATE_BACKUP_ID" ]; then
            [[ "$REC_UPDATE_BACKUP_ID" =~ $id_re ]] \
                || die "invalid UPDATE_BACKUP_ID '$REC_UPDATE_BACKUP_ID' in '$rec'"
        fi
        if { [ -n "$REC_UPDATE_STAGE_DIR" ] && [ -z "$REC_UPDATE_STAGE_ID" ]; } \
            || { [ -z "$REC_UPDATE_STAGE_DIR" ] && [ -n "$REC_UPDATE_STAGE_ID" ]; }; then
            die "incomplete UPDATE_STAGE_DIR/UPDATE_STAGE_ID pair in updating installation record '$rec'"
        fi
        if { [ -n "$REC_UPDATE_BACKUP_DIR" ] && [ -z "$REC_UPDATE_BACKUP_ID" ]; } \
            || { [ -z "$REC_UPDATE_BACKUP_DIR" ] && [ -n "$REC_UPDATE_BACKUP_ID" ]; }; then
            die "incomplete UPDATE_BACKUP_DIR/UPDATE_BACKUP_ID pair in updating installation record '$rec'"
        fi
        case "$REC_UPDATE_PHASE" in
            publishing | committed)
                [ -n "$REC_UPDATE_BACKUP_DIR" ] && [ -n "$REC_UPDATE_BACKUP_ID" ] \
                    || die "missing UPDATE_BACKUP_DIR/UPDATE_BACKUP_ID in $REC_UPDATE_PHASE updating record '$rec'"
                ;;
            restored)
                [ -z "$REC_UPDATE_STAGE_DIR" ] && [ -z "$REC_UPDATE_BACKUP_DIR" ] \
                    || die "unexpected UPDATE_STAGE_DIR/UPDATE_BACKUP_DIR in restored updating record '$rec'"
                ;;
        esac
    fi

    if [ "$REC_STATE" = "user-pending" ]; then
        [ -n "$REC_INSTALL_ID" ] \
            || die "incomplete user-pending installation record '$rec' (missing INSTALL_ID); refusing to adopt or purge '$REC_USER' (leaving record intact for manual inspection)"
        if [ -n "$REC_USER_UID" ]; then
            [[ "$REC_USER_UID" =~ ^[1-9][0-9]*$ ]] || die "invalid USER_UID '$REC_USER_UID' in '$rec'"
        fi
        if [ -n "$REC_USER_GID" ]; then
            [[ "$REC_USER_GID" =~ ^[1-9][0-9]*$ ]] || die "invalid USER_GID '$REC_USER_GID' in '$rec'"
        fi
        REC_USER_CREATED="${REC_USER_CREATED:-1}"
        REC_OWNED_CONFIG_DIR="${REC_OWNED_CONFIG_DIR:-1}"
        REC_OWNED_STATE_DIR="0"
        REC_OWNED_INSTALL_DIR="0"
        REC_OWNED_HOOK_DIR="0"
        REC_OWNED_UNIT="0"
        HAS_USER_RECORD=1
        HAS_INSTALL_RECORD=0
        return 0
    fi

    [[ "$REC_USER_UID" =~ ^[1-9][0-9]*$ ]] || die "invalid USER_UID '$REC_USER_UID' in '$rec'"
    [[ "$REC_USER_GID" =~ ^[1-9][0-9]*$ ]] || die "invalid USER_GID '$REC_USER_GID' in '$rec'"

    if [ "$REC_STATE" = "user-only" ]; then
        REC_OWNED_CONFIG_DIR="${REC_OWNED_CONFIG_DIR:-1}"
        REC_OWNED_STATE_DIR="0"
        REC_OWNED_INSTALL_DIR="0"
        REC_OWNED_HOOK_DIR="0"
        REC_OWNED_UNIT="0"
        HAS_USER_RECORD=1
        HAS_INSTALL_RECORD=0
    else
        [ -n "$REC_SERVICE" ] && [ -n "$REC_INSTALL_DIR" ] \
            && [ -n "$REC_STATE_DIR" ] && [ -n "$REC_HOOK_DIR" ] \
            || die "incomplete installation record '$rec'"
        local def_owned="1"
        if [ "$REC_STATE" = "installing" ] || [ "$REC_STATE" = "partial-uninstall" ]; then
            def_owned="0"
        fi
        REC_OWNED_CONFIG_DIR="${REC_OWNED_CONFIG_DIR:-1}"
        REC_OWNED_STATE_DIR="${REC_OWNED_STATE_DIR:-$def_owned}"
        REC_OWNED_INSTALL_DIR="${REC_OWNED_INSTALL_DIR:-$def_owned}"
        REC_OWNED_HOOK_DIR="${REC_OWNED_HOOK_DIR:-$def_owned}"
        REC_OWNED_UNIT="${REC_OWNED_UNIT:-$def_owned}"
        local flag
        for flag in "$REC_OWNED_CONFIG_DIR" "$REC_OWNED_STATE_DIR" "$REC_OWNED_INSTALL_DIR" "$REC_OWNED_HOOK_DIR" "$REC_OWNED_UNIT"; do
            case "$flag" in
                0 | 1) ;;
                *) die "invalid OWNED_* flag '$flag' in '$rec'" ;;
            esac
        done
        HAS_INSTALL_RECORD=1
        HAS_USER_RECORD=1
    fi
}

_format_update_record_block() {
    local phase="$1" stage_dir="${2:-}" stage_id="${3:-}" backup_dir="${4:-}" backup_id="${5:-}" was_active="${6:-0}"
    printf 'UPDATE_PHASE=%s\nUPDATE_STAGE_DIR=%s\nUPDATE_STAGE_ID=%s\nUPDATE_BACKUP_DIR=%s\nUPDATE_BACKUP_ID=%s\nUPDATE_WAS_ACTIVE=%s' \
        "$phase" "$stage_dir" "$stage_id" "$backup_dir" "$backup_id" "$was_active"
}

_format_staged_record_block() {
    printf 'STAGED_UNIT=%s\nSTAGED_INSTALL_DIR=%s\nSTAGED_HOOK_DIR=%s\nSTAGED_STATE_DIR=%s' \
        "$REC_STAGED_UNIT" "$REC_STAGED_INSTALL_DIR" "$REC_STAGED_HOOK_DIR" "$REC_STAGED_STATE_DIR"
}

# Shared atomic writer for all full installation records (`install`, `update`,
# `uninstall`, and `migrate-record`) so schema fields stay consistent in one
# place.
_write_full_install_record() {
    local dest="$1" state="$2" install_id="$3" service="$4" user="$5" uid="$6" gid="$7" user_created="$8"
    local install_dir="$9" state_dir="${10}" hook_dir="${11}" config_dir="${12}"
    local target_url="${13}" runner_group="${14}" runner_name="${15}" rec_labels="${16}"
    local ephemeral="${17}" allow_auto_update="${18}" work_dir="${19}"
    local owned_cfg="${20}" owned_state="${21}" owned_inst="${22}" owned_hook="${23}" owned_unit="${24}"
    local vol_unit="${25}" vol_inst="${26}" vol_hook="${27}" vol_state="${28}"
    local extra_block="${29:-}"
    local extra_nl=""
    if [ -n "$extra_block" ]; then
        extra_nl="${extra_block}"$'\n'
    fi

    check_trusted_parent_dir "$dest"
    [ ! -L "$dest" ] || die "refusing symlinked installation record '$dest'"
    local tmp
    tmp="$(stage_managed_file_path "$dest")" \
        || die "failed to create staging file for '$dest'"
    if ! cat >"$tmp" <<EOF
# Managed by scripts/setup-kvm-runner.sh — root-owned installation record.
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
RECORD_SCHEMA=1
RECORD_STATE=${state}
INSTALL_ID=${install_id}
SERVICE=${service}
USER=${user}
USER_UID=${uid}
USER_GID=${gid}
USER_CREATED=${user_created}
INSTALL_DIR=${install_dir}
STATE_DIR=${state_dir}
HOOK_DIR=${hook_dir}
CONFIG_DIR=${config_dir}
TARGET_URL=${target_url}
RUNNER_GROUP=${runner_group}
RUNNER_NAME=${runner_name}
LABELS=${rec_labels}
EPHEMERAL=${ephemeral}
ALLOW_AUTO_UPDATE=${allow_auto_update}
WORK_DIR=${work_dir}
OWNED_CONFIG_DIR=${owned_cfg}
OWNED_STATE_DIR=${owned_state}
OWNED_INSTALL_DIR=${owned_inst}
OWNED_HOOK_DIR=${owned_hook}
OWNED_UNIT=${owned_unit}
${extra_nl}VOL_UNIT=${vol_unit}
VOL_INSTALL_DIR=${vol_inst}
VOL_HOOK_DIR=${vol_hook}
VOL_STATE_DIR=${vol_state}
EOF
    then
        rm -f "$tmp"
        die "failed to write installation record '$dest'"
    fi
    commit_managed_file "$tmp" "$dest" 0600 root root
}

write_install_record() {
    local dest="$1" runner_name="$2" state="${3:-installed}"
    local phase="${4:-}" stage_dir="${5:-}" stage_id="${6:-}" backup_dir="${7:-}" backup_id="${8:-}" was_active="${9:-0}"
    local extra_block=""
    if [ "$state" = "updating" ]; then
        extra_block="$(_format_update_record_block "$phase" "$stage_dir" "$stage_id" "$backup_dir" "$backup_id" "$was_active")"
    fi
    _write_full_install_record "$dest" "$state" \
        "$MANAGED_INSTALL_ID" "$OPT_SERVICE" "$OPT_USER" "$MANAGED_USER_UID" "$MANAGED_USER_GID" "$MANAGED_USER_CREATED" \
        "$OPT_INSTALL_DIR" "$OPT_STATE_DIR" "$OPT_HOOK_DIR" "$OPT_CONFIG_DIR" \
        "$TARGET_URL" "$OPT_RUNNER_GROUP" "$runner_name" "$OPT_LABELS" \
        "$OPT_EPHEMERAL" "$OPT_ALLOW_AUTO_UPDATE" "$RESOLVED_WORK_DIR" \
        "$OWNED_CONFIG_DIR" "$OWNED_STATE_DIR" "$OWNED_INSTALL_DIR" "$OWNED_HOOK_DIR" "$OWNED_UNIT" \
        "$VOL_UNIT" "$VOL_INSTALL_DIR" "$VOL_HOOK_DIR" "$VOL_STATE_DIR" \
        "$extra_block"
}

write_uninstall_record() {
    local dest="$1" extra_block
    extra_block="$(_format_staged_record_block)"
    _write_full_install_record "$dest" "partial-uninstall" \
        "$REC_INSTALL_ID" "$REC_SERVICE" "$REC_USER" "$REC_USER_UID" "$REC_USER_GID" "$REC_USER_CREATED" \
        "$REC_INSTALL_DIR" "$REC_STATE_DIR" "$REC_HOOK_DIR" "$REC_CONFIG_DIR" \
        "$REC_TARGET_URL" "$REC_RUNNER_GROUP" "$REC_RUNNER_NAME" "$REC_LABELS" \
        "$REC_EPHEMERAL" "$REC_ALLOW_AUTO_UPDATE" "$REC_WORK_DIR" \
        "$REC_OWNED_CONFIG_DIR" "$REC_OWNED_STATE_DIR" "$REC_OWNED_INSTALL_DIR" "$REC_OWNED_HOOK_DIR" "$REC_OWNED_UNIT" \
        "$REC_VOL_UNIT" "$REC_VOL_INSTALL_DIR" "$REC_VOL_HOOK_DIR" "$REC_VOL_STATE_DIR" \
        "$extra_block"
}

write_update_record() {
    local dest="$1" state="$2"
    local phase="${3:-}" stage_dir="${4:-}" stage_id="${5:-}" backup_dir="${6:-}" backup_id="${7:-}" was_active="${8:-0}"
    local extra_block=""
    if [ "$state" = "updating" ]; then
        extra_block="$(_format_update_record_block "$phase" "$stage_dir" "$stage_id" "$backup_dir" "$backup_id" "$was_active")"
    fi
    _write_full_install_record "$dest" "$state" \
        "$REC_INSTALL_ID" "$REC_SERVICE" "$REC_USER" "$REC_USER_UID" "$REC_USER_GID" "$REC_USER_CREATED" \
        "$REC_INSTALL_DIR" "$REC_STATE_DIR" "$REC_HOOK_DIR" "$REC_CONFIG_DIR" \
        "$REC_TARGET_URL" "$REC_RUNNER_GROUP" "$REC_RUNNER_NAME" "$REC_LABELS" \
        "$REC_EPHEMERAL" "$REC_ALLOW_AUTO_UPDATE" "$REC_WORK_DIR" \
        "$REC_OWNED_CONFIG_DIR" "$REC_OWNED_STATE_DIR" "$REC_OWNED_INSTALL_DIR" "$REC_OWNED_HOOK_DIR" "$REC_OWNED_UNIT" \
        "$REC_VOL_UNIT" "$REC_VOL_INSTALL_DIR" "$REC_VOL_HOOK_DIR" "$REC_VOL_STATE_DIR" \
        "$extra_block"
}

write_migrated_record() {
    local dest="$1" extra_block=""
    if [ "$REC_STATE" = "partial-uninstall" ]; then
        extra_block="$(_format_staged_record_block)"
    elif [ "$REC_STATE" = "updating" ]; then
        extra_block="$(_format_update_record_block \
            "$REC_UPDATE_PHASE" "$REC_UPDATE_STAGE_DIR" "$REC_UPDATE_STAGE_ID" \
            "$REC_UPDATE_BACKUP_DIR" "$REC_UPDATE_BACKUP_ID" "$REC_UPDATE_WAS_ACTIVE")"
    fi
    _write_full_install_record "$dest" "$REC_STATE" \
        "$REC_INSTALL_ID" "$REC_SERVICE" "$REC_USER" "$REC_USER_UID" "$REC_USER_GID" "$REC_USER_CREATED" \
        "$REC_INSTALL_DIR" "$REC_STATE_DIR" "$REC_HOOK_DIR" "$REC_CONFIG_DIR" \
        "$REC_TARGET_URL" "$REC_RUNNER_GROUP" "$REC_RUNNER_NAME" "$REC_LABELS" \
        "$REC_EPHEMERAL" "$REC_ALLOW_AUTO_UPDATE" "$REC_WORK_DIR" \
        "$REC_OWNED_CONFIG_DIR" "$REC_OWNED_STATE_DIR" "$REC_OWNED_INSTALL_DIR" "$REC_OWNED_HOOK_DIR" "$REC_OWNED_UNIT" \
        "$REC_VOL_UNIT" "$REC_VOL_INSTALL_DIR" "$REC_VOL_HOOK_DIR" "$REC_VOL_STATE_DIR" \
        "$extra_block"
}

update_policy_volumes() {
    local policy_path="$1" state_vol="$2" install_vol="$3"
    [ -e "$policy_path" ] || [ -L "$policy_path" ] || return 0
    [ ! -L "$policy_path" ] || die "refusing symlinked policy file '$policy_path'"
    [ -f "$policy_path" ] || die "refusing non-regular policy file '$policy_path'"
    publish_managed_file_cmd "$policy_path" 0640 root "$OPT_USER" \
        awk -v sv="$state_vol" -v iv="$install_vol" '
            BEGIN { seen_s = 0; seen_i = 0 }
            /^STATE_VOL=/ { print "STATE_VOL=" sv; seen_s = 1; next }
            /^INSTALL_VOL=/ { print "INSTALL_VOL=" iv; seen_i = 1; next }
            { print }
            END {
                if (!seen_s) print "STATE_VOL=" sv
                if (!seen_i) print "INSTALL_VOL=" iv
            }
        ' "$policy_path"
}

write_user_only_record() {
    local dest="$1" user="$2" uid="$3" gid="$4" created="$5" cfg_dir="$6" install_id="${7:-}"
    check_trusted_parent_dir "$dest"
    [ ! -L "$dest" ] || die "refusing symlinked installation record '$dest'"
    local tmp
    tmp="$(umask 0077 && mktemp "$(dirname "$dest")/.install.env.XXXXXX")"
    if ! cat >"$tmp" <<EOF
# Managed by scripts/setup-kvm-runner.sh — retained minimal UID/GID ownership
# record for a managed service user that survived uninstall without --purge-user.
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
RECORD_SCHEMA=1
RECORD_STATE=user-only
INSTALL_ID=${install_id}
USER=${user}
USER_UID=${uid}
USER_GID=${gid}
USER_CREATED=${created}
CONFIG_DIR=${cfg_dir}
EOF
    then
        rm -f "$tmp"
        die "failed to write user-only record '$dest'"
    fi
    if ! chown -h root:root "$tmp" || ! chmod 0600 "$tmp" || ! fs_ops replace-file "$tmp" "$dest"; then
        rm -f "$tmp"
        die "failed to finalize user-only record '$dest'"
    fi
}

write_user_pending_record() {
    local dest="$1" user="$2" cfg_dir="$3" install_id="$4"
    [ -n "$install_id" ] || die "internal error: missing install_id for pending bootstrap user record"
    check_trusted_parent_dir "$dest"
    [ ! -L "$dest" ] || die "refusing symlinked installation record '$dest'"
    local tmp
    tmp="$(umask 0077 && mktemp "$(dirname "$dest")/.install.env.XXXXXX")"
    if ! cat >"$tmp" <<EOF
# Managed by scripts/setup-kvm-runner.sh — durable pre-useradd bootstrap record.
# Preserved if both initial install.env update and rollback userdel fail (e.g. ENOSPC).
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
RECORD_SCHEMA=1
RECORD_STATE=user-pending
INSTALL_ID=${install_id}
USER=${user}
USER_CREATED=1
CONFIG_DIR=${cfg_dir}
EOF
    then
        rm -f "$tmp"
        die "failed to write pending bootstrap user record '$dest'"
    fi
    if ! chown -h root:root "$tmp" || ! chmod 0600 "$tmp" || ! fs_ops replace-file "$tmp" "$dest"; then
        rm -f "$tmp"
        die "failed to finalize pending bootstrap user record '$dest'"
    fi
}

# Strictly query the passwd database for <user>, verifying getent exit status,
# exact 7 colon-delimited fields, matching username, and optional numeric
# UID/GID match. Prints the complete untrimmed 5th (GECOS) field on stdout;
# returns non-zero on lookup failure or malformed entry so callers never
# confuse a failed lookup with an empty legacy GECOS.
lookup_passwd_gecos_strict() {
    local user="$1" expect_uid="${2:-}" expect_gid="${3:-}"
    local passwd_line colons
    passwd_line="$(getent passwd "$user" 2>/dev/null)" || return 1
    [ -n "$passwd_line" ] || return 1
    case "$passwd_line" in
        *$'\n'*) return 1 ;;
    esac
    colons="${passwd_line//[^:]/}"
    [ "${#colons}" -eq 6 ] || return 1
    local p_name p_uid p_gid p_gecos _
    IFS=':' read -r p_name _ p_uid p_gid p_gecos _ _ <<<"$passwd_line"
    [ "$p_name" = "$user" ] || return 1
    [[ "$p_uid" =~ ^[0-9]+$ ]] && [[ "$p_gid" =~ ^[0-9]+$ ]] || return 1
    if [ -n "$expect_uid" ] && [ "$p_uid" != "$expect_uid" ]; then
        return 1
    fi
    if [ -n "$expect_gid" ] && [ "$p_gid" != "$expect_gid" ]; then
        return 1
    fi
    printf '%s' "$p_gecos"
}

# Verify the live account's GECOS carries qeminga-runner-<REC_INSTALL_ID>.
# Leaves install.env intact on mismatch so an operator can inspect safely.
verify_user_install_marker() {
    local mode="$1" label="${2:-service user}"
    local expected_marker full_gecos primary_gecos hint=""
    expected_marker="qeminga-runner-${REC_INSTALL_ID}"
    if ! full_gecos="$(lookup_passwd_gecos_strict "$OPT_USER" "${REC_USER_UID:-}" "${REC_USER_GID:-}")"; then
        die "${mode}: failed to look up passwd entry for ${label} '$OPT_USER' while verifying installation marker '${expected_marker}'; refusing to adopt, modify, or delete an unverified account (leaving $OPT_CONFIG_DIR/install.env intact for manual inspection)"
    fi
    primary_gecos="${full_gecos%%,*}"
    if [ "$primary_gecos" != "$expected_marker" ]; then
        if [ -z "$full_gecos" ] && [ "${REC_STATE:-}" != "user-pending" ]; then
            hint=" (if this is a pre-marker managed account from an earlier upgrade, verify it and run 'sudo $0 migrate-record --config-dir $OPT_CONFIG_DIR --confirm-account-marker')"
        fi
        die "${mode}: ${label} '$OPT_USER' does not carry installation marker '${expected_marker}' (found '${full_gecos:-<empty>}'); refusing to adopt, modify, or delete an unverified account (leaving $OPT_CONFIG_DIR/install.env intact for manual inspection)${hint}"
    fi
}

# Verify a user-pending bootstrap account (no recorded UID/GID yet) was actually
# created by THIS installation (matching INSTALL_ID stamped into the account
# GECOS during useradd), is strictly non-root, and is confined to primary group
# $OPT_USER and supplementary group kvm. Preserves install.env on mismatch.
verify_pending_user_safety() {
    local mode="$1"
    if [ -z "${REC_INSTALL_ID:-}" ]; then
        die "${mode}: user-pending record at $OPT_CONFIG_DIR/install.env is missing INSTALL_ID; refusing to adopt, modify, or delete '$OPT_USER' (leaving record intact for manual inspection)"
    fi
    if ! id "$OPT_USER" >/dev/null 2>&1; then
        return 0
    fi
    local cur_uid cur_gid pgroup groups g
    cur_uid="$(id -u "$OPT_USER")"
    cur_gid="$(id -g "$OPT_USER")"
    pgroup="$(id -gn "$OPT_USER")"
    if [ "$cur_uid" -eq 0 ] || [ "$cur_gid" -eq 0 ]; then
        die "${mode}: pending service user '$OPT_USER' has root uid/gid (${cur_uid}:${cur_gid}); refusing to proceed (leaving $OPT_CONFIG_DIR/install.env intact)"
    fi
    if [ "$pgroup" != "$OPT_USER" ]; then
        die "${mode}: pending service user '$OPT_USER' primary group '$pgroup' does not match '$OPT_USER'; refusing to proceed (leaving $OPT_CONFIG_DIR/install.env intact)"
    fi
    groups="$(id -nG "$OPT_USER")"
    for g in $groups; do
        if [ "$g" != "$OPT_USER" ] && [ "$g" != "kvm" ]; then
            die "${mode}: pending service user '$OPT_USER' belongs to unexpected group '$g' (only '$OPT_USER' and 'kvm' are permitted); refusing to proceed (leaving $OPT_CONFIG_DIR/install.env intact)"
        fi
    done
    verify_user_install_marker "$mode" "pending service user"
}

# Verify the live numeric UID/GID (and, for records carrying INSTALL_ID, the
# stamped GECOS installation marker) of OPT_USER match the root-owned record
# BEFORE any runuser execution, chown, credential handling, service stop, or
# file removal. Leaves install.env intact on mismatch so the operator can
# inspect and recover safely. Legacy records without INSTALL_ID stay
# distinguishable and verify numeric UID/GID during migration.
verify_recorded_user_identity() {
    local mode="$1"
    if [ "$REC_STATE" = "user-pending" ]; then
        verify_pending_user_safety "$mode"
        return 0
    fi
    if id "$OPT_USER" >/dev/null 2>&1; then
        local cur_uid cur_gid
        cur_uid="$(id -u "$OPT_USER")"
        cur_gid="$(id -g "$OPT_USER")"
        if [ "$cur_uid" -eq 0 ] || [ "$cur_uid" != "$REC_USER_UID" ] || [ "$cur_gid" != "$REC_USER_GID" ]; then
            die "${mode}: service user '$OPT_USER' uid:gid (${cur_uid}:${cur_gid}) does not match recorded ${REC_USER_UID}:${REC_USER_GID}; refusing to proceed (leaving $OPT_CONFIG_DIR/install.env intact for recovery)"
        fi
        if [ -n "${REC_INSTALL_ID:-}" ] && [ "${REC_USER_CREATED:-1}" = "1" ]; then
            verify_user_install_marker "$mode" "service user"
        fi
    elif [ "$mode" = "update" ]; then
        die "update: recorded service user '$OPT_USER' does not exist"
    fi
}

# Shared fail-closed installation record verification for both `update` and
# `uninstall`. Refuses to proceed without a valid root-owned record, rejects
# any explicit CLI option that disagrees with the recorded identity or paths,
# and verifies live numeric UID/GID before any privileged operation.
load_and_verify_install_record() {
    local mode="$1"
    local rec_path="$OPT_CONFIG_DIR/install.env"
    read_install_record "$rec_path"

    if [ "$SET_USER" -eq 1 ] && [ "$OPT_USER" != "$REC_USER" ]; then
        die "${mode}: --user '$OPT_USER' does not match installation record '$REC_USER'"
    fi
    [ "$OPT_CONFIG_DIR" = "$REC_CONFIG_DIR" ] \
        || die "${mode}: --config-dir '$OPT_CONFIG_DIR' does not match installation record '$REC_CONFIG_DIR'"

    if [ "$REC_STATE" = "user-only" ] || [ "$REC_STATE" = "user-pending" ]; then
        if [ "$mode" = "update" ]; then
            die "update: $rec_path records only a surviving service user '$REC_USER' (state '$REC_STATE', no active runner installation)"
        fi
        OPT_USER="$REC_USER"
        OPT_CONFIG_DIR="$REC_CONFIG_DIR"
        check_abs_path "config directory" "$OPT_CONFIG_DIR"
        if is_reserved_system_dir "$OPT_CONFIG_DIR"; then
            die "refusing shared system directory '$OPT_CONFIG_DIR' as a managed runner directory"
        fi
        [ ! -L "$OPT_CONFIG_DIR" ] || die "refusing symlinked managed directory '$OPT_CONFIG_DIR'"
        check_trusted_parent_dir "$OPT_CONFIG_DIR"
        local extra
        extra="$(find "$OPT_CONFIG_DIR" -mindepth 1 -maxdepth 1 ! -name 'install.env' -print -quit 2>/dev/null || true)"
        if [ -n "$extra" ]; then
            die "${mode}: refusing unexpected entry '$extra' in '$OPT_CONFIG_DIR' alongside $REC_STATE install.env"
        fi
        verify_recorded_user_identity "$mode"
        return 0
    fi

    if [ "$mode" = "update" ] && [ "$REC_STATE" != "installed" ] && [ "$REC_STATE" != "updating" ]; then
        if [ "$REC_STATE" = "partial-uninstall" ]; then
            die "update: $rec_path has state 'partial-uninstall' (finish 'uninstall' first)"
        fi
        die "update: $rec_path has state '$REC_STATE' (finish 'install' or run 'uninstall' first)"
    fi

    if [ "$SET_SERVICE" -eq 1 ] && [ "$OPT_SERVICE" != "$REC_SERVICE" ]; then
        die "${mode}: --service '$OPT_SERVICE' does not match installation record '$REC_SERVICE'"
    fi
    if [ "$SET_INSTALL_DIR" -eq 1 ] && [ "$OPT_INSTALL_DIR" != "$REC_INSTALL_DIR" ]; then
        die "${mode}: --install-dir '$OPT_INSTALL_DIR' does not match installation record '$REC_INSTALL_DIR'"
    fi
    if [ "$SET_STATE_DIR" -eq 1 ] && [ "$OPT_STATE_DIR" != "$REC_STATE_DIR" ]; then
        die "${mode}: --state-dir '$OPT_STATE_DIR' does not match installation record '$REC_STATE_DIR'"
    fi
    if [ "$SET_HOOK_DIR" -eq 1 ] && [ "$OPT_HOOK_DIR" != "$REC_HOOK_DIR" ]; then
        die "${mode}: --hook-dir '$OPT_HOOK_DIR' does not match installation record '$REC_HOOK_DIR'"
    fi
    if [ "$mode" = "update" ]; then
        if [ "$SET_EPHEMERAL" -eq 1 ] && [ "$OPT_EPHEMERAL" != "${REC_EPHEMERAL:-0}" ]; then
            die "update: --ephemeral setting disagrees with installation record (EPHEMERAL=${REC_EPHEMERAL:-0})"
        fi
        if [ "$SET_ALLOW_AUTO_UPDATE" -eq 1 ] && [ "$OPT_ALLOW_AUTO_UPDATE" != "${REC_ALLOW_AUTO_UPDATE:-0}" ]; then
            die "update: --allow-auto-update setting disagrees with installation record (ALLOW_AUTO_UPDATE=${REC_ALLOW_AUTO_UPDATE:-0})"
        fi
        OPT_EPHEMERAL="${REC_EPHEMERAL:-0}"
        OPT_ALLOW_AUTO_UPDATE="${REC_ALLOW_AUTO_UPDATE:-0}"
    fi

    OPT_SERVICE="$REC_SERVICE"
    OPT_USER="$REC_USER"
    OPT_INSTALL_DIR="$REC_INSTALL_DIR"
    OPT_STATE_DIR="$REC_STATE_DIR"
    OPT_HOOK_DIR="$REC_HOOK_DIR"
    OPT_CONFIG_DIR="$REC_CONFIG_DIR"
    if [ "$mode" = "uninstall" ]; then
        check_dedicated_managed_dirs owned
    else
        check_dedicated_managed_dirs 1
    fi
    verify_recorded_user_identity "$mode"
}

# Shared rollback helper for both `update` and transactional `install`
# (reinstalling an existing installed runner). Restores the previous runner
# binaries from the verified backup container, immediately records
# `UPDATE_PHASE=restored` so a follow-up failure never points at a consumed
# backup, re-locks permissions with the original policy, restarts the service
# if it was originally active, and returns install.env to `installed`.
_rollback_runner_package_tx() {
    local rec_path="$1" expected_vol="$2" backup_dir="$3" backup_id="$4" work_child="$5" was_active="$6"
    local restore_ok=1
    if [ -n "$backup_dir" ]; then
        if [ -n "$backup_id" ]; then
            if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
                systemctl stop "${OPT_SERVICE}.service" 9>&- 2>/dev/null || true
            fi
            if fs_ops restore-runner-backup "$OPT_INSTALL_DIR" "$expected_vol" "$backup_dir" "$backup_id" "$work_child" "0"; then
                if [ -n "$rec_path" ]; then
                    ( write_update_record "$rec_path" "updating" "restored" "" "" "" "" "$was_active" ) || true
                fi
                if ! (
                    OPT_ALLOW_AUTO_UPDATE="${REC_ALLOW_AUTO_UPDATE:-0}"
                    OPT_EPHEMERAL="${REC_EPHEMERAL:-0}"
                    RESOLVED_WORK_DIR="${REC_WORK_DIR:-}"
                    VOL_INSTALL_DIR="$expected_vol"
                    lock_runner_permissions
                ); then
                    warn "rollback restored previous runner files but failed to re-lock permissions on '$OPT_INSTALL_DIR'; preserving updating record for retry"
                    restore_ok=0
                fi
            else
                warn "rollback could not restore previous runner from '$backup_dir'; preserving updating record at '$rec_path' for retry"
                restore_ok=0
            fi
        else
            warn "rollback missing captured identity for '$backup_dir'; preserving updating record at '$rec_path' for inspection"
            restore_ok=0
        fi
    fi
    if [ "$restore_ok" -eq 1 ]; then
        local service_ok=1
        if [ "$was_active" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
            warn "restarting previously active ${OPT_SERVICE}.service after failed package replacement"
            if ! systemctl start "${OPT_SERVICE}.service" 9>&-; then
                warn "failed to restart ${OPT_SERVICE}.service during rollback; preserving updating record so retry remembers the service was active"
                service_ok=0
            fi
        fi
        if [ -n "$rec_path" ]; then
            if [ "$service_ok" -eq 1 ]; then
                ( write_update_record "$rec_path" "installed" ) || true
            else
                ( write_update_record "$rec_path" "updating" "restored" "" "" "" "" "$was_active" ) || true
            fi
        fi
    fi
}

_INSTALL_BOOTSTRAP_CFG=""
_INSTALL_BOOTSTRAP_PENDING_REC=""
_INSTALL_BOOTSTRAP_DIR=""
_INSTALL_BOOTSTRAP_UNIT=""
_INSTALL_BOOTSTRAP_USER=""
_INSTALL_BOOTSTRAP_TARBALL=""
_INSTALL_BOOTSTRAP_STAGE=""
_INSTALL_BOOTSTRAP_STAGE_ID=""
_INSTALL_REINSTALL_TX=0
_INSTALL_REINSTALL_ROLLBACK=0
_INSTALL_REINSTALL_COMMITTED=0
_INSTALL_REINSTALL_BACKUP_DIR=""
_INSTALL_REINSTALL_BACKUP_ID=""
_INSTALL_REINSTALL_WAS_ACTIVE=0
_INSTALL_REINSTALL_WORK_CHILD=""
_INSTALL_REINSTALL_VOL=""
_INSTALL_REINSTALL_RECORD_PATH=""

cleanup_install_exit() {
    if [ -n "${_INSTALL_BOOTSTRAP_STAGE:-}" ]; then
        if [ -n "${_INSTALL_BOOTSTRAP_STAGE_ID:-}" ]; then
            if ! fs_ops safe-rmtree-id "$_INSTALL_BOOTSTRAP_STAGE" "$_INSTALL_BOOTSTRAP_STAGE_ID"; then
                warn "leaving staging directory '$_INSTALL_BOOTSTRAP_STAGE' for manual inspection because its identity or backing volume changed"
            fi
        else
            warn "leaving staging directory '$_INSTALL_BOOTSTRAP_STAGE' for manual inspection (missing captured identity)"
        fi
        _INSTALL_BOOTSTRAP_STAGE=""
        _INSTALL_BOOTSTRAP_STAGE_ID=""
    fi
    if [ -n "${_INSTALL_BOOTSTRAP_TARBALL:-}" ]; then
        rm -f "$_INSTALL_BOOTSTRAP_TARBALL"
        _INSTALL_BOOTSTRAP_TARBALL=""
    fi
    if [ "${_INSTALL_REINSTALL_ROLLBACK:-0}" -eq 1 ]; then
        _INSTALL_REINSTALL_ROLLBACK=0
        _rollback_runner_package_tx \
            "$_INSTALL_REINSTALL_RECORD_PATH" \
            "$_INSTALL_REINSTALL_VOL" \
            "$_INSTALL_REINSTALL_BACKUP_DIR" \
            "$_INSTALL_REINSTALL_BACKUP_ID" \
            "$_INSTALL_REINSTALL_WORK_CHILD" \
            "$_INSTALL_REINSTALL_WAS_ACTIVE"
        _INSTALL_REINSTALL_BACKUP_DIR=""
        _INSTALL_REINSTALL_BACKUP_ID=""
    elif [ "${_INSTALL_REINSTALL_COMMITTED:-0}" -eq 0 ] && [ -n "${_INSTALL_REINSTALL_BACKUP_DIR:-}" ]; then
        if [ -n "${_INSTALL_REINSTALL_BACKUP_ID:-}" ]; then
            if ! fs_ops safe-rmtree-id "$_INSTALL_REINSTALL_BACKUP_DIR" "$_INSTALL_REINSTALL_BACKUP_ID"; then
                warn "leaving uncommitted reinstall backup directory '$_INSTALL_REINSTALL_BACKUP_DIR' for manual inspection because its identity or backing volume changed"
            fi
        else
            warn "leaving uncommitted reinstall backup directory '$_INSTALL_REINSTALL_BACKUP_DIR' for manual inspection (missing captured identity)"
        fi
        _INSTALL_REINSTALL_BACKUP_DIR=""
        _INSTALL_REINSTALL_BACKUP_ID=""
    fi
    if [ -n "${_INSTALL_BOOTSTRAP_UNIT:-}" ]; then
        rm -f "$_INSTALL_BOOTSTRAP_UNIT"
        _INSTALL_BOOTSTRAP_UNIT=""
    fi
    if [ -n "${_INSTALL_BOOTSTRAP_DIR:-}" ]; then
        rmdir -- "$_INSTALL_BOOTSTRAP_DIR" 2>/dev/null || true
        _INSTALL_BOOTSTRAP_DIR=""
    fi
    if [ -n "${_INSTALL_BOOTSTRAP_USER:-}" ]; then
        if userdel "$_INSTALL_BOOTSTRAP_USER"; then
            if getent group "$_INSTALL_BOOTSTRAP_USER" >/dev/null 2>&1; then
                groupdel "$_INSTALL_BOOTSTRAP_USER" 2>/dev/null || true
            fi
            _INSTALL_BOOTSTRAP_USER=""
        else
            local surv_uid surv_gid
            surv_uid="$(id -u "$_INSTALL_BOOTSTRAP_USER" 2>/dev/null || echo unknown)"
            surv_gid="$(id -g "$_INSTALL_BOOTSTRAP_USER" 2>/dev/null || echo unknown)"
            warn "bootstrap rollback failed: could not delete newly created service user '${_INSTALL_BOOTSTRAP_USER}' (uid=${surv_uid}, gid=${surv_gid}); preserving recovery record '${_INSTALL_BOOTSTRAP_PENDING_REC:-${_INSTALL_BOOTSTRAP_CFG}/install.env}' — once the host issue is resolved, run: sudo $0 uninstall --config-dir '${_INSTALL_BOOTSTRAP_CFG}' --purge-user"
            # Preserve the durable user-pending record and config dir for recovery!
            _INSTALL_BOOTSTRAP_PENDING_REC=""
            _INSTALL_BOOTSTRAP_CFG=""
            _INSTALL_BOOTSTRAP_USER=""
            return 0
        fi
    fi
    if [ -n "${_INSTALL_BOOTSTRAP_PENDING_REC:-}" ]; then
        rm -f "$_INSTALL_BOOTSTRAP_PENDING_REC"
        _INSTALL_BOOTSTRAP_PENDING_REC=""
    fi
    if [ -n "${_INSTALL_BOOTSTRAP_CFG:-}" ]; then
        rmdir -- "$_INSTALL_BOOTSTRAP_CFG" 2>/dev/null || true
        _INSTALL_BOOTSTRAP_CFG=""
    fi
}

ensure_service_user() {
    say "configuring dedicated locked service user ${OPT_USER}"
    getent group kvm >/dev/null 2>&1 || die "group 'kvm' does not exist (is KVM enabled on this host?)"

    if id "$OPT_USER" >/dev/null 2>&1; then
        if [ "$HAS_INSTALL_RECORD" -ne 1 ] && [ "$HAS_USER_RECORD" -ne 1 ]; then
            die "account '$OPT_USER' already exists with no installation record at $OPT_CONFIG_DIR/install.env; refusing to adopt or modify a pre-existing account (pass --user <new-name>)"
        fi
        if [ "$REC_STATE" = "user-pending" ]; then
            verify_pending_user_safety install
        else
            verify_recorded_user_identity install
        fi
        local uid gid pgroup groups g
        uid="$(id -u "$OPT_USER")"
        gid="$(id -g "$OPT_USER")"
        pgroup="$(id -gn "$OPT_USER")"
        [ "$uid" -ne 0 ] || die "existing user $OPT_USER has uid 0"
        [ "$pgroup" = "$OPT_USER" ] || die "user '$OPT_USER' primary group '$pgroup' does not match '$OPT_USER'; refusing to reuse"
        groups="$(id -nG "$OPT_USER")"
        for g in $groups; do
            if [ "$g" != "$OPT_USER" ] && [ "$g" != "kvm" ]; then
                die "existing user $OPT_USER belongs to unexpected group '$g' (only '$OPT_USER' and 'kvm' are permitted); refusing to reuse"
            fi
        done
        usermod -s /usr/sbin/nologin -G kvm "$OPT_USER"
        MANAGED_USER_UID="$uid"
        MANAGED_USER_GID="$gid"
        MANAGED_USER_CREATED="${REC_USER_CREATED:-1}"
    else
        [ -n "${MANAGED_INSTALL_ID:-}" ] || MANAGED_INSTALL_ID="$(generate_install_id)"
        useradd --system --user-group \
            --comment "qeminga-runner-${MANAGED_INSTALL_ID}" \
            --home-dir "$OPT_STATE_DIR" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$OPT_USER"
        _INSTALL_BOOTSTRAP_USER="$OPT_USER"
        passwd -l "$OPT_USER" >/dev/null 2>&1 || true
        usermod -G kvm "$OPT_USER"
        MANAGED_USER_UID="$(id -u "$OPT_USER")"
        MANAGED_USER_GID="$(id -g "$OPT_USER")"
        MANAGED_USER_CREATED="1"
    fi
}

# Atomically create a fresh top-level managed directory (mode 0700 root:root)
# via `mkdir` without `-p`, failing on EEXIST so a concurrent creation after
# preflight can never be adopted or mutated.
reserve_fresh_dir() {
    local label="$1" dir="$2"
    check_abs_path "${label} directory" "$dir"
    if is_reserved_system_dir "$dir"; then
        die "refusing shared system directory '$dir' as a managed runner directory"
    fi
    [ ! -L "$dir" ] || die "refusing symlinked ${label} directory: $dir"
    check_trusted_parent_dir "$dir"
    local parent
    parent="$(dirname "$dir")"
    if [ ! -e "$parent" ]; then
        install -d -m 0755 -o root -g root "$parent"
        check_trusted_parent_dir "$dir"
    fi
    (
        umask 0077
        mkdir -- "$dir"
    ) || die "refusing to adopt existing unmanaged ${label} directory '$dir' (already exists)"
}

# Acquire or validate one of the four top-level managed directories:
#   claim_managed_dir <label> <owned_var> <dir> <mode> <owner> <group> <runner_name>
#
# - When <owned_var> is 0 (unowned), claims <dir> exclusively via
#   reserve_fresh_dir (atomic EEXIST refusal) leaving any foreign directory's
#   ownership, mode, and contents untouched.
# - Sets <owned_var>=1, records the backing volume fingerprint (VOL_*), and
#   persists install.env (state=installing, or preserving state=updating during
#   transactional reinstall) BEFORE adjusting permissions or initializing any
#   child files/subdirectories, so an interruption leaves <dir> recorded as
#   owned and recoverable by ordinary retry or uninstall.
# - When <owned_var> is 1 (already owned per verified install.env or reserved
#   earlier in this invocation), verifies the backing volume (refusing an absent
#   path without a recorded volume or on a mismatched/unmounted volume), validates
#   <dir> as a non-symlink directory under trusted root-owned ancestors, and
#   applies owner/group/mode.
claim_managed_dir() {
    local label="$1" owned_var="$2" dir="$3" mode="$4" owner="$5" group="$6" runner_name="$7"
    local is_owned=0
    case "$owned_var" in
        OWNED_CONFIG_DIR) is_owned="$OWNED_CONFIG_DIR" ;;
        OWNED_STATE_DIR) is_owned="$OWNED_STATE_DIR" ;;
        OWNED_INSTALL_DIR) is_owned="$OWNED_INSTALL_DIR" ;;
        OWNED_HOOK_DIR) is_owned="$OWNED_HOOK_DIR" ;;
        *) die "internal error: unknown ownership flag '$owned_var'" ;;
    esac

    check_abs_path "${label} directory" "$dir"
    if is_reserved_system_dir "$dir"; then
        die "refusing shared system directory '$dir' as a managed runner directory"
    fi
    [ ! -L "$dir" ] || die "refusing symlinked ${label} directory: $dir"
    check_trusted_parent_dir "$dir"

    local vol_id=""
    if [ "$is_owned" -ne 1 ]; then
        reserve_fresh_dir "$label" "$dir"
        _INSTALL_BOOTSTRAP_DIR="$dir"
        case "$owned_var" in
            OWNED_CONFIG_DIR)
                OWNED_CONFIG_DIR=1
                REC_OWNED_CONFIG_DIR=1
                ;;
            OWNED_STATE_DIR)
                OWNED_STATE_DIR=1
                REC_OWNED_STATE_DIR=1
                VOL_STATE_DIR="$(fs_ops volume-id "$dir")"
                REC_VOL_STATE_DIR="$VOL_STATE_DIR"
                ;;
            OWNED_INSTALL_DIR)
                OWNED_INSTALL_DIR=1
                REC_OWNED_INSTALL_DIR=1
                VOL_INSTALL_DIR="$(fs_ops volume-id "$dir")"
                REC_VOL_INSTALL_DIR="$VOL_INSTALL_DIR"
                ;;
            OWNED_HOOK_DIR)
                OWNED_HOOK_DIR=1
                REC_OWNED_HOOK_DIR=1
                VOL_HOOK_DIR="$(fs_ops volume-id "$dir")"
                REC_VOL_HOOK_DIR="$VOL_HOOK_DIR"
                ;;
        esac
        if [ "${_INSTALL_REINSTALL_TX:-0}" -eq 1 ]; then
            write_update_record "$_INSTALL_REINSTALL_RECORD_PATH" "updating" "publishing" \
                "$_INSTALL_BOOTSTRAP_STAGE" "$_INSTALL_BOOTSTRAP_STAGE_ID" \
                "$_INSTALL_REINSTALL_BACKUP_DIR" "$_INSTALL_REINSTALL_BACKUP_ID" \
                "$_INSTALL_REINSTALL_WAS_ACTIVE"
        else
            write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installing"
        fi
        _INSTALL_BOOTSTRAP_DIR=""
        if [ "$owned_var" = "OWNED_CONFIG_DIR" ]; then
            _INSTALL_BOOTSTRAP_USER=""
            _INSTALL_BOOTSTRAP_PENDING_REC=""
            _INSTALL_BOOTSTRAP_CFG=""
        fi
    else
        if [ "$owned_var" != "OWNED_CONFIG_DIR" ]; then
            local expected_vol=""
            case "$owned_var" in
                OWNED_STATE_DIR) expected_vol="$VOL_STATE_DIR" ;;
                OWNED_INSTALL_DIR) expected_vol="$VOL_INSTALL_DIR" ;;
                OWNED_HOOK_DIR) expected_vol="$VOL_HOOK_DIR" ;;
            esac
            fs_ops verify-volume "$dir" "$expected_vol" \
                || die "refusing to modify or recreate owned ${label} directory '$dir': recorded backing volume is unavailable, mismatched, or unrecorded for an absent path"
        fi
        if [ -e "$dir" ]; then
            [ -d "$dir" ] || die "${label} path '$dir' exists and is not a directory"
        else
            reserve_fresh_dir "$label" "$dir"
        fi
        local need_vol_write=0
        case "$owned_var" in
            OWNED_STATE_DIR)
                if [ -z "$VOL_STATE_DIR" ]; then
                    vol_id="$(fs_ops volume-id "$dir")"
                    VOL_STATE_DIR="$vol_id"
                    REC_VOL_STATE_DIR="$vol_id"
                    need_vol_write=1
                fi
                ;;
            OWNED_INSTALL_DIR)
                if [ -z "$VOL_INSTALL_DIR" ]; then
                    vol_id="$(fs_ops volume-id "$dir")"
                    VOL_INSTALL_DIR="$vol_id"
                    REC_VOL_INSTALL_DIR="$vol_id"
                    need_vol_write=1
                fi
                ;;
            OWNED_HOOK_DIR)
                if [ -z "$VOL_HOOK_DIR" ]; then
                    vol_id="$(fs_ops volume-id "$dir")"
                    VOL_HOOK_DIR="$vol_id"
                    REC_VOL_HOOK_DIR="$vol_id"
                    need_vol_write=1
                fi
                ;;
        esac
        if [ "${_INSTALL_REINSTALL_TX:-0}" -eq 1 ]; then
            if [ "$need_vol_write" -eq 1 ]; then
                write_update_record "$_INSTALL_REINSTALL_RECORD_PATH" "updating" "publishing" \
                    "$_INSTALL_BOOTSTRAP_STAGE" "$_INSTALL_BOOTSTRAP_STAGE_ID" \
                    "$_INSTALL_REINSTALL_BACKUP_DIR" "$_INSTALL_REINSTALL_BACKUP_ID" \
                    "$_INSTALL_REINSTALL_WAS_ACTIVE"
            fi
        elif [ "$owned_var" = "OWNED_CONFIG_DIR" ]; then
            write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installing"
            _INSTALL_BOOTSTRAP_USER=""
            _INSTALL_BOOTSTRAP_PENDING_REC=""
            _INSTALL_BOOTSTRAP_CFG=""
        elif [ "$need_vol_write" -eq 1 ]; then
            write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installing"
        fi
    fi

    [ ! -L "$dir" ] || die "refusing symlinked ${label} directory: $dir"
    chown -h "${owner}:${group}" "$dir"
    chmod "$mode" "$dir"
}

# Initialize runtime state subdirectories strictly as OPT_USER (after the
# top-level state root has already been exclusively claimed and persisted as
# OWNED_STATE_DIR=1) so a runner-planted symlink can never redirect root
# ownership or chmod changes and a runuser/quota failure stays recoverable.
init_state_subdirs() {
    [ ! -L "$OPT_STATE_DIR" ] || die "refusing symlinked state directory: $OPT_STATE_DIR"
    check_trusted_parent_dir "$OPT_STATE_DIR"
    [ -d "$OPT_STATE_DIR" ] || die "state directory '$OPT_STATE_DIR' does not exist"
    command -v runuser >/dev/null 2>&1 || die "runuser (util-linux) is required to provision state subdirectories as $OPT_USER"
    runuser -u "$OPT_USER" -- mkdir -p -m 0700 \
        "$OPT_STATE_DIR/work" \
        "$OPT_STATE_DIR/images" \
        "$OPT_STATE_DIR/image-cache" \
        "$OPT_STATE_DIR/.config" \
        "$OPT_STATE_DIR/.cache" \
        "$OPT_STATE_DIR/.local" \
        "$OPT_STATE_DIR/.local/share" 9>&-
}

lock_runner_permissions() {
    [ ! -L "$OPT_INSTALL_DIR" ] || die "refusing symlinked runner directory: $OPT_INSTALL_DIR"
    [ -d "$OPT_INSTALL_DIR" ] || die "runner directory does not exist: $OPT_INSTALL_DIR"
    local expected_vol="${VOL_INSTALL_DIR:-${REC_VOL_INSTALL_DIR:-}}"
    local skip_children
    skip_children="$(runner_workspace_skip_list "$OPT_INSTALL_DIR" "${RESOLVED_WORK_DIR:-${REC_WORK_DIR:-}}")"
    if [ "$OPT_ALLOW_AUTO_UPDATE" -eq 1 ]; then
        safe_chown_runner_dir "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR" "$expected_vol" "$skip_children"
    else
        safe_chown_runner_dir root:root "$OPT_INSTALL_DIR" "$expected_vol" "$skip_children"
        chmod 0755 "$OPT_INSTALL_DIR"

        local user_uid user_gid
        user_uid="${REC_USER_UID:-${MANAGED_USER_UID:-$(id -u "$OPT_USER")}}"
        user_gid="${REC_USER_GID:-${MANAGED_USER_GID:-$(id -g "$OPT_USER")}}"

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
                fs_ops safe-chown-file "$p" "$user_uid" "$user_gid" 0600 "$expected_vol" \
                    || die "refusing unsafe runner file '$p'"
                if [ "$(/usr/bin/id -u)" -ne 0 ]; then
                    chown -h "${OPT_USER}:${OPT_USER}" "$p"
                fi
            fi
        done

        # Keep .env root-owned and read-only so jobs cannot inject hooks or env vars.
        local env_file="$OPT_INSTALL_DIR/.env"
        [ ! -L "$env_file" ] || die "refusing symlinked runner env file: $env_file"
        if [ -e "$env_file" ]; then
            [ -f "$env_file" ] || die "refusing non-regular runner env file: $env_file"
            fs_ops safe-chown-file "$env_file" 0 "$user_gid" 0640 "$expected_vol" \
                || die "refusing unsafe runner env file '$env_file'"
            if [ "$(/usr/bin/id -u)" -ne 0 ]; then
                chown -h "root:${OPT_USER}" "$env_file"
            fi
        else
            install -m 0640 -o root -g "$OPT_USER" /dev/null "$env_file"
        fi

        local bin_dir="$OPT_INSTALL_DIR/bin"
        local runsvc="$bin_dir/runsvc.sh"
        [ ! -L "$bin_dir" ] || die "refusing symlinked runner bin directory: $bin_dir"
        [ ! -L "$runsvc" ] || die "refusing symlinked runner launcher: $runsvc"
        if [ -f "$runsvc" ]; then
            fs_ops safe-chown-file "$runsvc" 0 0 0755 "$expected_vol" \
                || die "refusing unsafe runner launcher '$runsvc'"
        fi

        # Ephemeral/JIT mode needs the runner user to create/remove .runner/.credentials*
        # (and validated JIT _work) while bin/, externals/, scripts, and .env stay ReadOnlyPaths.
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
            "$OPT_INSTALL_DIR/config.sh" "$@" 9>&-
    )
}

# Inspect any existing .runner registration BEFORE stopping the live service or
# mutating files. Prints "configure" when no .runner exists, prints "reuse"
# when an existing registration matches the requested target and settings, and
# dies immediately when an existing registration is incompatible.
check_existing_registration() {
    local want_url="$1" want_name="$2"
    local runner_file="$OPT_INSTALL_DIR/.runner"
    [ ! -L "$runner_file" ] || die "refusing symlinked runner file: $runner_file"
    if [ ! -e "$runner_file" ]; then
        echo "configure"
        return 0
    fi
    [ -f "$runner_file" ] || die "refusing non-regular runner file: $runner_file"
    if [ -n "$OPT_JITCONFIG_FILE" ]; then
        die "existing persistent registration found at $runner_file; run 'sudo $0 uninstall --token-file ...' before provisioning a JIT runner"
    fi
    command -v jq >/dev/null 2>&1 || die "jq is required to inspect existing runner registration"
    local json got_url got_name got_work got_disable_update got_ephemeral
    json="$(sed '1s/^\xef\xbb\xbf//' "$runner_file")"
    got_url="$(printf '%s' "$json" | jq -er '.gitHubUrl // empty' 2>/dev/null)" \
        || die "existing $runner_file is malformed (missing gitHubUrl); uninstall before reinstalling"
    got_name="$(printf '%s' "$json" | jq -er '.agentName // empty' 2>/dev/null)" \
        || die "existing $runner_file is malformed (missing agentName); uninstall before reinstalling"
    got_work="$(printf '%s' "$json" | jq -er '.workFolder // empty' 2>/dev/null)" \
        || die "existing $runner_file is malformed (missing workFolder); uninstall before reinstalling"
    got_disable_update="$(printf '%s' "$json" | jq -er 'if has("disableUpdate") then (if (.disableUpdate | type) == "boolean" then (if .disableUpdate then "1" else "0" end) else error("bad type") end) else "0" end' 2>/dev/null)" \
        || die "existing $runner_file is malformed (invalid disableUpdate); uninstall before reinstalling"
    got_ephemeral="$(printf '%s' "$json" | jq -er 'if has("ephemeral") then (if (.ephemeral | type) == "boolean" then (if .ephemeral then "1" else "0" end) else error("bad type") end) else "0" end' 2>/dev/null)" \
        || die "existing $runner_file is malformed (invalid ephemeral); uninstall before reinstalling"

    local norm_got="${got_url%/}" norm_want="${want_url%/}"
    local want_work="${OPT_STATE_DIR}/work"
    local want_disable_update=1
    [ "$OPT_ALLOW_AUTO_UPDATE" -eq 1 ] && want_disable_update=0
    if [ "${norm_got,,}" != "${norm_want,,}" ]; then
        die "existing registration in $runner_file targets '$got_url', not '$want_url'; run 'sudo $0 uninstall --token-file ...' first"
    fi
    if [ "$got_name" != "$want_name" ]; then
        die "existing registration in $runner_file has runner name '$got_name', not '$want_name'; run 'sudo $0 uninstall --token-file ...' first"
    fi
    if [ "$got_work" != "$want_work" ]; then
        die "existing registration in $runner_file uses work folder '$got_work', not '$want_work'; run 'sudo $0 uninstall --token-file ...' first"
    fi
    if [ "$got_disable_update" != "$want_disable_update" ]; then
        die "existing registration in $runner_file has disableUpdate=$got_disable_update (incompatible with --allow-auto-update=$OPT_ALLOW_AUTO_UPDATE); run 'sudo $0 uninstall --token-file ...' first"
    fi
    if [ "$got_ephemeral" != "$OPT_EPHEMERAL" ]; then
        die "existing registration in $runner_file has ephemeral=$got_ephemeral (incompatible with --ephemeral=$OPT_EPHEMERAL); run 'sudo $0 uninstall --token-file ...' first"
    fi
    if [ "$HAS_INSTALL_RECORD" -eq 1 ]; then
        local norm_rec="${REC_TARGET_URL%/}"
        if [ -n "$norm_rec" ] && [ "${norm_rec,,}" != "${norm_want,,}" ]; then
            die "existing installation record targets '$REC_TARGET_URL', not '$want_url'; run 'sudo $0 uninstall --token-file ...' first"
        fi
        if [ -n "$REC_RUNNER_NAME" ] && [ "$REC_RUNNER_NAME" != "$want_name" ]; then
            die "existing installation record has runner name '$REC_RUNNER_NAME', not '$want_name'; run 'sudo $0 uninstall --token-file ...' first"
        fi
        if [ -n "$REC_WORK_DIR" ] && [ "$REC_WORK_DIR" != "$want_work" ]; then
            die "existing installation record uses work dir '$REC_WORK_DIR', not '$want_work'; run 'sudo $0 uninstall --token-file ...' first"
        fi
        if [ "$REC_LABELS" != "$OPT_LABELS" ] \
            || [ "$REC_RUNNER_GROUP" != "$OPT_RUNNER_GROUP" ] \
            || [ "$REC_EPHEMERAL" != "$OPT_EPHEMERAL" ] \
            || [ "$REC_ALLOW_AUTO_UPDATE" != "$OPT_ALLOW_AUTO_UPDATE" ]; then
            die "existing registration in $OPT_INSTALL_DIR differs in labels/runner-group/ephemeral/auto-update policy; run 'sudo $0 uninstall --token-file ...' first"
        fi
    fi
    echo "reuse"
}

register_runner_with_rollback() {
    local was_active="$1" token="$2"
    shift 2
    local skip_children
    skip_children="$(runner_workspace_skip_list "$OPT_INSTALL_DIR" "${RESOLVED_WORK_DIR:-${REC_WORK_DIR:-}}")"
    safe_chown_runner_dir "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR" "${VOL_INSTALL_DIR:-}" "$skip_children"
    local rc=0
    if run_runner_config_with_token "$token" "$@"; then
        return 0
    else
        rc=$?
    fi
    warn "runner registration failed (exit $rc); restoring locked runner permissions"
    lock_runner_permissions || true
    if [ "$was_active" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
        warn "restarting previously active ${OPT_SERVICE}.service"
        systemctl start "${OPT_SERVICE}.service" || true
    fi
    return "$rc"
}

# ---- install --------------------------------------------------------------

cmd_install() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "install must run as root (e.g. sudo $0 install ...)"
    check_service_lock_disjoint
    resolve_target_registration install
    if [ -n "$OPT_TOKEN_FILE" ] && [ -n "$OPT_JITCONFIG_FILE" ]; then
        die "--token-file and --jitconfig-file are mutually exclusive"
    fi

    local host_arch arch
    host_arch="$(normalize_arch "$(uname -m)")"
    arch="${OPT_ARCH:-$host_arch}"
    [ "$arch" = "$host_arch" ] || die "--arch $arch does not match host architecture $host_arch"

    local kvm_dev="${QEMINGA_KVM_DEVICE:-/dev/kvm}"
    [ -c "$kvm_dev" ] || die "KVM device $kvm_dev does not exist; refusing to register a non-KVM host as a KVM runner"

    local cg_ctrls="${QEMINGA_CGROUP_CONTROLLERS:-/sys/fs/cgroup/cgroup.controllers}"
    [ -r "$cg_ctrls" ] || die "cgroup v2 unified hierarchy missing ($cg_ctrls); required for systemd IPAddressDeny= BPF firewall"

    # Serialize overlapping lifecycle operations targeting the same OPT_CONFIG_DIR
    # BEFORE reading install.env or inspecting/mutating live state.
    acquire_install_lock

    # Load and validate existing installation record (if reinstalling, recovering
    # from an interrupted install, or reusing a managed user retained after
    # uninstall/failed bootstrap rollback) BEFORE mutating any live state.
    OWNED_CONFIG_DIR=0
    OWNED_STATE_DIR=0
    OWNED_INSTALL_DIR=0
    OWNED_HOOK_DIR=0
    OWNED_UNIT=0
    MANAGED_INSTALL_ID=""
    VOL_UNIT=""
    VOL_INSTALL_DIR=""
    VOL_HOOK_DIR=""
    VOL_STATE_DIR=""
    local unit_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    unit_dir="${unit_dir%/}"
    check_abs_path "systemd unit dir" "$unit_dir"
    local unit_path="${unit_dir}/${OPT_SERVICE}.service"

    local rec_path="$OPT_CONFIG_DIR/install.env"
    if [ -e "$rec_path" ] || [ -L "$rec_path" ]; then
        read_install_record "$rec_path"
        [ "$REC_USER" = "$OPT_USER" ] || die "existing record at $rec_path is for user '$REC_USER', not '$OPT_USER'"
        [ "$REC_CONFIG_DIR" = "$OPT_CONFIG_DIR" ] || die "existing record at $rec_path manages config dir '$REC_CONFIG_DIR', not '$OPT_CONFIG_DIR'"
        MANAGED_INSTALL_ID="${REC_INSTALL_ID:-}"
        if [ "$REC_STATE" = "user-only" ] || [ "$REC_STATE" = "user-pending" ]; then
            verify_recorded_user_identity install
            OWNED_CONFIG_DIR=1
            fs_ops check-no-mounts "$OPT_CONFIG_DIR" \
                || die "refusing reinstall: owned config directory '$OPT_CONFIG_DIR' contains an active mount or bind mount"
            check_dedicated_managed_dirs 2
            check_unit_not_occupied
        elif [ "$REC_STATE" = "partial-uninstall" ]; then
            die "existing installation at $rec_path is in partial-uninstall state (stray VM state or pending removal preserved); finish 'sudo $0 uninstall --config-dir $OPT_CONFIG_DIR' before reinstalling"
        elif [ "$REC_STATE" = "updating" ]; then
            die "existing installation at $rec_path has an interrupted update in progress; finish 'sudo $0 update --config-dir $OPT_CONFIG_DIR' or run 'sudo $0 uninstall --config-dir $OPT_CONFIG_DIR' before reinstalling"
        else
            [ "$REC_SERVICE" = "$OPT_SERVICE" ] || die "existing record at $rec_path is for service '$REC_SERVICE', not '$OPT_SERVICE'"
            [ "$REC_INSTALL_DIR" = "$OPT_INSTALL_DIR" ] || die "existing record at $rec_path manages install dir '$REC_INSTALL_DIR', not '$OPT_INSTALL_DIR'"
            [ "$REC_STATE_DIR" = "$OPT_STATE_DIR" ] || die "existing record at $rec_path manages state dir '$REC_STATE_DIR', not '$OPT_STATE_DIR'"
            [ "$REC_HOOK_DIR" = "$OPT_HOOK_DIR" ] || die "existing record at $rec_path manages hook dir '$REC_HOOK_DIR', not '$OPT_HOOK_DIR'"
            OWNED_CONFIG_DIR="$REC_OWNED_CONFIG_DIR"
            OWNED_STATE_DIR="$REC_OWNED_STATE_DIR"
            OWNED_INSTALL_DIR="$REC_OWNED_INSTALL_DIR"
            OWNED_HOOK_DIR="$REC_OWNED_HOOK_DIR"
            OWNED_UNIT="$REC_OWNED_UNIT"
            VOL_UNIT="${REC_VOL_UNIT:-}"
            VOL_INSTALL_DIR="${REC_VOL_INSTALL_DIR:-}"
            VOL_HOOK_DIR="${REC_VOL_HOOK_DIR:-}"
            VOL_STATE_DIR="${REC_VOL_STATE_DIR:-}"
            verify_recorded_user_identity install
            check_dedicated_managed_dirs record
            if [ "$OWNED_CONFIG_DIR" -eq 1 ] && [ -e "$OPT_CONFIG_DIR" ]; then
                fs_ops check-no-mounts "$OPT_CONFIG_DIR" \
                    || die "refusing reinstall: owned config directory '$OPT_CONFIG_DIR' contains an active mount or bind mount"
            fi
            if [ "$OWNED_STATE_DIR" -eq 1 ]; then
                fs_ops verify-volume "$OPT_STATE_DIR" "$VOL_STATE_DIR" \
                    || die "refusing reinstall: owned state directory '$OPT_STATE_DIR' backing volume is unavailable, mismatched, or unrecorded for an absent path"
            fi
            if [ "$OWNED_INSTALL_DIR" -eq 1 ]; then
                fs_ops verify-volume "$OPT_INSTALL_DIR" "$VOL_INSTALL_DIR" \
                    || die "refusing reinstall: owned runner directory '$OPT_INSTALL_DIR' backing volume is unavailable, mismatched, or unrecorded for an absent path"
                if [ -e "$OPT_INSTALL_DIR" ]; then
                    fs_ops check-no-mounts "$OPT_INSTALL_DIR" \
                        || die "refusing reinstall: owned runner directory '$OPT_INSTALL_DIR' contains an active mount or bind mount"
                fi
            fi
            if [ "$OWNED_HOOK_DIR" -eq 1 ]; then
                fs_ops verify-volume "$OPT_HOOK_DIR" "$VOL_HOOK_DIR" \
                    || die "refusing reinstall: owned hook directory '$OPT_HOOK_DIR' backing volume is unavailable, mismatched, or unrecorded for an absent path"
                if [ -e "$OPT_HOOK_DIR" ]; then
                    fs_ops check-no-mounts "$OPT_HOOK_DIR" \
                        || die "refusing reinstall: owned hook directory '$OPT_HOOK_DIR' contains an active mount or bind mount"
                fi
            fi
            if [ "$OWNED_UNIT" -eq 1 ]; then
                fs_ops verify-volume "$unit_path" "$VOL_UNIT" \
                    || die "refusing reinstall: owned systemd unit '$unit_path' backing volume is unavailable, mismatched, or unrecorded for an absent path"
                if [ -e "$unit_path" ]; then
                    fs_ops check-no-mounts "$unit_path" \
                        || die "refusing reinstall: owned systemd unit '$unit_path' is a mount or bind mount"
                fi
            else
                check_unit_not_occupied
            fi
        fi
    else
        check_dedicated_managed_dirs 0
        check_unit_not_occupied
        MANAGED_INSTALL_ID="$(generate_install_id)"
    fi

    local runner_name
    if [ -n "$OPT_NAME" ]; then
        runner_name="$OPT_NAME"
    else
        local host_short
        host_short="$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-32)"
        runner_name="qeminga-kvm-${arch}-${host_short:-host}"
    fi
    check_runner_name "$runner_name"

    # Detect existing registration compatibility BEFORE installing packages or stopping
    # the live runner (only when we actually own OPT_INSTALL_DIR).
    local reg_mode="configure"
    if [ "$OWNED_INSTALL_DIR" -eq 1 ]; then
        reg_mode="$(check_existing_registration "$TARGET_URL" "$runner_name")"
    fi

    # Read credentials early (before installing packages) without requiring jq yet;
    # JIT blob decoding/validation runs right after install_packages so a fresh
    # donor without jq can bootstrap in one command.
    local reg_token="" jit_config=""
    if [ -n "$OPT_JITCONFIG_FILE" ]; then
        jit_config="$(read_secret_file --jitconfig-file "$OPT_JITCONFIG_FILE")"
    elif [ "$reg_mode" = "reuse" ]; then
        say "reusing existing matching runner registration in ${OPT_INSTALL_DIR}"
    elif [ -n "$OPT_TOKEN_FILE" ]; then
        reg_token="$(read_secret_file --token-file "$OPT_TOKEN_FILE")"
    elif [ -n "${QEMINGA_RUNNER_TOKEN:-}" ]; then
        reg_token="$QEMINGA_RUNNER_TOKEN"
        unset QEMINGA_RUNNER_TOKEN
    elif [ -t 0 ]; then
        printf 'GitHub runner registration token for %s (input hidden): ' "$TARGET_URL" >&2
        IFS= read -r -s reg_token
        printf '\n' >&2
        [ -n "$reg_token" ] || die "registration token cannot be empty"
    else
        die "provide a registration token via --token-file PATH (mode 0600), --token-file - (stdin), --jitconfig-file PATH, QEMINGA_RUNNER_TOKEN, or an interactive terminal"
    fi

    if [ "$OPT_SKIP_PACKAGES" -eq 0 ]; then
        install_packages "$arch"
    fi

    # Decode and validate JIT config AFTER install_packages provides jq (and
    # BEFORE creating any user account or mutating directories).
    if [ -n "$jit_config" ]; then
        RESOLVED_WORK_DIR="$(resolve_jit_work_dir "$jit_config" "$TARGET_URL")"
    fi
    finalize_policy_defaults

    # Verify private repository visibility for --repo targets (after curl/jq are installed).
    if [ -n "$OPT_REPO" ]; then
        verify_private_repo "$ALLOWED_REPO_SLUG"
    fi

    if [ "$arch" = "aarch64" ]; then
        find_aavmf >/dev/null || die "missing AArch64 UEFI firmware (install qemu-efi-aarch64 or edk2-aarch64)"
    fi

    # Detect whether we are reinstalling an existing owned `installed` runner
    # whose runner directory already exists on disk: in that case validate and
    # stage the replacement bundle BEFORE stopping the live service or mutating
    # install.env, and share `update`'s recoverable transactional replacement.
    local is_reinstall_installed=0
    if [ "$HAS_INSTALL_RECORD" -eq 1 ] && [ "$REC_STATE" = "installed" ] \
        && [ "$OWNED_CONFIG_DIR" -eq 1 ] && [ "$OWNED_INSTALL_DIR" -eq 1 ] \
        && [ -d "$OPT_INSTALL_DIR" ]; then
        is_reinstall_installed=1
    fi

    _INSTALL_BOOTSTRAP_CFG=""
    _INSTALL_BOOTSTRAP_PENDING_REC=""
    _INSTALL_BOOTSTRAP_DIR=""
    _INSTALL_BOOTSTRAP_UNIT=""
    _INSTALL_BOOTSTRAP_USER=""
    _INSTALL_BOOTSTRAP_TARBALL=""
    _INSTALL_BOOTSTRAP_STAGE=""
    _INSTALL_BOOTSTRAP_STAGE_ID=""
    _INSTALL_REINSTALL_TX=0
    _INSTALL_REINSTALL_ROLLBACK=0
    _INSTALL_REINSTALL_COMMITTED=0
    _INSTALL_REINSTALL_BACKUP_DIR=""
    _INSTALL_REINSTALL_BACKUP_ID=""
    _INSTALL_REINSTALL_WAS_ACTIVE=0
    _INSTALL_REINSTALL_WORK_CHILD=""
    _INSTALL_REINSTALL_VOL=""
    _INSTALL_REINSTALL_RECORD_PATH=""
    trap 'cleanup_install_exit' EXIT

    local was_active=0
    local tarball stage_dir stage_id backup_dir="" backup_id="" work_child run_deps=0 fetch_args=()
    [ "$OPT_SKIP_PACKAGES" -eq 0 ] && run_deps=1

    if [ "$is_reinstall_installed" -eq 1 ]; then
        local reinstall_install_vol="${VOL_INSTALL_DIR:-}"
        if [ -z "$reinstall_install_vol" ]; then
            reinstall_install_vol="$(fs_ops volume-id "$OPT_INSTALL_DIR")"
        fi
        tarball="$(mktemp /tmp/qeminga-actions-runner.XXXXXX.tar.gz)"
        _INSTALL_BOOTSTRAP_TARBALL="$tarball"
        fetch_args=(--arch "$arch" --dest "$tarball" --version "$OPT_RUNNER_VERSION")
        if [ -n "$OPT_RUNNER_SHA256" ]; then fetch_args+=(--sha256 "$OPT_RUNNER_SHA256"); fi
        if [ -n "$OPT_URL" ]; then fetch_args+=(--url "$OPT_URL"); fi
        cmd_fetch_runner "${fetch_args[@]}"

        # Re-verify runner directory invariants after network download and
        # stage/validate the replacement bundle BEFORE stopping the live
        # service or changing install.env out of `installed`.
        [ ! -L "$OPT_INSTALL_DIR" ] || die "refusing symlinked runner directory: $OPT_INSTALL_DIR"
        [ -d "$OPT_INSTALL_DIR" ] || die "runner directory $OPT_INSTALL_DIR no longer exists after download"
        fs_ops verify-volume "$OPT_INSTALL_DIR" "$reinstall_install_vol" \
            || die "refusing reinstall: owned runner directory '$OPT_INSTALL_DIR' backing volume changed during download"
        fs_ops check-no-mounts "$OPT_INSTALL_DIR" \
            || die "refusing reinstall: owned runner directory '$OPT_INSTALL_DIR' contains an active mount or bind mount"

        stage_dir="$(umask 0077 && mktemp -d "$(dirname "$OPT_INSTALL_DIR")/.qeminga-extract.XXXXXX")" \
            || die "failed to create private staging directory beside '$OPT_INSTALL_DIR'"
        _INSTALL_BOOTSTRAP_STAGE="$stage_dir"
        stage_id="$(fs_ops path-identity "$stage_dir")" \
            || die "failed to record staging directory identity for '$stage_dir'"
        _INSTALL_BOOTSTRAP_STAGE_ID="$stage_id"
        chown -h root:root "$stage_dir"
        chmod 0700 "$stage_dir"
        work_child="$(runner_workspace_child_name "$OPT_INSTALL_DIR" "${RESOLVED_WORK_DIR:-${REC_WORK_DIR:-}}")"
        fs_ops stage-runner-archive "$OPT_INSTALL_DIR" "$reinstall_install_vol" "$tarball" "$stage_dir" "$stage_id" "$run_deps" "$work_child" \
            || die "failed to stage, validate, and prepare verified actions/runner archive beside '$OPT_INSTALL_DIR'"
        rm -f "$tarball"
        _INSTALL_BOOTSTRAP_TARBALL=""

        if [ "$OWNED_UNIT" -eq 1 ] && systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
            was_active=1
        fi

        # Create a private 0700 sibling backup container and persist the
        # recoverable `updating` (`publishing`) transaction BEFORE stopping
        # the live service or mutating any live files.
        backup_dir="$(umask 0077 && mktemp -d "$(dirname "$OPT_INSTALL_DIR")/.qeminga-update-backup.XXXXXX")" \
            || die "failed to create private reinstall backup directory beside '$OPT_INSTALL_DIR'"
        backup_id="$(fs_ops path-identity "$backup_dir")" \
            || die "failed to record reinstall backup directory identity for '$backup_dir'"
        chown -h root:root "$backup_dir"
        chmod 0700 "$backup_dir"
        _INSTALL_REINSTALL_TX=1
        _INSTALL_REINSTALL_BACKUP_DIR="$backup_dir"
        _INSTALL_REINSTALL_BACKUP_ID="$backup_id"
        _INSTALL_REINSTALL_WAS_ACTIVE="$was_active"
        _INSTALL_REINSTALL_WORK_CHILD="$work_child"
        _INSTALL_REINSTALL_VOL="$reinstall_install_vol"
        _INSTALL_REINSTALL_RECORD_PATH="$OPT_CONFIG_DIR/install.env"
        REC_VOL_INSTALL_DIR="${REC_VOL_INSTALL_DIR:-$reinstall_install_vol}"
        VOL_INSTALL_DIR="$reinstall_install_vol"
        write_update_record "$_INSTALL_REINSTALL_RECORD_PATH" "updating" "publishing" "$stage_dir" "$stage_id" "$backup_dir" "$backup_id" "$was_active"
        _INSTALL_REINSTALL_ROLLBACK=1

        if [ "$was_active" -eq 1 ]; then
            say "stopping existing ${OPT_SERVICE}.service"
            systemctl stop "${OPT_SERVICE}.service" 9>&-
        fi

        ensure_service_user
        claim_managed_dir config OWNED_CONFIG_DIR "$OPT_CONFIG_DIR" 0750 root "$OPT_USER" "$runner_name"
        claim_managed_dir state OWNED_STATE_DIR "$OPT_STATE_DIR" 0700 "$OPT_USER" "$OPT_USER" "$runner_name"
        init_state_subdirs
        claim_managed_dir runner OWNED_INSTALL_DIR "$OPT_INSTALL_DIR" 0755 root root "$runner_name"

        local pub_rc=0
        fs_ops publish-runner-stage "$OPT_INSTALL_DIR" "$reinstall_install_vol" "$stage_dir" "$stage_id" "$backup_dir" "$backup_id" "$work_child" || pub_rc=$?
        if [ "$pub_rc" -ne 0 ]; then
            if [ "$pub_rc" -eq 99 ] && [ -n "${QEMINGA_TEST_CRASH_PUBLISH_AFTER:-}" ]; then
                trap - EXIT
                exit 99
            fi
            die "failed to publish staged actions/runner archive into '$OPT_INSTALL_DIR'"
        fi
        _INSTALL_BOOTSTRAP_STAGE=""
        _INSTALL_BOOTSTRAP_STAGE_ID=""
    else
        # Stop existing managed service ONLY when this installation owns that unit.
        if [ "$OWNED_UNIT" -eq 1 ] && systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
            was_active=1
            say "stopping existing ${OPT_SERVICE}.service"
            systemctl stop "${OPT_SERVICE}.service" 9>&-
        fi

        # Reserve a fresh config directory exclusively as root and write a durable
        # pre-useradd user-pending record (with unique INSTALL_ID) BEFORE creating
        # the service account so:
        # - a concurrent config-dir collision fails without creating a user;
        # - useradd stamps qeminga-runner-<INSTALL_ID> into the account GECOS so
        #   recovery can distinguish accounts created by this install from unrelated ones;
        # - if post-useradd install.env update fails and userdel succeeds, both the
        #   user and reserved config dir are cleanly rolled back;
        # - if BOTH post-useradd install.env update AND rollback userdel fail (e.g.
        #   full /etc), the durable user-pending record stays intact so the operator
        #   can recover with `uninstall --purge-user` or retry `install`.
        if [ "$OWNED_CONFIG_DIR" -ne 1 ]; then
            reserve_fresh_dir config "$OPT_CONFIG_DIR"
            _INSTALL_BOOTSTRAP_CFG="$OPT_CONFIG_DIR"
            write_user_pending_record "$OPT_CONFIG_DIR/install.env" "$OPT_USER" "$OPT_CONFIG_DIR" "$MANAGED_INSTALL_ID"
            _INSTALL_BOOTSTRAP_PENDING_REC="$OPT_CONFIG_DIR/install.env"
            OWNED_CONFIG_DIR=1
        fi

        ensure_service_user

        # Establish install.env (disarming bootstrap rollback) and claim each
        # remaining top-level directory exclusively (atomic EEXIST refusal) before
        # adjusting permissions or initializing contents so any interruption stays
        # recoverable and never adopts a directory created after preflight.
        claim_managed_dir config OWNED_CONFIG_DIR "$OPT_CONFIG_DIR" 0750 root "$OPT_USER" "$runner_name"
        claim_managed_dir state OWNED_STATE_DIR "$OPT_STATE_DIR" 0700 "$OPT_USER" "$OPT_USER" "$runner_name"
        init_state_subdirs

        # Download, SHA-256 verify, and extract actions/runner into a private 0700
        # root-owned sibling staging directory so installdependencies.sh executes
        # strictly from verified root-private content before publishing into the
        # volume-verified runner directory.
        tarball="$(mktemp /tmp/qeminga-actions-runner.XXXXXX.tar.gz)"
        _INSTALL_BOOTSTRAP_TARBALL="$tarball"
        fetch_args=(--arch "$arch" --dest "$tarball" --version "$OPT_RUNNER_VERSION")
        if [ -n "$OPT_RUNNER_SHA256" ]; then fetch_args+=(--sha256 "$OPT_RUNNER_SHA256"); fi
        if [ -n "$OPT_URL" ]; then fetch_args+=(--url "$OPT_URL"); fi
        cmd_fetch_runner "${fetch_args[@]}"

        claim_managed_dir runner OWNED_INSTALL_DIR "$OPT_INSTALL_DIR" 0755 root root "$runner_name"
        stage_dir="$(umask 0077 && mktemp -d "$(dirname "$OPT_INSTALL_DIR")/.qeminga-extract.XXXXXX")" \
            || die "failed to create private staging directory beside '$OPT_INSTALL_DIR'"
        _INSTALL_BOOTSTRAP_STAGE="$stage_dir"
        stage_id="$(fs_ops path-identity "$stage_dir")" \
            || die "failed to record staging directory identity for '$stage_dir'"
        _INSTALL_BOOTSTRAP_STAGE_ID="$stage_id"
        chown -h root:root "$stage_dir"
        chmod 0700 "$stage_dir"
        work_child="$(runner_workspace_child_name "$OPT_INSTALL_DIR" "${RESOLVED_WORK_DIR:-${REC_WORK_DIR:-}}")"
        fs_ops install-runner-archive "$OPT_INSTALL_DIR" "$VOL_INSTALL_DIR" "$tarball" "$stage_dir" "$stage_id" "$run_deps" "$work_child" \
            || die "failed to stage, configure dependencies, and publish verified actions/runner archive into '$OPT_INSTALL_DIR'"
        rm -f "$tarball"
        _INSTALL_BOOTSTRAP_TARBALL=""
        _INSTALL_BOOTSTRAP_STAGE=""
        _INSTALL_BOOTSTRAP_STAGE_ID=""
    fi

    # Install root-owned hooks, egress firewall gate, main-process launcher, and policy.
    say "installing root-owned job guard, egress check, launcher, and cleanup hooks"
    claim_managed_dir hook OWNED_HOOK_DIR "$OPT_HOOK_DIR" 0755 root root "$runner_name"
    write_policy_file "$OPT_CONFIG_DIR/policy.env" "$ALLOWED_REPO_SLUG" 0640 root "$OPT_USER"
    write_job_started_hook "$OPT_HOOK_DIR/hook-job-started.sh" root root
    write_job_completed_hook "$OPT_HOOK_DIR/hook-job-completed.sh" root root
    write_egress_firewall_check "$OPT_HOOK_DIR/check-egress-firewall.sh" root root

    local launcher_name="run-runner.sh"
    if [ -n "$jit_config" ]; then
        launcher_name="run-jit.sh"
        say "installing one-shot JIT config credential (workspace: ${RESOLVED_WORK_DIR})"
        fs_ops safe-rmtree "$OPT_HOOK_DIR/run-runner.sh"
        write_jit_launcher "$OPT_HOOK_DIR/run-jit.sh" root root
        publish_managed_file_cmd "$OPT_CONFIG_DIR/jitconfig" 0600 root root printf '%s\n' "$jit_config"
        unset jit_config
    else
        fs_ops safe-rmtree "$OPT_HOOK_DIR/run-jit.sh"
        write_runner_launcher "$OPT_HOOK_DIR/run-runner.sh" root root
        if [ "$reg_mode" = "configure" ]; then
            command -v runuser >/dev/null 2>&1 || die "runuser (util-linux) is required to register the runner as $OPT_USER"
            say "registering runner '${runner_name}' (${arch}, labels=${OPT_LABELS}) against ${TARGET_URL}"
            local cfg_args=(
                --unattended
                --replace
                --url "$TARGET_URL"
                --name "$runner_name"
                --labels "$OPT_LABELS"
                --work "$RESOLVED_WORK_DIR"
            )
            [ -n "$OPT_RUNNER_GROUP" ] && cfg_args+=(--runnergroup "$OPT_RUNNER_GROUP")
            [ "$OPT_ALLOW_AUTO_UPDATE" -eq 0 ] && cfg_args+=(--disableupdate)
            [ "$OPT_EPHEMERAL" -eq 1 ] && cfg_args+=(--ephemeral)

            local reg_was_active="$was_active"
            [ "$is_reinstall_installed" -eq 1 ] && reg_was_active=0
            if ! register_runner_with_rollback "$reg_was_active" "$reg_token" "${cfg_args[@]}"; then
                unset reg_token
                die "runner registration failed"
            fi
            unset reg_token
        fi
    fi

    lock_runner_permissions

    # Install and verify the hardened systemd unit. Stage the complete unit and
    # set its owner/mode on a temporary regular file in the trusted unit dir,
    # then publish a fresh unit via hard link (`ln -T`, i.e. link(2) with exact
    # destination semantics), which fails atomically with EEXIST on ANY existing
    # directory entry — including a systemd mask symlink to /dev/null or a
    # directory — without following symlinks, linking into a directory, or
    # altering target permissions. Record OWNED_UNIT=1 only after publication.
    check_trusted_parent_dir "$unit_path"
    [ ! -L "$unit_path" ] || die "refusing symlinked systemd unit path: $unit_path"
    if [ "$OWNED_UNIT" -ne 1 ]; then
        check_unit_not_occupied
    fi
    if [ ! -e "$unit_dir" ]; then
        install -d -m 0755 -o root -g root "$unit_dir"
        check_trusted_parent_dir "$unit_path"
    fi
    say "installing hardened systemd unit ${unit_path}"
    local tmp_unit
    tmp_unit="$(umask 0077 && mktemp "${unit_dir}/.${OPT_SERVICE}.service.XXXXXX")"
    if ! render_unit_text "$arch" | awk 'NF || prev_nf { print } { prev_nf = NF }' >"$tmp_unit" \
        || ! chown -h root:root "$tmp_unit" \
        || ! chmod 0644 "$tmp_unit"; then
        rm -f "$tmp_unit"
        die "failed to stage hardened systemd unit in '$unit_dir'"
    fi
    if [ "$OWNED_UNIT" -ne 1 ]; then
        if ! ln -T -- "$tmp_unit" "$unit_path" 2>/dev/null; then
            rm -f "$tmp_unit"
            die "refusing to overwrite unexpected existing systemd unit '$unit_path'"
        fi
        rm -f "$tmp_unit"
        _INSTALL_BOOTSTRAP_UNIT="$unit_path"
        OWNED_UNIT=1
        VOL_UNIT="$(fs_ops volume-id "$unit_path")"
        if [ "$is_reinstall_installed" -eq 1 ]; then
            REC_OWNED_UNIT=1
            REC_VOL_UNIT="$VOL_UNIT"
            write_update_record "$_INSTALL_REINSTALL_RECORD_PATH" "updating" "publishing" "" "" "$backup_dir" "$backup_id" "$was_active"
        else
            write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installing"
        fi
        _INSTALL_BOOTSTRAP_UNIT=""
    else
        if ! fs_ops verify-volume "$unit_path" "$VOL_UNIT"; then
            rm -f "$tmp_unit"
            die "refusing to replace owned systemd unit '$unit_path': recorded backing volume is unavailable, mismatched, or unrecorded for an absent path"
        fi
        if ! fs_ops replace-file "$tmp_unit" "$unit_path"; then
            rm -f "$tmp_unit"
            die "failed to update owned systemd unit '$unit_path'"
        fi
        if [ -z "$VOL_UNIT" ]; then
            VOL_UNIT="$(fs_ops volume-id "$unit_path")"
        fi
    fi

    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze verify --man=no "$unit_path" || die "systemd-analyze verify failed for $unit_path"
    fi

    systemctl daemon-reload 9>&-
    if [ "$OPT_NO_START" -eq 0 ]; then
        # Because the unit uses Type=notify (NotifyAccess=main), systemctl waits
        # until the launcher passes check-egress-firewall.sh and sends READY=1
        # (or exits non-zero immediately if the firewall gate rejects the host).
        if [ "$OPT_EPHEMERAL" -eq 1 ]; then
            systemctl start "${OPT_SERVICE}.service" 9>&-
            say "${OPT_SERVICE}.service started and passed egress firewall gate (ephemeral one-shot; not enabled across reboot)"
        else
            systemctl enable --now "${OPT_SERVICE}.service" 9>&-
            say "${OPT_SERVICE}.service is enabled, started, and passed egress firewall gate"
        fi
    else
        say "--no-start set; inspect ${unit_path}, then run: sudo systemctl enable --now ${OPT_SERVICE}.service"
    fi

    # Finalize installation record state only after unit verification & startup
    # readiness (unless --no-start) succeed. For transactional reinstall, record
    # `UPDATE_PHASE=committed` BEFORE pruning the backup container so an
    # interruption mid-prune never triggers rollback of the committed runner.
    if [ "$is_reinstall_installed" -eq 1 ]; then
        write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "updating" "committed" "" "" "$backup_dir" "$backup_id" "$was_active"
        _INSTALL_REINSTALL_ROLLBACK=0
        _INSTALL_REINSTALL_COMMITTED=1
        fs_ops safe-rmtree-id "$backup_dir" "$backup_id" \
            || die "failed to remove verified reinstall backup directory '$backup_dir' (leaving committed updating record for inspection)"
        _INSTALL_REINSTALL_BACKUP_DIR=""
        _INSTALL_REINSTALL_BACKUP_ID=""
    fi
    write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installed"
    trap - EXIT

    echo
    echo "qeminga KVM runner installed:"
    echo "  service:     ${OPT_SERVICE}.service"
    echo "  target:      ${TARGET_URL}${OPT_RUNNER_GROUP:+ (runner-group: ${OPT_RUNNER_GROUP})}"
    echo "  user:        ${OPT_USER} (uid=${MANAGED_USER_UID}, supplementary group: kvm only)"
    echo "  arch:        ${arch} (GitHub labels: self-hosted, linux, $(gh_runner_arch_of "$arch"), ${OPT_LABELS})"
    echo "  libvirt:     qemu:///session (unprivileged, isolated from host system VMs)"
    echo "  workspace:   ${RESOLVED_WORK_DIR}"
    echo "  policy:      ${OPT_CONFIG_DIR}/policy.env"
    echo "  record:      ${OPT_CONFIG_DIR}/install.env"
    echo "  hooks:       ${OPT_HOOK_DIR}/{hook-job-started,hook-job-completed,check-egress-firewall,${launcher_name%.sh}}.sh"
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
    local unit_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    if command -v systemd-analyze >/dev/null 2>&1 && [ -f "${unit_dir%/}/${OPT_SERVICE}.service" ]; then
        echo "-- systemd security exposure:"
        systemd-analyze security --no-pager "${OPT_SERVICE}.service" | tail -n 5 || true
    fi
}

# ---- update ---------------------------------------------------------------

_UPDATE_TMP_TARBALL=""
_UPDATE_TMP_STAGE=""
_UPDATE_TMP_STAGE_ID=""
_UPDATE_BACKUP_DIR=""
_UPDATE_BACKUP_ID=""
_UPDATE_RECORD_PATH=""
_UPDATE_ROLLBACK_ACTIVE=0
_UPDATE_COMMITTED=0
_UPDATE_WAS_ACTIVE=0
_UPDATE_WORK_CHILD=""

cleanup_update_exit() {
    if [ -n "${_UPDATE_TMP_STAGE:-}" ]; then
        if [ -n "${_UPDATE_TMP_STAGE_ID:-}" ]; then
            if ! fs_ops safe-rmtree-id "$_UPDATE_TMP_STAGE" "$_UPDATE_TMP_STAGE_ID"; then
                warn "leaving update staging directory '$_UPDATE_TMP_STAGE' for manual inspection because its identity or backing volume changed"
            fi
        else
            warn "leaving update staging directory '$_UPDATE_TMP_STAGE' for manual inspection (missing captured identity)"
        fi
        _UPDATE_TMP_STAGE=""
        _UPDATE_TMP_STAGE_ID=""
    fi
    if [ -n "${_UPDATE_TMP_TARBALL:-}" ]; then
        rm -f "$_UPDATE_TMP_TARBALL"
        _UPDATE_TMP_TARBALL=""
    fi
    if [ "${_UPDATE_ROLLBACK_ACTIVE:-0}" -eq 1 ]; then
        _UPDATE_ROLLBACK_ACTIVE=0
        _rollback_runner_package_tx \
            "$_UPDATE_RECORD_PATH" \
            "$REC_VOL_INSTALL_DIR" \
            "$_UPDATE_BACKUP_DIR" \
            "$_UPDATE_BACKUP_ID" \
            "$_UPDATE_WORK_CHILD" \
            "$_UPDATE_WAS_ACTIVE"
        _UPDATE_BACKUP_DIR=""
        _UPDATE_BACKUP_ID=""
    elif [ "${_UPDATE_COMMITTED:-0}" -eq 0 ] && [ -n "${_UPDATE_BACKUP_DIR:-}" ]; then
        if [ -n "${_UPDATE_BACKUP_ID:-}" ]; then
            if ! fs_ops safe-rmtree-id "$_UPDATE_BACKUP_DIR" "$_UPDATE_BACKUP_ID"; then
                warn "leaving uncommitted update backup directory '$_UPDATE_BACKUP_DIR' for manual inspection because its identity or backing volume changed"
            fi
        else
            warn "leaving uncommitted update backup directory '$_UPDATE_BACKUP_DIR' for manual inspection (missing captured identity)"
        fi
        _UPDATE_BACKUP_DIR=""
        _UPDATE_BACKUP_ID=""
    fi
}

cmd_update() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "update must run as root"
    acquire_install_lock

    # Refuse to modify any service or directory without a valid root-owned
    # installation record matching CLI options and live user UID/GID/marker.
    load_and_verify_install_record update

    [ ! -L "$OPT_INSTALL_DIR" ] || die "refusing symlinked runner directory: $OPT_INSTALL_DIR"
    [ -d "$OPT_INSTALL_DIR" ] || die "runner directory $OPT_INSTALL_DIR does not exist"
    [ -n "${REC_VOL_INSTALL_DIR:-}" ] \
        || die "update: installation record '$OPT_CONFIG_DIR/install.env' is missing VOL_INSTALL_DIR; verify the runner directory and run 'sudo $0 migrate-record --config-dir $OPT_CONFIG_DIR --confirm-volumes' before updating"
    verify_resource_volume install "runner directory" "$OPT_INSTALL_DIR"
    fs_ops check-no-mounts "$OPT_INSTALL_DIR" \
        || die "refusing to update runner directory '$OPT_INSTALL_DIR' containing an active mount or bind mount"
    local unit_dir="" unit_path=""
    if [ "$REC_OWNED_UNIT" = "1" ]; then
        unit_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
        unit_dir="${unit_dir%/}"
        check_abs_path "systemd unit dir" "$unit_dir"
        unit_path="${unit_dir}/${OPT_SERVICE}.service"
        [ -n "${REC_VOL_UNIT:-}" ] \
            || die "update: installation record '$OPT_CONFIG_DIR/install.env' is missing VOL_UNIT; verify the systemd unit and run 'sudo $0 migrate-record --config-dir $OPT_CONFIG_DIR --confirm-volumes' before updating"
        verify_resource_volume unit "systemd unit" "$unit_path"
    fi

    local work_child=""
    RESOLVED_WORK_DIR="${REC_WORK_DIR:-}"
    if [ -n "$RESOLVED_WORK_DIR" ]; then
        work_child="$(runner_workspace_child_name "$OPT_INSTALL_DIR" "$RESOLVED_WORK_DIR")"
    fi

    _UPDATE_TMP_TARBALL=""
    _UPDATE_TMP_STAGE=""
    _UPDATE_TMP_STAGE_ID=""
    _UPDATE_BACKUP_DIR=""
    _UPDATE_BACKUP_ID=""
    _UPDATE_RECORD_PATH="$OPT_CONFIG_DIR/install.env"
    _UPDATE_ROLLBACK_ACTIVE=0
    _UPDATE_COMMITTED=0
    _UPDATE_WAS_ACTIVE=0
    _UPDATE_WORK_CHILD="$work_child"
    trap 'cleanup_update_exit' EXIT

    # Recover any previously interrupted update BEFORE fetching or staging a
    # new archive according to UPDATE_PHASE:
    # - committed: previous replacement already succeeded; finish pruning the
    #   backup container without rolling back and return to `installed`.
    # - publishing: reclaim any recorded stage dir, restore the previous runner
    #   from the verified backup container (refusing missing/swapped backup),
    #   record `UPDATE_PHASE=restored` immediately once backup is consumed,
    #   re-lock permissions, and preserve original `UPDATE_WAS_ACTIVE`.
    # - restored: backup already consumed; ensure permissions are locked and
    #   preserve original `UPDATE_WAS_ACTIVE` across the retry.
    local was_active=0
    if [ "$REC_STATE" = "updating" ]; then
        if [ "$REC_UPDATE_PHASE" = "committed" ]; then
            if [ -n "$REC_UPDATE_STAGE_DIR" ]; then
                validate_update_stage_path "$OPT_INSTALL_DIR" "$REC_UPDATE_STAGE_DIR"
                fs_ops safe-rmtree-id "$REC_UPDATE_STAGE_DIR" "$REC_UPDATE_STAGE_ID" \
                    || die "update: failed to reclaim leftover stage '$REC_UPDATE_STAGE_DIR' after committed update; preserving updating record for inspection"
                REC_UPDATE_STAGE_DIR=""
                REC_UPDATE_STAGE_ID=""
            fi
            validate_update_backup_path "$OPT_INSTALL_DIR" "$REC_UPDATE_BACKUP_DIR"
            say "finishing backup cleanup for committed update (${REC_UPDATE_BACKUP_DIR})"
            fs_ops safe-rmtree-id "$REC_UPDATE_BACKUP_DIR" "$REC_UPDATE_BACKUP_ID" \
                || die "update: failed to prune committed update backup '$REC_UPDATE_BACKUP_DIR'; preserving updating record for inspection"
            REC_UPDATE_BACKUP_DIR=""
            REC_UPDATE_BACKUP_ID=""
            REC_UPDATE_PHASE=""
            REC_STATE="installed"
            write_update_record "$_UPDATE_RECORD_PATH" "installed"
        elif [ "$REC_UPDATE_PHASE" = "publishing" ]; then
            was_active="$REC_UPDATE_WAS_ACTIVE"
            _UPDATE_WAS_ACTIVE="$was_active"
            if [ -n "$REC_UPDATE_STAGE_DIR" ]; then
                validate_update_stage_path "$OPT_INSTALL_DIR" "$REC_UPDATE_STAGE_DIR"
                say "reclaiming leftover stage directory from interrupted update (${REC_UPDATE_STAGE_DIR})"
                fs_ops safe-rmtree-id "$REC_UPDATE_STAGE_DIR" "$REC_UPDATE_STAGE_ID" \
                    || die "update: failed to reclaim interrupted update stage '$REC_UPDATE_STAGE_DIR'; preserving updating record for inspection"
                REC_UPDATE_STAGE_DIR=""
                REC_UPDATE_STAGE_ID=""
            fi
            validate_update_backup_path "$OPT_INSTALL_DIR" "$REC_UPDATE_BACKUP_DIR"
            say "recovering previous runner from interrupted update backup ${REC_UPDATE_BACKUP_DIR}"
            fs_ops restore-runner-backup "$OPT_INSTALL_DIR" "$REC_VOL_INSTALL_DIR" "$REC_UPDATE_BACKUP_DIR" "$REC_UPDATE_BACKUP_ID" "$work_child" "0" \
                || die "update: failed to restore previous runner from '$REC_UPDATE_BACKUP_DIR'; preserving updating record for retry"
            REC_UPDATE_BACKUP_DIR=""
            REC_UPDATE_BACKUP_ID=""
            REC_UPDATE_PHASE="restored"
            write_update_record "$_UPDATE_RECORD_PATH" "updating" "restored" "" "" "" "" "$was_active"
            lock_runner_permissions
            _UPDATE_ROLLBACK_ACTIVE=1
        else
            was_active="$REC_UPDATE_WAS_ACTIVE"
            _UPDATE_WAS_ACTIVE="$was_active"
            lock_runner_permissions
            _UPDATE_ROLLBACK_ACTIVE=1
        fi
    fi

    local arch
    arch="$(normalize_arch "$(uname -m)")"

    local tarball stage_dir stage_id backup_dir backup_id fetch_args=()
    tarball="$(mktemp /tmp/qeminga-actions-runner-update.XXXXXX.tar.gz)"
    _UPDATE_TMP_TARBALL="$tarball"
    fetch_args=(--arch "$arch" --dest "$tarball" --version "$OPT_RUNNER_VERSION")
    if [ -n "$OPT_RUNNER_SHA256" ]; then fetch_args+=(--sha256 "$OPT_RUNNER_SHA256"); fi
    if [ -n "$OPT_URL" ]; then fetch_args+=(--url "$OPT_URL"); fi
    cmd_fetch_runner "${fetch_args[@]}"

    # Re-verify backing volume and mount invariants AFTER the network download
    # and BEFORE staging or stopping the live service so an unmount/swap during
    # download fails closed without touching the service or an underlying tree.
    [ ! -L "$OPT_INSTALL_DIR" ] || die "refusing symlinked runner directory: $OPT_INSTALL_DIR"
    [ -d "$OPT_INSTALL_DIR" ] || die "runner directory $OPT_INSTALL_DIR no longer exists after download"
    verify_resource_volume install "runner directory" "$OPT_INSTALL_DIR"
    fs_ops check-no-mounts "$OPT_INSTALL_DIR" \
        || die "refusing to update runner directory '$OPT_INSTALL_DIR' containing an active mount or bind mount"
    if [ "$REC_OWNED_UNIT" = "1" ]; then
        verify_resource_volume unit "systemd unit" "$unit_path"
    fi

    # Extract, sanitize, and validate the verified archive in a private 0700
    # root-owned sibling staging directory BEFORE stopping the live service.
    stage_dir="$(umask 0077 && mktemp -d "$(dirname "$OPT_INSTALL_DIR")/.qeminga-extract.XXXXXX")" \
        || die "failed to create private staging directory beside '$OPT_INSTALL_DIR'"
    _UPDATE_TMP_STAGE="$stage_dir"
    stage_id="$(fs_ops path-identity "$stage_dir")" \
        || die "failed to record update staging directory identity for '$stage_dir'"
    _UPDATE_TMP_STAGE_ID="$stage_id"
    chown -h root:root "$stage_dir"
    chmod 0700 "$stage_dir"
    fs_ops stage-runner-archive "$OPT_INSTALL_DIR" "$REC_VOL_INSTALL_DIR" "$tarball" "$stage_dir" "$stage_id" "0" "$work_child" \
        || die "refusing runner update staging beside '$OPT_INSTALL_DIR' (volume changed, mount boundary, invalid bundle, or extraction error)"
    rm -f "$tarball"
    _UPDATE_TMP_TARBALL=""

    if [ "$REC_STATE" != "updating" ]; then
        was_active=0
        if systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
            was_active=1
        fi
        _UPDATE_WAS_ACTIVE="$was_active"
    fi

    # Create a private 0700 sibling backup container on the same verified
    # volume and durably record `RECORD_STATE=updating`, `UPDATE_PHASE=publishing`,
    # verified stage+backup paths/identities, and `UPDATE_WAS_ACTIVE` BEFORE
    # stopping the service or displacing live runner entries.
    backup_dir="$(umask 0077 && mktemp -d "$(dirname "$OPT_INSTALL_DIR")/.qeminga-update-backup.XXXXXX")" \
        || die "failed to create private update backup directory beside '$OPT_INSTALL_DIR'"
    backup_id="$(fs_ops path-identity "$backup_dir")" \
        || die "failed to record update backup directory identity for '$backup_dir'"
    _UPDATE_BACKUP_DIR="$backup_dir"
    _UPDATE_BACKUP_ID="$backup_id"
    chown -h root:root "$backup_dir"
    chmod 0700 "$backup_dir"
    write_update_record "$_UPDATE_RECORD_PATH" "updating" "publishing" "$stage_dir" "$stage_id" "$backup_dir" "$backup_id" "$was_active"
    _UPDATE_ROLLBACK_ACTIVE=1

    if systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
        say "stopping ${OPT_SERVICE}.service"
        systemctl stop "${OPT_SERVICE}.service" 9>&-
    fi

    local pub_rc=0
    fs_ops publish-runner-stage "$OPT_INSTALL_DIR" "$REC_VOL_INSTALL_DIR" "$stage_dir" "$stage_id" "$backup_dir" "$backup_id" "$work_child" || pub_rc=$?
    if [ "$pub_rc" -ne 0 ]; then
        if [ "$pub_rc" -eq 99 ] && [ -n "${QEMINGA_TEST_CRASH_PUBLISH_AFTER:-}" ]; then
            trap - EXIT
            exit 99
        fi
        die "refusing runner update publish into '$OPT_INSTALL_DIR' (volume changed, mount boundary, or unsafe destination)"
    fi
    _UPDATE_TMP_STAGE=""
    _UPDATE_TMP_STAGE_ID=""

    lock_runner_permissions

    # Keep the complete backup container intact through service activation so a
    # startup failure on the replacement rolls back to the previous runner and
    # restarts it. Record `UPDATE_PHASE=committed` BEFORE pruning the backup so
    # an interruption mid-prune finishes cleanup without rolling back.
    if [ "$was_active" -eq 1 ] && [ "$OPT_NO_START" -eq 0 ]; then
        say "restarting ${OPT_SERVICE}.service"
        systemctl start "${OPT_SERVICE}.service" 9>&-
    fi

    write_update_record "$_UPDATE_RECORD_PATH" "updating" "committed" "" "" "$backup_dir" "$backup_id" "$was_active"
    _UPDATE_ROLLBACK_ACTIVE=0
    _UPDATE_COMMITTED=1

    fs_ops safe-rmtree-id "$backup_dir" "$backup_id" \
        || die "failed to remove verified update backup directory '$backup_dir' (leaving committed updating record for inspection)"
    _UPDATE_BACKUP_DIR=""
    _UPDATE_BACKUP_ID=""

    write_update_record "$_UPDATE_RECORD_PATH" "installed"
    trap - EXIT
    echo "updated actions/runner in ${OPT_INSTALL_DIR} to v${OPT_RUNNER_VERSION} (${arch})"
}

# ---- migrate-record -------------------------------------------------------

# Verify and upgrade one resource slot's recorded volume fingerprint during
# `migrate-record --confirm-volumes`. Mirrors `reconcile_staged_entry`: when a
# partial-uninstall record has already moved the managed payload into a private
# STAGED_* directory (even if interrupted before persisting OWNED_*=0), verify
# the staged container instead of the vacated/potentially-replaced public path;
# if a released slot's staging directory was already deleted before clearing
# STAGED_*, verify its legacy fingerprint against the trusted parent directory.
migrate_slot_volume() {
    local label="$1" public_path="$2" owned_val="$3" staged_dir="$4" old_vol="$5"
    if [ "$REC_STATE" = "partial-uninstall" ] && [ -n "$staged_dir" ]; then
        validate_staged_path "$label" "$public_path" "$staged_dir"
        if [ ! -e "$staged_dir" ] && [ ! -L "$staged_dir" ]; then
            if [ "$owned_val" != "1" ]; then
                fs_ops verify-legacy-volume-absent "$staged_dir" "$old_vol" \
                    || die "migrate-record: refusing to upgrade absent staged ${label} volume for '$staged_dir'"
                return 0
            fi
        else
            local payload
            payload="${staged_dir}/$(basename "$public_path")"
            if [ -e "$payload" ] || [ -L "$payload" ] || [ "$owned_val" != "1" ]; then
                fs_ops verify-legacy-volume "$staged_dir" "$old_vol" \
                    || die "migrate-record: refusing to upgrade staged ${label} volume for '$staged_dir'"
                return 0
            fi
        fi
    fi
    if [ "$owned_val" = "1" ]; then
        check_trusted_parent_dir "$public_path"
        fs_ops verify-legacy-volume "$public_path" "$old_vol" \
            || die "migrate-record: refusing to upgrade ${label} volume for '$public_path'"
        return 0
    fi
    printf '%s' "$old_vol"
}

# Operator-confirmed migration for existing records created by earlier versions
# of setup-kvm-runner.sh:
#   --confirm-volumes: upgrades empty or matching legacy 4-field VOL_* records
#     (mp,root,fs,src without uuid/fsid) to strong persistent UUID/fsid
#     fingerprints after verifying each owned (or staged) path exists with no
#     nested mounts and matches the legacy fields; refreshes STATE_VOL and
#     INSTALL_VOL in policy.env when present. Never overwrites a mismatched
#     strong UUID/fsid.
#   --confirm-account-marker: stamps qeminga-runner-<INSTALL_ID> onto a
#     verified legacy managed account whose numeric UID/GID and groups match
#     install.env and whose complete untrimmed GECOS is empty (refusing
#     user-pending records, failed passwd lookups, and any non-empty GECOS).
cmd_migrate_record() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "migrate-record must run as root"
    if [ "$OPT_CONFIRM_VOLUMES" -eq 0 ] && [ "$OPT_CONFIRM_ACCOUNT_MARKER" -eq 0 ]; then
        die "migrate-record requires explicit operator confirmation: pass --confirm-volumes and/or --confirm-account-marker"
    fi
    acquire_install_lock

    local rec_path="$OPT_CONFIG_DIR/install.env"
    read_install_record "$rec_path"

    if [ "$SET_USER" -eq 1 ] && [ "$OPT_USER" != "$REC_USER" ]; then
        die "migrate-record: --user '$OPT_USER' does not match installation record '$REC_USER'"
    fi
    [ "$OPT_CONFIG_DIR" = "$REC_CONFIG_DIR" ] \
        || die "migrate-record: --config-dir '$OPT_CONFIG_DIR' does not match installation record '$REC_CONFIG_DIR'"
    [ "$REC_STATE" != "user-pending" ] \
        || die "migrate-record: refusing to migrate unverified user-pending record '$rec_path'"

    OPT_USER="$REC_USER"
    OPT_CONFIG_DIR="$REC_CONFIG_DIR"
    check_abs_path "config directory" "$OPT_CONFIG_DIR"
    if is_reserved_system_dir "$OPT_CONFIG_DIR"; then
        die "refusing shared system directory '$OPT_CONFIG_DIR' as a managed runner directory"
    fi
    [ ! -L "$OPT_CONFIG_DIR" ] || die "refusing symlinked managed directory '$OPT_CONFIG_DIR'"
    check_trusted_parent_dir "$OPT_CONFIG_DIR"
    fs_ops check-no-mounts "$OPT_CONFIG_DIR" \
        || die "migrate-record: refusing config directory '$OPT_CONFIG_DIR' containing an active mount or bind mount"

    if [ "$REC_STATE" != "user-only" ]; then
        if [ "$SET_SERVICE" -eq 1 ] && [ "$OPT_SERVICE" != "$REC_SERVICE" ]; then
            die "migrate-record: --service '$OPT_SERVICE' does not match installation record '$REC_SERVICE'"
        fi
        if [ "$SET_INSTALL_DIR" -eq 1 ] && [ "$OPT_INSTALL_DIR" != "$REC_INSTALL_DIR" ]; then
            die "migrate-record: --install-dir '$OPT_INSTALL_DIR' does not match installation record '$REC_INSTALL_DIR'"
        fi
        if [ "$SET_STATE_DIR" -eq 1 ] && [ "$OPT_STATE_DIR" != "$REC_STATE_DIR" ]; then
            die "migrate-record: --state-dir '$OPT_STATE_DIR' does not match installation record '$REC_STATE_DIR'"
        fi
        if [ "$SET_HOOK_DIR" -eq 1 ] && [ "$OPT_HOOK_DIR" != "$REC_HOOK_DIR" ]; then
            die "migrate-record: --hook-dir '$OPT_HOOK_DIR' does not match installation record '$REC_HOOK_DIR'"
        fi
        OPT_SERVICE="$REC_SERVICE"
        OPT_INSTALL_DIR="$REC_INSTALL_DIR"
        OPT_STATE_DIR="$REC_STATE_DIR"
        OPT_HOOK_DIR="$REC_HOOK_DIR"
        local dirs=("$OPT_INSTALL_DIR" "$OPT_STATE_DIR" "$OPT_HOOK_DIR")
        local labels=("runner directory" "state directory" "hook directory")
        local owned=("$REC_OWNED_INSTALL_DIR" "$REC_OWNED_STATE_DIR" "$REC_OWNED_HOOK_DIR")
        local staged=("$REC_STAGED_INSTALL_DIR" "$REC_STAGED_STATE_DIR" "$REC_STAGED_HOOK_DIR")
        local i d
        for i in 0 1 2; do
            d="${dirs[$i]}"
            check_abs_path "managed directory" "$d"
            if is_reserved_system_dir "$d"; then
                die "refusing shared system directory '$d' as a managed runner directory"
            fi
            check_trusted_parent_dir "$d"
            if [ "${owned[$i]}" = "1" ] && ! staged_payload_exists "${labels[$i]}" "$d" "${staged[$i]}"; then
                [ ! -L "$d" ] || die "refusing symlinked managed directory '$d'"
            fi
        done
    elif [ "$OPT_CONFIRM_VOLUMES" -eq 1 ]; then
        die "migrate-record: --confirm-volumes does not apply to user-only record '$rec_path'"
    fi

    # Always verify live numeric UID/GID match before any migration mutation.
    if id "$OPT_USER" >/dev/null 2>&1; then
        local cur_uid cur_gid
        cur_uid="$(id -u "$OPT_USER")"
        cur_gid="$(id -g "$OPT_USER")"
        if [ "$cur_uid" -eq 0 ] || [ "$cur_uid" != "$REC_USER_UID" ] || [ "$cur_gid" != "$REC_USER_GID" ]; then
            die "migrate-record: service user '$OPT_USER' uid:gid (${cur_uid}:${cur_gid}) does not match recorded ${REC_USER_UID}:${REC_USER_GID}; refusing to migrate"
        fi
    elif [ "$OPT_CONFIRM_ACCOUNT_MARKER" -eq 1 ]; then
        die "migrate-record: recorded service user '$OPT_USER' does not exist"
    fi

    # Phase 1: Validate all requested migrations read-only BEFORE mutating anything.
    local need_gecos_stamp=0 expected_marker="" generated_id=0
    if [ "$OPT_CONFIRM_ACCOUNT_MARKER" -eq 1 ]; then
        [ "${REC_USER_CREATED:-0}" = "1" ] \
            || die "migrate-record: refusing --confirm-account-marker because '$OPT_USER' was not created by this installer (USER_CREATED=${REC_USER_CREATED:-0})"
        local pgroup groups g full_gecos primary_gecos
        pgroup="$(id -gn "$OPT_USER")"
        if [ "$pgroup" != "$OPT_USER" ]; then
            die "migrate-record: service user '$OPT_USER' primary group '$pgroup' does not match '$OPT_USER'"
        fi
        groups="$(id -nG "$OPT_USER")"
        for g in $groups; do
            if [ "$g" != "$OPT_USER" ] && [ "$g" != "kvm" ]; then
                die "migrate-record: service user '$OPT_USER' belongs to unexpected group '$g' (only '$OPT_USER' and 'kvm' are permitted)"
            fi
        done
        if [ -z "${REC_INSTALL_ID:-}" ]; then
            REC_INSTALL_ID="$(generate_install_id)"
            generated_id=1
        fi
        expected_marker="qeminga-runner-${REC_INSTALL_ID}"
        if ! full_gecos="$(lookup_passwd_gecos_strict "$OPT_USER" "$REC_USER_UID" "$REC_USER_GID")"; then
            die "migrate-record: failed to look up passwd entry for service user '$OPT_USER' (${REC_USER_UID}:${REC_USER_GID}); refusing to stamp account marker"
        fi
        primary_gecos="${full_gecos%%,*}"
        if [ "$full_gecos" = "$expected_marker" ] || [ "$primary_gecos" = "$expected_marker" ]; then
            need_gecos_stamp=0
        elif [ -n "$full_gecos" ]; then
            die "migrate-record: refusing to overwrite non-empty GECOS '${full_gecos}' on account '$OPT_USER' (expected empty legacy GECOS or '${expected_marker}')"
        else
            command -v usermod >/dev/null 2>&1 || die "usermod is required for --confirm-account-marker"
            need_gecos_stamp=1
        fi
    fi

    local new_vol_unit="$REC_VOL_UNIT"
    local new_vol_install="$REC_VOL_INSTALL_DIR"
    local new_vol_hook="$REC_VOL_HOOK_DIR"
    local new_vol_state="$REC_VOL_STATE_DIR"
    if [ "$OPT_CONFIRM_VOLUMES" -eq 1 ]; then
        local unit_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
        unit_dir="${unit_dir%/}"
        check_abs_path "systemd unit dir" "$unit_dir"
        local unit_path="${unit_dir}/${OPT_SERVICE}.service"

        new_vol_unit="$(migrate_slot_volume "systemd unit" "$unit_path" "$REC_OWNED_UNIT" "$REC_STAGED_UNIT" "$REC_VOL_UNIT")"
        new_vol_install="$(migrate_slot_volume "runner directory" "$OPT_INSTALL_DIR" "$REC_OWNED_INSTALL_DIR" "$REC_STAGED_INSTALL_DIR" "$REC_VOL_INSTALL_DIR")"
        new_vol_hook="$(migrate_slot_volume "hook directory" "$OPT_HOOK_DIR" "$REC_OWNED_HOOK_DIR" "$REC_STAGED_HOOK_DIR" "$REC_VOL_HOOK_DIR")"
        new_vol_state="$(migrate_slot_volume "state directory" "$OPT_STATE_DIR" "$REC_OWNED_STATE_DIR" "$REC_STAGED_STATE_DIR" "$REC_VOL_STATE_DIR")"
    fi

    # Phase 2: All preconditions passed — apply mutations cleanly.
    # Persist any newly generated INSTALL_ID to install.env BEFORE calling
    # usermod so any crash/interruption during or after usermod stays
    # idempotent and retries reuse the exact same installation ID.
    if [ "$generated_id" -eq 1 ]; then
        if [ "$REC_STATE" = "user-only" ]; then
            write_user_only_record "$rec_path" \
                "$REC_USER" "$REC_USER_UID" "$REC_USER_GID" "$REC_USER_CREATED" "$REC_CONFIG_DIR" "$REC_INSTALL_ID"
        else
            write_migrated_record "$rec_path"
        fi
    fi

    if [ "$need_gecos_stamp" -eq 1 ]; then
        usermod -c "$expected_marker" "$OPT_USER" \
            || die "migrate-record: usermod failed to stamp '${expected_marker}' onto '$OPT_USER'"
        verify_user_install_marker migrate-record "service user"
        say "stamped installation marker '${expected_marker}' onto legacy account '$OPT_USER'"
    fi

    if [ "$OPT_CONFIRM_VOLUMES" -eq 1 ]; then
        REC_VOL_UNIT="$new_vol_unit"
        REC_VOL_INSTALL_DIR="$new_vol_install"
        REC_VOL_HOOK_DIR="$new_vol_hook"
        REC_VOL_STATE_DIR="$new_vol_state"
        write_migrated_record "$rec_path"
        update_policy_volumes "$OPT_CONFIG_DIR/policy.env" "$REC_VOL_STATE_DIR" "$REC_VOL_INSTALL_DIR"
        say "upgraded backing volume fingerprints in $rec_path"
    fi
}

# ---- uninstall ------------------------------------------------------------

_UNINSTALL_TEMP_RT=""
_UNINSTALL_TEMP_HOOK_DIR=""
_UNINSTALL_EMPTY_STAGE=""

# Terminate session libvirt daemons (libvirtd / virtqemud / virtlogd /
# virtlockd / etc.) whose PID files live directly under $rt_dir/libvirt so no
# temporary or idle daemon remains running as OPT_USER (which would cause
# `userdel` during --purge-user to fail with "user is currently used by
# process"). PID-file reading and signaling run strictly as OPT_USER so root
# never opens user-writable files and the kernel enforces UID ownership.
# Pass force_kill=1 for a temporary uninstall runtime dir we created ourselves
# so a stuck daemon is killed before removing the directory.
stop_temp_session_libvirt_daemons() {
    local rt_dir="$1"
    local force_kill="${2:-0}"
    [ ! -L "$rt_dir" ] && [ -d "$rt_dir" ] || return 0
    [ ! -L "$rt_dir/libvirt" ] && [ -d "$rt_dir/libvirt" ] || return 0
    runuser -u "$OPT_USER" -- sh -c '
        rt_dir="$1"
        force_kill="$2"
        pids=""
        for pidf in "$rt_dir"/libvirt/libvirtd.pid "$rt_dir"/libvirt/virt*d.pid; do
            [ ! -L "$pidf" ] && [ -f "$pidf" ] && [ -r "$pidf" ] || continue
            pid="$(head -c 32 "$pidf" 2>/dev/null | tr -d "[:space:]")"
            case "$pid" in
                ""|*[!0-9]*|0*) continue ;;
            esac
            [ "$pid" = "$$" ] && continue
            pids="$pids $pid"
        done
        [ -n "$pids" ] || exit 0
        for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            alive=0
            for p in $pids; do
                if kill -0 "$p" 2>/dev/null; then alive=1; break; fi
            done
            [ "$alive" -eq 0 ] && exit 0
            sleep 0.2
        done
        if [ "$force_kill" = "1" ]; then
            for p in $pids; do kill -KILL "$p" 2>/dev/null || true; done
            for _ in 1 2 3 4 5; do
                alive=0
                for p in $pids; do
                    if kill -0 "$p" 2>/dev/null; then alive=1; break; fi
                done
                [ "$alive" -eq 0 ] && exit 0
                sleep 0.2
            done
        fi
    ' _ "$rt_dir" "$force_kill" 9>&- || true
}

cleanup_uninstall_temp_rt() {
    local rt="${_UNINSTALL_TEMP_RT:-}"
    [ -n "$rt" ] || return 0
    _UNINSTALL_TEMP_RT=""
    stop_temp_session_libvirt_daemons "$rt" 1 || true
    fs_ops safe-rmtree "$rt" || true
}

cleanup_uninstall_temp_hook() {
    local hd="${_UNINSTALL_TEMP_HOOK_DIR:-}"
    [ -n "$hd" ] || return 0
    _UNINSTALL_TEMP_HOOK_DIR=""
    fs_ops safe-rmtree "$hd" || true
}

cleanup_uninstall_exit() {
    cleanup_uninstall_temp_hook
    cleanup_uninstall_temp_rt
    if [ -n "${_UNINSTALL_EMPTY_STAGE:-}" ]; then
        rmdir -- "$_UNINSTALL_EMPTY_STAGE" 2>/dev/null || true
        _UNINSTALL_EMPTY_STAGE=""
    fi
}

set_rec_owned_flag() {
    local slot="$1" val="$2"
    case "$slot" in
        unit) REC_OWNED_UNIT="$val" ;;
        install) REC_OWNED_INSTALL_DIR="$val" ;;
        hook) REC_OWNED_HOOK_DIR="$val" ;;
        state) REC_OWNED_STATE_DIR="$val" ;;
        *) die "internal error: unknown uninstall slot '$slot'" ;;
    esac
}

get_rec_owned_flag() {
    case "$1" in
        unit) printf '%s' "$REC_OWNED_UNIT" ;;
        install) printf '%s' "$REC_OWNED_INSTALL_DIR" ;;
        hook) printf '%s' "$REC_OWNED_HOOK_DIR" ;;
        state) printf '%s' "$REC_OWNED_STATE_DIR" ;;
        *) die "internal error: unknown uninstall slot '$1'" ;;
    esac
}

set_rec_staged_path() {
    local slot="$1" val="$2"
    case "$slot" in
        unit) REC_STAGED_UNIT="$val" ;;
        install) REC_STAGED_INSTALL_DIR="$val" ;;
        hook) REC_STAGED_HOOK_DIR="$val" ;;
        state) REC_STAGED_STATE_DIR="$val" ;;
        *) die "internal error: unknown uninstall slot '$slot'" ;;
    esac
}

get_rec_staged_path() {
    case "$1" in
        unit) printf '%s' "$REC_STAGED_UNIT" ;;
        install) printf '%s' "$REC_STAGED_INSTALL_DIR" ;;
        hook) printf '%s' "$REC_STAGED_HOOK_DIR" ;;
        state) printf '%s' "$REC_STAGED_STATE_DIR" ;;
        *) die "internal error: unknown uninstall slot '$1'" ;;
    esac
}

get_rec_vol_id() {
    case "$1" in
        unit) printf '%s' "$REC_VOL_UNIT" ;;
        install) printf '%s' "$REC_VOL_INSTALL_DIR" ;;
        hook) printf '%s' "$REC_VOL_HOOK_DIR" ;;
        state) printf '%s' "$REC_VOL_STATE_DIR" ;;
        *) die "internal error: unknown uninstall slot '$1'" ;;
    esac
}

# Verify that $check_path (or its parent directory when $check_path is absent)
# resides on the exact backing volume recorded in install.env. Fails closed when
# an absent path lacks a recorded volume or its volume is unmounted/mismatched
# so uninstall never clears ownership or purges OPT_USER for offline storage.
verify_resource_volume() {
    local slot="$1" label="$2" check_path="$3"
    local expected_vol
    expected_vol="$(get_rec_vol_id "$slot")"
    if ! fs_ops verify-volume "$check_path" "$expected_vol"; then
        die "refusing to modify or release ownership of ${label} '$check_path': recorded backing volume is unavailable or mismatched; preserving $OPT_CONFIG_DIR/install.env and service account '$OPT_USER' for retry"
    fi
}

# Remove a validated private staging container without crossing any filesystem
# or same-filesystem bind-mount boundary, and clear STAGED_* ONLY after deletion
# (or same-volume confirmed absence) is verified.
remove_staged_container() {
    local slot="$1" label="$2" staged_dir="$3"
    if [ ! -e "$staged_dir" ] && [ ! -L "$staged_dir" ]; then
        verify_resource_volume "$slot" "staged ${label}" "$staged_dir"
    else
        verify_resource_volume "$slot" "staged ${label}" "$staged_dir"
        if ! fs_ops safe-rmtree "$staged_dir"; then
            die "failed to remove staged ${label} '$staged_dir'; preserving installation record at $OPT_CONFIG_DIR/install.env and service account '$OPT_USER' for retry"
        fi
    fi
    if [ -e "$staged_dir" ] || [ -L "$staged_dir" ]; then
        die "staged ${label} '$staged_dir' still exists after removal; preserving installation record at $OPT_CONFIG_DIR/install.env and service account '$OPT_USER' for retry"
    fi
    set_rec_staged_path "$slot" ""
    write_uninstall_record "$OPT_CONFIG_DIR/install.env"
}

# Reconcile any STAGED_* removal container recorded by a previous interrupted
# or failed uninstall BEFORE touching live public paths or purging OPT_USER.
reconcile_staged_entry() {
    local slot="$1" label="$2" target="$3"
    local staged_dir owned_val payload
    staged_dir="$(get_rec_staged_path "$slot")"
    [ -n "$staged_dir" ] || return 0
    validate_staged_path "$label" "$target" "$staged_dir"
    owned_val="$(get_rec_owned_flag "$slot")"
    payload="${staged_dir}/$(basename "$target")"

    if [ ! -e "$staged_dir" ] && [ ! -L "$staged_dir" ]; then
        verify_resource_volume "$slot" "staged ${label}" "$staged_dir"
        set_rec_staged_path "$slot" ""
        write_uninstall_record "$OPT_CONFIG_DIR/install.env"
        return 0
    fi

    if [ "$owned_val" = "1" ]; then
        if [ -e "$payload" ] || [ -L "$payload" ]; then
            # Prior uninstall already moved target into staged_dir but stopped
            # before persisting OWNED_*=0. Release public path ownership now so
            # retry never touches an independent replacement at $target.
            verify_resource_volume "$slot" "staged ${label}" "$staged_dir"
            set_rec_owned_flag "$slot" "0"
            write_uninstall_record "$OPT_CONFIG_DIR/install.env"
            if [ "$slot" = "unit" ] && command -v systemctl >/dev/null 2>&1; then
                systemctl daemon-reload 9>&- || true
            fi
        else
            # Prior uninstall stopped before moving target into staged_dir;
            # clean up the empty staging dir and retain OWNED_*=1.
            remove_staged_container "$slot" "$label" "$staged_dir"
            return 0
        fi
    fi

    remove_staged_container "$slot" "$label" "$staged_dir"
}

reconcile_staged_removals() {
    local unit_path="$1"
    reconcile_staged_entry unit "systemd unit" "$unit_path"
    reconcile_staged_entry install "runner directory" "$OPT_INSTALL_DIR"
    reconcile_staged_entry hook "hook directory" "$OPT_HOOK_DIR"
    reconcile_staged_entry state "state directory" "$OPT_STATE_DIR"
}

# Move an owned unit file or directory atomically via rename(2) (no copy
# fallback on EXDEV) into a private root-only 0700 staging directory on the
# same filesystem after verifying the backing volume and confirming zero nested
# mounts/bind mounts, record STAGED_* BEFORE moving, release OWNED_*=0 (keeping
# STAGED_*) AFTER moving and BEFORE daemon-reload, delete the private staging
# directory via mount-safe safe-rmtree, and clear STAGED_* ONLY after deletion
# is confirmed. If any check, rename, or deletion fails, OWNED_* or STAGED_*
# stays recorded and cmd_uninstall exits non-zero without purging OPT_USER.
stage_and_remove_resource() {
    local slot="$1" label="$2" target="$3"
    [ "$(get_rec_owned_flag "$slot")" = "1" ] || return 0

    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        verify_resource_volume "$slot" "$label" "$target"
        set_rec_owned_flag "$slot" "0"
        write_uninstall_record "$OPT_CONFIG_DIR/install.env"
        if [ "$slot" = "unit" ] && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload 9>&- || true
        fi
        return 0
    fi

    if [ -L "$target" ]; then
        if [ "$slot" = "unit" ]; then
            warn "refusing to remove symlinked systemd unit path '$target'"
            set_rec_owned_flag "$slot" "0"
            write_uninstall_record "$OPT_CONFIG_DIR/install.env"
            if command -v systemctl >/dev/null 2>&1; then
                systemctl daemon-reload 9>&- || true
            fi
            return 0
        fi
        die "refusing to remove symlinked ${label} '$target'"
    fi

    check_trusted_parent_dir "$target"
    verify_resource_volume "$slot" "$label" "$target"
    if ! fs_ops check-no-mounts "$target"; then
        die "refusing to stage or remove ${label} '$target' containing an active mount or bind mount; preserving $OPT_CONFIG_DIR/install.env and service account '$OPT_USER' for retry"
    fi

    local parent base stage_parent payload
    parent="$(dirname "$target")"
    base="$(basename "$target")"
    stage_parent="$(umask 0077 && mktemp -d "${parent}/.qeminga-removing.XXXXXX")" \
        || die "failed to create removal staging directory under '$parent' for ${label} '$target'; preserving installation record at $OPT_CONFIG_DIR/install.env for retry"
    _UNINSTALL_EMPTY_STAGE="$stage_parent"
    if ! chown -h root:root "$stage_parent" || ! chmod 0700 "$stage_parent"; then
        rmdir -- "$stage_parent" 2>/dev/null || true
        _UNINSTALL_EMPTY_STAGE=""
        die "failed to secure removal staging directory '$stage_parent' for ${label} '$target'"
    fi

    set_rec_staged_path "$slot" "$stage_parent"
    write_uninstall_record "$OPT_CONFIG_DIR/install.env"
    _UNINSTALL_EMPTY_STAGE=""

    payload="${stage_parent}/${base}"
    if ! fs_ops rename-only "$target" "$payload"; then
        rmdir -- "$stage_parent" 2>/dev/null || true
        set_rec_staged_path "$slot" ""
        write_uninstall_record "$OPT_CONFIG_DIR/install.env" || true
        die "failed to stage removal of ${label} '$target' via rename-only transition; ownership retained in $OPT_CONFIG_DIR/install.env for retry"
    fi

    set_rec_owned_flag "$slot" "0"
    write_uninstall_record "$OPT_CONFIG_DIR/install.env"
    if [ "$slot" = "unit" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 9>&- || true
    fi

    remove_staged_container "$slot" "$label" "$stage_parent"
}

cmd_uninstall() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "uninstall must run as root"
    acquire_install_lock

    _UNINSTALL_TEMP_RT=""
    _UNINSTALL_TEMP_HOOK_DIR=""
    _UNINSTALL_EMPTY_STAGE=""
    trap 'cleanup_uninstall_exit' EXIT

    # Refuse to run any cleanup, chown, token handoff, or deletion without a
    # valid root-owned installation record and matching live user UID/GID.
    load_and_verify_install_record uninstall

    # Handle a retained user-only record (from uninstall without --purge-user)
    # or a preserved user-pending record (from failed bootstrap userdel rollback).
    if [ "$REC_STATE" = "user-only" ] || [ "$REC_STATE" = "user-pending" ]; then
        if [ "$OPT_PURGE_USER" -eq 1 ]; then
            if [ "$REC_USER_CREATED" = "1" ] && id "$OPT_USER" >/dev/null 2>&1; then
                userdel "$OPT_USER" || die "could not delete user $OPT_USER; preserving ownership record at $OPT_CONFIG_DIR/install.env"
                if getent group "$OPT_USER" >/dev/null 2>&1; then
                    groupdel "$OPT_USER" || true
                fi
            fi
            fs_ops safe-rmtree "$OPT_CONFIG_DIR"
            echo "purged user ${OPT_USER} and removed ${OPT_CONFIG_DIR}"
        elif ! id "$OPT_USER" >/dev/null 2>&1; then
            fs_ops safe-rmtree "$OPT_CONFIG_DIR"
            echo "removed stale ${REC_STATE} record in ${OPT_CONFIG_DIR}"
        else
            local live_uid
            live_uid="${REC_USER_UID:-$(id -u "$OPT_USER" 2>/dev/null || echo unknown)}"
            echo "no runner installation remains in ${OPT_CONFIG_DIR}; managed user '${OPT_USER}' (uid=${live_uid}) is preserved (pass --purge-user to remove it)"
        fi
        trap - EXIT
        return 0
    fi

    local unit_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    unit_dir="${unit_dir%/}"
    check_abs_path "systemd unit dir" "$unit_dir"
    local unit_path="${unit_dir}/${OPT_SERVICE}.service"

    # Reconcile any previously staged removals BEFORE stopping services, running
    # cleanup hooks, deregistering, or purging OPT_USER.
    reconcile_staged_removals "$unit_path"

    # If uninstalling after an interrupted update, reclaim any recorded stage
    # directory and reconcile the verified private update backup container
    # according to UPDATE_PHASE so neither is leaked and optional deregistration
    # still finds config.sh.
    if [ "$REC_STATE" = "updating" ]; then
        if [ -n "$REC_UPDATE_STAGE_DIR" ]; then
            validate_update_stage_path "$OPT_INSTALL_DIR" "$REC_UPDATE_STAGE_DIR"
            verify_resource_volume install "update stage directory" "$REC_UPDATE_STAGE_DIR"
            fs_ops safe-rmtree-id "$REC_UPDATE_STAGE_DIR" "$REC_UPDATE_STAGE_ID" \
                || die "uninstall: failed to reclaim interrupted update stage '$REC_UPDATE_STAGE_DIR'; preserving $OPT_CONFIG_DIR/install.env for retry"
            REC_UPDATE_STAGE_DIR=""
            REC_UPDATE_STAGE_ID=""
        fi
        if [ -n "$REC_UPDATE_BACKUP_DIR" ]; then
            validate_update_backup_path "$OPT_INSTALL_DIR" "$REC_UPDATE_BACKUP_DIR"
            verify_resource_volume install "update backup directory" "$REC_UPDATE_BACKUP_DIR"
            if [ "$REC_UPDATE_PHASE" = "committed" ]; then
                fs_ops safe-rmtree-id "$REC_UPDATE_BACKUP_DIR" "$REC_UPDATE_BACKUP_ID" \
                    || die "uninstall: failed to prune committed update backup '$REC_UPDATE_BACKUP_DIR'; preserving $OPT_CONFIG_DIR/install.env for retry"
            elif [ "$REC_OWNED_INSTALL_DIR" = "1" ] && [ -d "$OPT_INSTALL_DIR" ]; then
                local uninstall_work_child=""
                if [ -n "${REC_WORK_DIR:-}" ]; then
                    uninstall_work_child="$(runner_workspace_child_name "$OPT_INSTALL_DIR" "$REC_WORK_DIR")"
                fi
                fs_ops restore-runner-backup "$OPT_INSTALL_DIR" "$REC_VOL_INSTALL_DIR" "$REC_UPDATE_BACKUP_DIR" "$REC_UPDATE_BACKUP_ID" "$uninstall_work_child" "0" \
                    || die "uninstall: failed to reconcile interrupted update backup '$REC_UPDATE_BACKUP_DIR'; preserving $OPT_CONFIG_DIR/install.env for retry"
            else
                fs_ops safe-rmtree-id "$REC_UPDATE_BACKUP_DIR" "$REC_UPDATE_BACKUP_ID" \
                    || die "uninstall: failed to remove interrupted update backup '$REC_UPDATE_BACKUP_DIR'; preserving $OPT_CONFIG_DIR/install.env for retry"
            fi
            REC_UPDATE_BACKUP_DIR=""
            REC_UPDATE_BACKUP_ID=""
        fi
        REC_UPDATE_PHASE="restored"
        write_update_record "$OPT_CONFIG_DIR/install.env" "updating" "restored" "" "" "" "" "$REC_UPDATE_WAS_ACTIVE"
    fi

    # Only stop/disable the unit if this installation actually created/owns it
    # and its recorded backing volume matches.
    if [ "$REC_OWNED_UNIT" = "1" ]; then
        verify_resource_volume unit "systemd unit" "$unit_path"
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop "${OPT_SERVICE}.service" 9>&- 2>/dev/null || true
            systemctl disable "${OPT_SERVICE}.service" 9>&- 2>/dev/null || true
        fi
    fi

    # Run THIS installer's own domain-only cleanup logic (with a minimal
    # generated STATE_DIR/IMAGES_DIR policy — never executing a stale hook from
    # $OPT_HOOK_DIR and never referencing WORK_DIR/INSTALL_DIR) as the runner
    # user to destroy any stray qeminga-e2e-* session domains before removing
    # owned state files.
    local cleanup_rc=0
    if [ "$REC_OWNED_STATE_DIR" = "1" ] && [ -d "$OPT_STATE_DIR" ] \
        && command -v runuser >/dev/null 2>&1 && id "$OPT_USER" >/dev/null 2>&1; then
        verify_resource_volume state "state directory" "$OPT_STATE_DIR"
        local runtime_root="${QEMINGA_RUNTIME_ROOT:-/run}"
        runtime_root="${runtime_root%/}"
        check_abs_path "runtime root" "$runtime_root"
        [ ! -L "$runtime_root" ] && [ -d "$runtime_root" ] || die "runtime root directory '$runtime_root' is missing or unsafe"
        check_trusted_parent_dir "${runtime_root}/qeminga-uninstall"

        local default_rt="${runtime_root}/${OPT_SERVICE}"
        local cleanup_rt="" cleanup_rt_created=0
        if [ "$REC_OWNED_UNIT" = "1" ] && [ ! -L "$default_rt" ] && [ -d "$default_rt" ] && [ "$(stat -c '%u:%a' "$default_rt" 2>/dev/null || echo '')" = "${REC_USER_UID}:700" ]; then
            cleanup_rt="$default_rt"
        else
            cleanup_rt="$(umask 0077 && mktemp -d "${runtime_root}/qeminga-uninstall.XXXXXX")"
            _UNINSTALL_TEMP_RT="$cleanup_rt"
            chmod 0700 "$cleanup_rt"
            chown -h "${REC_USER_UID}:${REC_USER_GID}" "$cleanup_rt"
            cleanup_rt_created=1
        fi

        local cleanup_hook_dir policy_state_vol="${REC_VOL_STATE_DIR:-}"
        if [ -n "${QEMINGA_MOUNTINFO:-}" ] && [ -n "$policy_state_vol" ]; then
            # In tests using synthetic QEMINGA_MOUNTINFO, verify_resource_volume
            # above already checked REC_VOL_STATE_DIR; bridge to the real host
            # volume identity because the isolated hook reads only /proc/self/mountinfo.
            policy_state_vol="$(QEMINGA_MOUNTINFO="" QEMINGA_FS_UUID_MAP="" QEMINGA_TEST_MNT_ID="" fs_ops volume-id "$OPT_STATE_DIR")"
        fi
        cleanup_hook_dir="$(umask 0077 && mktemp -d "${runtime_root}/qeminga-uninstall-hook.XXXXXX")"
        _UNINSTALL_TEMP_HOOK_DIR="$cleanup_hook_dir"
        chown -h "0:${REC_USER_GID}" "$cleanup_hook_dir"
        chmod 0750 "$cleanup_hook_dir"
        write_job_completed_hook "$cleanup_hook_dir/hook-job-completed.sh" root root
        publish_managed_file "$cleanup_hook_dir/policy.env" 0640 0 "$REC_USER_GID" <<EOF
STATE_DIR=${OPT_STATE_DIR}
IMAGES_DIR=${OPT_STATE_DIR%/}/images
STATE_VOL=${policy_state_vol}
LIBVIRT_CONNECT=qemu:///session
EOF

        say "running domain-only cleanup hook to remove stray qeminga session domains"
        if ! runuser -u "$OPT_USER" -- env -u DBUS_SESSION_BUS_ADDRESS \
            "HOME=$OPT_STATE_DIR" \
            "XDG_RUNTIME_DIR=$cleanup_rt" \
            "XDG_CONFIG_HOME=$OPT_STATE_DIR/.config" \
            "XDG_CACHE_HOME=$OPT_STATE_DIR/.cache" \
            "XDG_DATA_HOME=$OPT_STATE_DIR/.local/share" \
            "LIBVIRT_DEFAULT_URI=qemu:///session" \
            "QEMINGA_RUNNER_POLICY=$cleanup_hook_dir/policy.env" \
            "$cleanup_hook_dir/hook-job-completed.sh" --domains-only 9>&-; then
            cleanup_rc=1
            warn "cleanup hook could not confirm all qeminga domains are gone; preserving $OPT_STATE_DIR/images"
        fi
        cleanup_uninstall_temp_hook
        if [ "$cleanup_rt_created" -eq 1 ]; then
            cleanup_uninstall_temp_rt
        elif [ "$cleanup_rc" -eq 0 ]; then
            stop_temp_session_libvirt_daemons "$cleanup_rt" 0 || true
        fi
    elif [ "$REC_OWNED_STATE_DIR" = "1" ] && [ -d "$OPT_STATE_DIR" ]; then
        verify_resource_volume state "state directory" "$OPT_STATE_DIR"
        if ! fs_ops verify-images-fallback "$OPT_STATE_DIR"; then
            cleanup_rc=1
            warn "cleanup hook unavailable and $OPT_STATE_DIR/images could not be verified clean; preserving $OPT_STATE_DIR/images and $OPT_STATE_DIR/.config"
        fi
    fi

    # Optional deregistration from GitHub if a removal token was supplied (only
    # when this installation actually owns OPT_INSTALL_DIR).
    if [ "$REC_OWNED_INSTALL_DIR" = "1" ] && [ -n "$OPT_TOKEN_FILE" ] \
        && [ ! -L "$OPT_INSTALL_DIR" ] && [ ! -L "$OPT_INSTALL_DIR/config.sh" ] \
        && [ -x "$OPT_INSTALL_DIR/config.sh" ] && id "$OPT_USER" >/dev/null 2>&1; then
        verify_resource_volume install "runner directory" "$OPT_INSTALL_DIR"
        fs_ops check-no-mounts "$OPT_INSTALL_DIR" \
            || die "refusing to deregister or modify runner directory '$OPT_INSTALL_DIR' containing an active mount or bind mount; preserving $OPT_CONFIG_DIR/install.env and service account '$OPT_USER' for retry"
        command -v runuser >/dev/null 2>&1 || die "runuser is required to deregister the runner as $OPT_USER"
        local rm_token skip_children
        rm_token="$(read_secret_file --token-file "$OPT_TOKEN_FILE")"
        skip_children="$(runner_workspace_skip_list "$OPT_INSTALL_DIR" "${REC_WORK_DIR:-}")"
        say "deregistering runner from GitHub"
        safe_chown_runner_dir "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR" "$REC_VOL_INSTALL_DIR" "$skip_children"
        run_runner_config_with_token "$rm_token" remove --unattended \
            || warn "deregistration failed (remove manually in GitHub Settings -> Actions -> Runners)"
        unset rm_token
    elif [ "$REC_OWNED_INSTALL_DIR" != "1" ] && [ -n "$OPT_TOKEN_FILE" ]; then
        warn "skipping runner deregistration: $OPT_INSTALL_DIR is not owned by this installation (already removed or never created)"
    fi

    # Stage each owned resource into a private root-only container on the same
    # filesystem, release its OWNED_* flag only after moving it out of the
    # public path, and clear STAGED_* only once deletion is confirmed.
    stage_and_remove_resource unit "systemd unit" "$unit_path"
    stage_and_remove_resource install "runner directory" "$OPT_INSTALL_DIR"

    if [ "$cleanup_rc" -eq 0 ]; then
        stage_and_remove_resource hook "hook directory" "$OPT_HOOK_DIR"
        stage_and_remove_resource state "state directory" "$OPT_STATE_DIR"

        if [ "$REC_OWNED_UNIT" != "0" ] || [ "$REC_OWNED_INSTALL_DIR" != "0" ] \
            || [ "$REC_OWNED_HOOK_DIR" != "0" ] || [ "$REC_OWNED_STATE_DIR" != "0" ] \
            || [ -n "$REC_STAGED_UNIT" ] || [ -n "$REC_STAGED_INSTALL_DIR" ] \
            || [ -n "$REC_STAGED_HOOK_DIR" ] || [ -n "$REC_STAGED_STATE_DIR" ]; then
            die "refusing to purge service user or remove ${OPT_CONFIG_DIR} while owned or staged resources remain in ${OPT_CONFIG_DIR}/install.env"
        fi

        local user_purged=0
        if [ "$OPT_PURGE_USER" -eq 1 ] && [ "$REC_USER_CREATED" = "1" ] && id "$OPT_USER" >/dev/null 2>&1; then
            if userdel "$OPT_USER"; then
                user_purged=1
                if getent group "$OPT_USER" >/dev/null 2>&1; then
                    groupdel "$OPT_USER" || true
                fi
            else
                warn "could not delete user $OPT_USER"
            fi
        fi

        if [ "$user_purged" -eq 1 ] || [ "$REC_USER_CREATED" != "1" ] || ! id "$OPT_USER" >/dev/null 2>&1; then
            fs_ops safe-rmtree "$OPT_CONFIG_DIR"
        else
            # Retain a minimal UID/GID ownership record while the managed
            # account survives uninstall so a subsequent default install or a
            # later `uninstall --purge-user` can verify and manage it safely.
            local cfg_entry
            shopt -s dotglob nullglob
            for cfg_entry in "$OPT_CONFIG_DIR"/*; do
                [ "$(basename "$cfg_entry")" = "install.env" ] && continue
                fs_ops safe-rmtree "$cfg_entry"
            done
            shopt -u dotglob nullglob
            write_user_only_record "$OPT_CONFIG_DIR/install.env" \
                "$OPT_USER" "$REC_USER_UID" "$REC_USER_GID" "$REC_USER_CREATED" "$OPT_CONFIG_DIR" "$REC_INSTALL_ID"
            chown -h root:root "$OPT_CONFIG_DIR"
            chmod 0700 "$OPT_CONFIG_DIR"
        fi
        trap - EXIT
        echo "uninstalled ${OPT_SERVICE}"
    else
        # Preserve images/, libvirt session .config/, hooks, and config in
        # partial-uninstall state (with unit and runner dir already released) so
        # the operator can inspect domains and re-run uninstall safely.
        write_uninstall_record "$OPT_CONFIG_DIR/install.env"
        if [ "$REC_OWNED_STATE_DIR" = "1" ] && [ -d "$OPT_STATE_DIR" ]; then
            local sub
            for sub in work image-cache .cache .local; do
                if [ -e "$OPT_STATE_DIR/$sub" ] || [ -L "$OPT_STATE_DIR/$sub" ]; then
                    fs_ops safe-rmtree "$OPT_STATE_DIR/$sub" \
                        || warn "skipped removing '$OPT_STATE_DIR/$sub' during partial uninstall (mount boundary or permission error)"
                fi
            done
        fi
        die "partial uninstall of ${OPT_SERVICE}: preserved $OPT_STATE_DIR/images, $OPT_STATE_DIR/.config, $OPT_HOOK_DIR, and $OPT_CONFIG_DIR because libvirt domain cleanup did not confirm domains absent"
    fi
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
        migrate-record) cmd_migrate_record "$@" ;;
        uninstall) cmd_uninstall "$@" ;;
        -h | --help) usage ;;
        *) die "unknown subcommand '$sub' (run with --help)" ;;
    esac
fi
