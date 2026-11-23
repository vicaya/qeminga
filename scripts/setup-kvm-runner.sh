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
  preflight     Read-only host check (arch, /dev/kvm, cgroup v2, libvirt/QEMU, AAVMF on arm64, RAM/disk, DNS)
  install       Install packages, create locked user, verify & register runner, install hardened unit
  render-unit   Print the hardened systemd unit to stdout without modifying the host
  render-hooks  Write hook scripts, egress firewall check, and policy.env into --out DIR
  fetch-runner  Download and SHA-256 verify the pinned actions/runner tarball for x86_64 or aarch64
  status        Show service status, systemd security score, KVM state, and active policy
  update        Stop service, replace actions/runner with a SHA-256-verified archive, restart
  uninstall     Stop & remove service (using install record), clean stray qeminga domains, optionally deregister & purge user

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
    mv -f "$tmp" "$dest"
    trap - RETURN
    echo "verified actions/runner v${ver} (${arch}): sha256=${got}"
}

# ---- render-hooks ---------------------------------------------------------

write_policy_file() {
    local dest="$1" slug="$2"
    local work_dir="${RESOLVED_WORK_DIR:-${OPT_STATE_DIR}/work}"
    local deny_lan=1
    [ "$OPT_NO_LAN_DENY" -eq 1 ] && deny_lan=0
    cat >"$dest" <<EOF
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
DENY_LAN=${deny_lan}
LIBVIRT_CONNECT=qemu:///session
EOF
}

write_job_started_hook() {
    local dest="$1"
    cat >"$dest" <<'EOF'
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
        INSTALL_DIR | STATE_DIR | WORK_DIR | IMAGES_DIR | IMAGE_CACHE_DIR | DENY_LAN) ;;
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
LIBVIRT_CONNECT="qemu:///session"

while IFS='=' read -r key val; do
    case "$key" in
        '' | '#'*) continue ;;
        INSTALL_DIR) INSTALL_DIR="$val" ;;
        STATE_DIR) STATE_DIR="$val" ;;
        WORK_DIR) WORK_DIR="$val" ;;
        IMAGES_DIR) IMAGES_DIR="$val" ;;
        LIBVIRT_CONNECT) LIBVIRT_CONNECT="$val" ;;
    esac
done <"$POLICY"

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

safe_subdir "$IMAGES_DIR" || die "refusing unsafe IMAGES_DIR '$IMAGES_DIR'"
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
elif [ -d "$IMAGES_DIR" ]; then
    shopt -s nullglob
    for dir in "$IMAGES_DIR"/qeminga-e2e-*; do
        [ -e "$dir" ] || continue
        log "virsh is unavailable while $dir exists; keeping disks"
        rc=1
        break
    done
    shopt -u nullglob
fi

if [ "$DOMAINS_ONLY" -eq 0 ]; then
    # Re-verify WORK_DIR has no symlinks or protected-state overlap right before
    # scrubbing, and use find -P so symlinks are never traversed.
    verify_work_dir_safe
    if [ -d "$WORK_DIR" ] && [ ! -L "$WORK_DIR" ]; then
        find -P "$WORK_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf --one-file-system -- {} +
        log "scrubbed work directory $WORK_DIR"
    fi
fi

exit "$rc"
EOF
    chmod 0755 "$dest"
}

write_egress_firewall_check() {
    local dest="$1"
    local py_deny_lan="True"
    [ "$OPT_NO_LAN_DENY" -eq 1 ] && py_deny_lan="False"
    local py_allow_cidrs="" ip
    for ip in "${OPT_ALLOW_IPS[@]}"; do
        py_allow_cidrs="${py_allow_cidrs}${py_allow_cidrs:+, }\"${ip}\""
    done

    cat >"$dest" <<'EOF'
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
    printf 'DENY_LAN = %s\nALLOW_CIDRS = [%s]\n' "$py_deny_lan" "$py_allow_cidrs" >>"$dest"
    cat >>"$dest" <<'EOF'
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
EOF
    chmod 0755 "$dest"
}

write_runner_launcher() {
    local dest="$1"
    cat >"$dest" <<EOF
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
    cat >>"$dest" <<'EOF'
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
EOF
    chmod 0755 "$dest"
}

write_jit_launcher() {
    local dest="$1"
    cat >"$dest" <<EOF
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
    cat >>"$dest" <<'EOF'
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
EOF
    chmod 0755 "$dest"
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
    mkdir -p "$OPT_OUT"
    write_policy_file "$OPT_OUT/policy.env" "$ALLOWED_REPO_SLUG"
    write_job_started_hook "$OPT_OUT/hook-job-started.sh"
    write_job_completed_hook "$OPT_OUT/hook-job-completed.sh"
    write_egress_firewall_check "$OPT_OUT/check-egress-firewall.sh"
    if [ -n "$OPT_JITCONFIG_FILE" ]; then
        write_jit_launcher "$OPT_OUT/run-jit.sh"
        echo "wrote $OPT_OUT/policy.env, $OPT_OUT/hook-job-started.sh, $OPT_OUT/hook-job-completed.sh, $OPT_OUT/check-egress-firewall.sh, $OPT_OUT/run-jit.sh"
    else
        write_runner_launcher "$OPT_OUT/run-runner.sh"
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

MANAGED_USER_UID=""
MANAGED_USER_GID=""
MANAGED_USER_CREATED="0"

OWNED_CONFIG_DIR=0
OWNED_STATE_DIR=0
OWNED_INSTALL_DIR=0
OWNED_HOOK_DIR=0
OWNED_UNIT=0

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

# allow_existing:
#   0      = fresh install (none of the four managed dirs may exist)
#   1      = active install record (all four managed dirs may exist)
#   2      = user-only record retained after uninstall (only CONFIG_DIR may exist,
#            and it may contain only install.env)
#   record = interrupted install recovery (each dir may exist ONLY if its
#            corresponding REC_OWNED_* flag is 1)
#   owned  = uninstall mode (validate only dirs with REC_OWNED_* = 1; ignore
#            unowned paths so foreign paths cannot block cleanup of owned dirs)
check_dedicated_managed_dirs() {
    local allow_existing="$1"
    local dirs=("$OPT_INSTALL_DIR" "$OPT_STATE_DIR" "$OPT_HOOK_DIR" "$OPT_CONFIG_DIR")
    local owned=("${REC_OWNED_INSTALL_DIR:-0}" "${REC_OWNED_STATE_DIR:-0}" "${REC_OWNED_HOOK_DIR:-0}" "${REC_OWNED_CONFIG_DIR:-0}")
    local i j a b
    for i in 0 1 2 3; do
        a="${dirs[$i]}"
        check_abs_path "managed directory" "$a"
        if is_reserved_system_dir "$a"; then
            die "refusing shared system directory '$a' as a managed runner directory"
        fi
        if [ "$allow_existing" = "owned" ] && [ "${owned[$i]}" != "1" ]; then
            continue
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
            die "refusing unexpected entry '$extra' in '$OPT_CONFIG_DIR' alongside user-only install.env"
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
    REC_SCHEMA="" REC_STATE="" REC_SERVICE="" REC_USER="" REC_USER_UID="" REC_USER_GID=""
    REC_USER_CREATED="" REC_INSTALL_DIR="" REC_STATE_DIR="" REC_HOOK_DIR=""
    REC_CONFIG_DIR="" REC_TARGET_URL="" REC_RUNNER_GROUP="" REC_RUNNER_NAME=""
    REC_LABELS="" REC_EPHEMERAL="" REC_ALLOW_AUTO_UPDATE="" REC_WORK_DIR=""
    REC_OWNED_CONFIG_DIR="" REC_OWNED_STATE_DIR="" REC_OWNED_INSTALL_DIR=""
    REC_OWNED_HOOK_DIR="" REC_OWNED_UNIT=""

    local key val
    while IFS='=' read -r key val; do
        case "$key" in
            '' | '#'*) continue ;;
            RECORD_SCHEMA) REC_SCHEMA="$val" ;;
            RECORD_STATE) REC_STATE="$val" ;;
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
            *) die "unknown key '$key' in installation record '$rec'" ;;
        esac
    done <"$rec"

    [ "$REC_SCHEMA" = "1" ] || die "unsupported installation record schema '${REC_SCHEMA:-<empty>}' in '$rec'"
    REC_STATE="${REC_STATE:-installed}"
    case "$REC_STATE" in
        installed | installing | partial-uninstall | user-only) ;;
        *) die "unsupported installation record state '$REC_STATE' in '$rec'" ;;
    esac
    [ -n "$REC_USER" ] && [ -n "$REC_CONFIG_DIR" ] \
        || die "incomplete installation record '$rec'"
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

write_install_record() {
    local dest="$1" runner_name="$2" state="${3:-installed}"
    check_trusted_parent_dir "$dest"
    [ ! -L "$dest" ] || die "refusing symlinked installation record '$dest'"
    local tmp
    tmp="$(mktemp "$(dirname "$dest")/.install.env.XXXXXX")"
    if ! cat >"$tmp" <<EOF
# Managed by scripts/setup-kvm-runner.sh — root-owned installation record.
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
RECORD_SCHEMA=1
RECORD_STATE=${state}
SERVICE=${OPT_SERVICE}
USER=${OPT_USER}
USER_UID=${MANAGED_USER_UID}
USER_GID=${MANAGED_USER_GID}
USER_CREATED=${MANAGED_USER_CREATED}
INSTALL_DIR=${OPT_INSTALL_DIR}
STATE_DIR=${OPT_STATE_DIR}
HOOK_DIR=${OPT_HOOK_DIR}
CONFIG_DIR=${OPT_CONFIG_DIR}
TARGET_URL=${TARGET_URL}
RUNNER_GROUP=${OPT_RUNNER_GROUP}
RUNNER_NAME=${runner_name}
LABELS=${OPT_LABELS}
EPHEMERAL=${OPT_EPHEMERAL}
ALLOW_AUTO_UPDATE=${OPT_ALLOW_AUTO_UPDATE}
WORK_DIR=${RESOLVED_WORK_DIR}
OWNED_CONFIG_DIR=${OWNED_CONFIG_DIR}
OWNED_STATE_DIR=${OWNED_STATE_DIR}
OWNED_INSTALL_DIR=${OWNED_INSTALL_DIR}
OWNED_HOOK_DIR=${OWNED_HOOK_DIR}
OWNED_UNIT=${OWNED_UNIT}
EOF
    then
        rm -f "$tmp"
        die "failed to write installation record '$dest'"
    fi
    if ! chown -h root:root "$tmp" || ! chmod 0600 "$tmp" || ! mv -f "$tmp" "$dest"; then
        rm -f "$tmp"
        die "failed to finalize installation record '$dest'"
    fi
}

write_uninstall_record() {
    local dest="$1"
    check_trusted_parent_dir "$dest"
    [ ! -L "$dest" ] || die "refusing symlinked installation record '$dest'"
    local tmp
    tmp="$(mktemp "$(dirname "$dest")/.install.env.XXXXXX")"
    if ! cat >"$tmp" <<EOF
# Managed by scripts/setup-kvm-runner.sh — root-owned installation record.
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
RECORD_SCHEMA=1
RECORD_STATE=partial-uninstall
SERVICE=${REC_SERVICE}
USER=${REC_USER}
USER_UID=${REC_USER_UID}
USER_GID=${REC_USER_GID}
USER_CREATED=${REC_USER_CREATED}
INSTALL_DIR=${REC_INSTALL_DIR}
STATE_DIR=${REC_STATE_DIR}
HOOK_DIR=${REC_HOOK_DIR}
CONFIG_DIR=${REC_CONFIG_DIR}
TARGET_URL=${REC_TARGET_URL}
RUNNER_GROUP=${REC_RUNNER_GROUP}
RUNNER_NAME=${REC_RUNNER_NAME}
LABELS=${REC_LABELS}
EPHEMERAL=${REC_EPHEMERAL}
ALLOW_AUTO_UPDATE=${REC_ALLOW_AUTO_UPDATE}
WORK_DIR=${REC_WORK_DIR}
OWNED_CONFIG_DIR=${REC_OWNED_CONFIG_DIR}
OWNED_STATE_DIR=${REC_OWNED_STATE_DIR}
OWNED_INSTALL_DIR=${REC_OWNED_INSTALL_DIR}
OWNED_HOOK_DIR=${REC_OWNED_HOOK_DIR}
OWNED_UNIT=${REC_OWNED_UNIT}
EOF
    then
        rm -f "$tmp"
        die "failed to write uninstall record '$dest'"
    fi
    if ! chown -h root:root "$tmp" || ! chmod 0600 "$tmp" || ! mv -f "$tmp" "$dest"; then
        rm -f "$tmp"
        die "failed to finalize uninstall record '$dest'"
    fi
}

write_user_only_record() {
    local dest="$1" user="$2" uid="$3" gid="$4" created="$5" cfg_dir="$6"
    check_trusted_parent_dir "$dest"
    [ ! -L "$dest" ] || die "refusing symlinked installation record '$dest'"
    local tmp
    tmp="$(mktemp "$(dirname "$dest")/.install.env.XXXXXX")"
    if ! cat >"$tmp" <<EOF
# Managed by scripts/setup-kvm-runner.sh — retained minimal UID/GID ownership
# record for a managed service user that survived uninstall without --purge-user.
# Parsed strictly as KEY=VALUE lines (never sourced or eval'd).
RECORD_SCHEMA=1
RECORD_STATE=user-only
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
    if ! chown -h root:root "$tmp" || ! chmod 0600 "$tmp" || ! mv -f "$tmp" "$dest"; then
        rm -f "$tmp"
        die "failed to finalize user-only record '$dest'"
    fi
}

# Verify the live numeric UID and GID of OPT_USER match the root-owned record
# BEFORE any runuser execution, chown, credential handling, service stop, or
# file removal. Leaves install.env intact on mismatch so the operator can
# inspect and recover safely.
verify_recorded_user_identity() {
    local mode="$1"
    if id "$OPT_USER" >/dev/null 2>&1; then
        local cur_uid cur_gid
        cur_uid="$(id -u "$OPT_USER")"
        cur_gid="$(id -g "$OPT_USER")"
        if [ "$cur_uid" -eq 0 ] || [ "$cur_uid" != "$REC_USER_UID" ] || [ "$cur_gid" != "$REC_USER_GID" ]; then
            die "${mode}: service user '$OPT_USER' uid:gid (${cur_uid}:${cur_gid}) does not match recorded ${REC_USER_UID}:${REC_USER_GID}; refusing to proceed (leaving $OPT_CONFIG_DIR/install.env intact for recovery)"
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

    if [ "$REC_STATE" = "user-only" ]; then
        if [ "$mode" = "update" ]; then
            die "update: $rec_path records only a surviving service user '$REC_USER' (no active runner installation)"
        fi
        OPT_USER="$REC_USER"
        OPT_CONFIG_DIR="$REC_CONFIG_DIR"
        check_abs_path "config directory" "$OPT_CONFIG_DIR"
        if is_reserved_system_dir "$OPT_CONFIG_DIR"; then
            die "refusing shared system directory '$OPT_CONFIG_DIR' as a managed runner directory"
        fi
        [ ! -L "$OPT_CONFIG_DIR" ] || die "refusing symlinked managed directory '$OPT_CONFIG_DIR'"
        check_trusted_parent_dir "$OPT_CONFIG_DIR"
        verify_recorded_user_identity "$mode"
        return 0
    fi

    if [ "$mode" = "update" ] && [ "$REC_STATE" != "installed" ]; then
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

_INSTALL_BOOTSTRAP_CFG=""
_INSTALL_BOOTSTRAP_DIR=""
_INSTALL_BOOTSTRAP_UNIT=""
_INSTALL_BOOTSTRAP_USER=""
_INSTALL_BOOTSTRAP_TARBALL=""

cleanup_install_exit() {
    if [ -n "${_INSTALL_BOOTSTRAP_TARBALL:-}" ]; then
        rm -f "$_INSTALL_BOOTSTRAP_TARBALL"
        _INSTALL_BOOTSTRAP_TARBALL=""
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
        userdel "$_INSTALL_BOOTSTRAP_USER" 2>/dev/null || true
        if getent group "$_INSTALL_BOOTSTRAP_USER" >/dev/null 2>&1; then
            groupdel "$_INSTALL_BOOTSTRAP_USER" 2>/dev/null || true
        fi
        _INSTALL_BOOTSTRAP_USER=""
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
        local uid gid pgroup groups g
        uid="$(id -u "$OPT_USER")"
        gid="$(id -g "$OPT_USER")"
        pgroup="$(id -gn "$OPT_USER")"
        [ "$uid" -ne 0 ] || die "existing user $OPT_USER has uid 0"
        [ "$uid" = "$REC_USER_UID" ] || die "user '$OPT_USER' uid $uid does not match recorded uid $REC_USER_UID; refusing to reuse"
        [ "$gid" = "$REC_USER_GID" ] || die "user '$OPT_USER' gid $gid does not match recorded gid $REC_USER_GID; refusing to reuse"
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
        useradd --system --user-group \
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
# - Sets <owned_var>=1 and persists install.env (state=installing) BEFORE
#   adjusting permissions or initializing any child files/subdirectories, so
#   an interruption during chmod/chown/runuser/extraction leaves <dir>
#   recorded as owned and recoverable by ordinary retry or uninstall.
# - When <owned_var> is 1 (already owned per verified install.env or reserved
#   earlier in this invocation), validates <dir> as a non-symlink directory
#   under trusted root-owned ancestors (or recreates it exclusively if absent)
#   and applies owner/group/mode.
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

    if [ "$is_owned" -ne 1 ]; then
        reserve_fresh_dir "$label" "$dir"
        _INSTALL_BOOTSTRAP_DIR="$dir"
        case "$owned_var" in
            OWNED_CONFIG_DIR) OWNED_CONFIG_DIR=1 ;;
            OWNED_STATE_DIR) OWNED_STATE_DIR=1 ;;
            OWNED_INSTALL_DIR) OWNED_INSTALL_DIR=1 ;;
            OWNED_HOOK_DIR) OWNED_HOOK_DIR=1 ;;
        esac
        write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installing"
        _INSTALL_BOOTSTRAP_DIR=""
        if [ "$owned_var" = "OWNED_CONFIG_DIR" ]; then
            _INSTALL_BOOTSTRAP_USER=""
            _INSTALL_BOOTSTRAP_CFG=""
        fi
    else
        if [ -e "$dir" ]; then
            [ -d "$dir" ] || die "${label} path '$dir' exists and is not a directory"
        else
            reserve_fresh_dir "$label" "$dir"
        fi
        if [ "$owned_var" = "OWNED_CONFIG_DIR" ]; then
            write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installing"
            _INSTALL_BOOTSTRAP_USER=""
            _INSTALL_BOOTSTRAP_CFG=""
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
        "$OPT_STATE_DIR/.local/share"
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
            "$OPT_INSTALL_DIR/config.sh" "$@"
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
    chown -h -R -P "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR"
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

    # Load and validate existing installation record (if reinstalling, recovering
    # from an interrupted install, or reusing a managed user retained after
    # uninstall) BEFORE mutating any live state, directories, or service status.
    OWNED_CONFIG_DIR=0
    OWNED_STATE_DIR=0
    OWNED_INSTALL_DIR=0
    OWNED_HOOK_DIR=0
    OWNED_UNIT=0
    local rec_path="$OPT_CONFIG_DIR/install.env"
    if [ -e "$rec_path" ] || [ -L "$rec_path" ]; then
        read_install_record "$rec_path"
        [ "$REC_USER" = "$OPT_USER" ] || die "existing record at $rec_path is for user '$REC_USER', not '$OPT_USER'"
        [ "$REC_CONFIG_DIR" = "$OPT_CONFIG_DIR" ] || die "existing record at $rec_path manages config dir '$REC_CONFIG_DIR', not '$OPT_CONFIG_DIR'"
        if [ "$REC_STATE" = "user-only" ]; then
            OWNED_CONFIG_DIR=1
            check_dedicated_managed_dirs 2
            check_unit_not_occupied
        elif [ "$REC_STATE" = "partial-uninstall" ]; then
            die "existing installation at $rec_path is in partial-uninstall state (stray VM state preserved); finish 'sudo $0 uninstall --config-dir $OPT_CONFIG_DIR' before reinstalling"
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
            check_dedicated_managed_dirs record
            if [ "$OWNED_UNIT" -ne 1 ]; then
                check_unit_not_occupied
            fi
        fi
    else
        check_dedicated_managed_dirs 0
        check_unit_not_occupied
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

    # Stop existing managed service ONLY when this installation owns that unit.
    local was_active=0
    if [ "$OWNED_UNIT" -eq 1 ] && systemctl is-active --quiet "${OPT_SERVICE}.service" 2>/dev/null; then
        was_active=1
        say "stopping existing ${OPT_SERVICE}.service"
        systemctl stop "${OPT_SERVICE}.service"
    fi

    # Reserve a fresh config directory exclusively as root BEFORE creating the
    # service account so a concurrent config-dir collision fails without
    # orphaning an unrecorded user. If ensure_service_user or the first
    # install.env write fails, cleanup_install_exit rolls back both the empty
    # reserved config dir and any user created by this invocation.
    _INSTALL_BOOTSTRAP_CFG=""
    _INSTALL_BOOTSTRAP_DIR=""
    _INSTALL_BOOTSTRAP_UNIT=""
    _INSTALL_BOOTSTRAP_USER=""
    _INSTALL_BOOTSTRAP_TARBALL=""
    trap 'cleanup_install_exit' EXIT
    if [ "$OWNED_CONFIG_DIR" -ne 1 ]; then
        reserve_fresh_dir config "$OPT_CONFIG_DIR"
        _INSTALL_BOOTSTRAP_CFG="$OPT_CONFIG_DIR"
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

    # Download, SHA-256 verify, and extract actions/runner.
    local tarball fetch_args=()
    tarball="$(mktemp /tmp/qeminga-actions-runner.XXXXXX.tar.gz)"
    _INSTALL_BOOTSTRAP_TARBALL="$tarball"
    fetch_args=(--arch "$arch" --dest "$tarball" --version "$OPT_RUNNER_VERSION")
    if [ -n "$OPT_RUNNER_SHA256" ]; then fetch_args+=(--sha256 "$OPT_RUNNER_SHA256"); fi
    if [ -n "$OPT_URL" ]; then fetch_args+=(--url "$OPT_URL"); fi
    cmd_fetch_runner "${fetch_args[@]}"

    claim_managed_dir runner OWNED_INSTALL_DIR "$OPT_INSTALL_DIR" 0755 root root "$runner_name"
    rm -rf --one-file-system -- "${OPT_INSTALL_DIR:?}/bin" "${OPT_INSTALL_DIR:?}/externals"
    tar --no-same-owner -xzf "$tarball" -C "$OPT_INSTALL_DIR"
    rm -f "$tarball"
    _INSTALL_BOOTSTRAP_TARBALL=""

    if [ "$OPT_SKIP_PACKAGES" -eq 0 ] && [ -x "$OPT_INSTALL_DIR/bin/installdependencies.sh" ]; then
        say "installing actions/runner runtime dependencies"
        "$OPT_INSTALL_DIR/bin/installdependencies.sh" >/dev/null
    fi

    # Install root-owned hooks, egress firewall gate, main-process launcher, and policy.
    say "installing root-owned job guard, egress check, launcher, and cleanup hooks"
    claim_managed_dir hook OWNED_HOOK_DIR "$OPT_HOOK_DIR" 0755 root root "$runner_name"
    write_policy_file "$OPT_CONFIG_DIR/policy.env" "$ALLOWED_REPO_SLUG"
    chown -h "root:${OPT_USER}" "$OPT_CONFIG_DIR/policy.env"
    chmod 0640 "$OPT_CONFIG_DIR/policy.env"
    write_job_started_hook "$OPT_HOOK_DIR/hook-job-started.sh"
    write_job_completed_hook "$OPT_HOOK_DIR/hook-job-completed.sh"
    write_egress_firewall_check "$OPT_HOOK_DIR/check-egress-firewall.sh"
    chown -h root:root \
        "$OPT_HOOK_DIR/hook-job-started.sh" \
        "$OPT_HOOK_DIR/hook-job-completed.sh" \
        "$OPT_HOOK_DIR/check-egress-firewall.sh"

    local launcher_name="run-runner.sh"
    if [ -n "$jit_config" ]; then
        launcher_name="run-jit.sh"
        say "installing one-shot JIT config credential (workspace: ${RESOLVED_WORK_DIR})"
        rm -f "$OPT_HOOK_DIR/run-runner.sh"
        write_jit_launcher "$OPT_HOOK_DIR/run-jit.sh"
        chown -h root:root "$OPT_HOOK_DIR/run-jit.sh"
        umask 0177
        printf '%s\n' "$jit_config" >"$OPT_CONFIG_DIR/jitconfig"
        umask 0022
        chown -h root:root "$OPT_CONFIG_DIR/jitconfig"
        chmod 0600 "$OPT_CONFIG_DIR/jitconfig"
        unset jit_config
    else
        rm -f "$OPT_HOOK_DIR/run-jit.sh"
        write_runner_launcher "$OPT_HOOK_DIR/run-runner.sh"
        chown -h root:root "$OPT_HOOK_DIR/run-runner.sh"
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

            if ! register_runner_with_rollback "$was_active" "$reg_token" "${cfg_args[@]}"; then
                unset reg_token
                die "runner registration failed"
            fi
            unset reg_token
        fi
    fi

    lock_runner_permissions

    # Install and verify the hardened systemd unit. Stage the complete unit and
    # set its owner/mode on a temporary regular file in the trusted unit dir,
    # then publish a fresh unit via hard link (`ln`, i.e. link(2)), which fails
    # atomically with EEXIST on ANY existing directory entry — including a
    # systemd mask symlink to /dev/null — without following symlinks or altering
    # target permissions. Record OWNED_UNIT=1 only after publication succeeds.
    local unit_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    unit_dir="${unit_dir%/}"
    check_abs_path "systemd unit dir" "$unit_dir"
    local unit_path="${unit_dir}/${OPT_SERVICE}.service"
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
    tmp_unit="$(mktemp "${unit_dir}/.${OPT_SERVICE}.service.XXXXXX")"
    if ! render_unit_text "$arch" | awk 'NF || prev_nf { print } { prev_nf = NF }' >"$tmp_unit" \
        || ! chown -h root:root "$tmp_unit" \
        || ! chmod 0644 "$tmp_unit"; then
        rm -f "$tmp_unit"
        die "failed to stage hardened systemd unit in '$unit_dir'"
    fi
    if [ "$OWNED_UNIT" -ne 1 ]; then
        if ! ln -- "$tmp_unit" "$unit_path" 2>/dev/null; then
            rm -f "$tmp_unit"
            die "refusing to overwrite unexpected existing systemd unit '$unit_path'"
        fi
        rm -f "$tmp_unit"
        _INSTALL_BOOTSTRAP_UNIT="$unit_path"
        OWNED_UNIT=1
        write_install_record "$OPT_CONFIG_DIR/install.env" "$runner_name" "installing"
        _INSTALL_BOOTSTRAP_UNIT=""
    else
        if ! mv -f -- "$tmp_unit" "$unit_path"; then
            rm -f "$tmp_unit"
            die "failed to update owned systemd unit '$unit_path'"
        fi
    fi

    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze verify --man=no "$unit_path" || die "systemd-analyze verify failed for $unit_path"
    fi

    systemctl daemon-reload
    if [ "$OPT_NO_START" -eq 0 ]; then
        # Because the unit uses Type=notify (NotifyAccess=main), systemctl waits
        # until the launcher passes check-egress-firewall.sh and sends READY=1
        # (or exits non-zero immediately if the firewall gate rejects the host).
        if [ "$OPT_EPHEMERAL" -eq 1 ]; then
            systemctl start "${OPT_SERVICE}.service"
            say "${OPT_SERVICE}.service started and passed egress firewall gate (ephemeral one-shot; not enabled across reboot)"
        else
            systemctl enable --now "${OPT_SERVICE}.service"
            say "${OPT_SERVICE}.service is enabled, started, and passed egress firewall gate"
        fi
    else
        say "--no-start set; inspect ${unit_path}, then run: sudo systemctl enable --now ${OPT_SERVICE}.service"
    fi

    # Finalize installation record state only after unit verification & startup
    # readiness (unless --no-start) succeed.
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

cmd_update() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "update must run as root"

    # Refuse to modify any service or directory without a valid root-owned
    # installation record matching CLI options and live user UID/GID.
    load_and_verify_install_record update

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

_UNINSTALL_TEMP_RT=""

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
    ' _ "$rt_dir" "$force_kill" || true
}

cleanup_uninstall_temp_rt() {
    local rt="${_UNINSTALL_TEMP_RT:-}"
    [ -n "$rt" ] || return 0
    _UNINSTALL_TEMP_RT=""
    stop_temp_session_libvirt_daemons "$rt" 1 || true
    rm -rf --one-file-system -- "$rt"
}

cmd_uninstall() {
    parse_common_opts "$@"
    [ "$(id -u)" -eq 0 ] || die "uninstall must run as root"

    # Refuse to run any cleanup, chown, token handoff, or deletion without a
    # valid root-owned installation record and matching live user UID/GID.
    load_and_verify_install_record uninstall

    # Handle a retained user-only record from a prior uninstall without --purge-user.
    if [ "$REC_STATE" = "user-only" ]; then
        if [ "$OPT_PURGE_USER" -eq 1 ]; then
            if [ "$REC_USER_CREATED" = "1" ] && id "$OPT_USER" >/dev/null 2>&1; then
                userdel "$OPT_USER" || die "could not delete user $OPT_USER; preserving ownership record at $OPT_CONFIG_DIR/install.env"
                if getent group "$OPT_USER" >/dev/null 2>&1; then
                    groupdel "$OPT_USER" || true
                fi
            fi
            rm -rf --one-file-system -- "$OPT_CONFIG_DIR"
            echo "purged user ${OPT_USER} and removed ${OPT_CONFIG_DIR}"
        elif ! id "$OPT_USER" >/dev/null 2>&1; then
            rm -rf --one-file-system -- "$OPT_CONFIG_DIR"
            echo "removed stale user-only record in ${OPT_CONFIG_DIR}"
        else
            echo "no runner installation remains in ${OPT_CONFIG_DIR}; managed user '${OPT_USER}' (uid=${REC_USER_UID}) is preserved (pass --purge-user to remove it)"
        fi
        return 0
    fi

    local unit_dir="${QEMINGA_SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
    unit_dir="${unit_dir%/}"
    check_abs_path "systemd unit dir" "$unit_dir"
    local unit_path="${unit_dir}/${OPT_SERVICE}.service"

    # Only stop/disable the unit if this installation actually created/owns it.
    if [ "$REC_OWNED_UNIT" = "1" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl stop "${OPT_SERVICE}.service" 2>/dev/null || true
        systemctl disable "${OPT_SERVICE}.service" 2>/dev/null || true
    fi

    # Run the post-job cleanup hook as the runner user to destroy any stray
    # qeminga-e2e-* session domains before removing owned state files.
    local cleanup_rc=0
    if [ "$REC_OWNED_STATE_DIR" = "1" ] && [ "$REC_OWNED_HOOK_DIR" = "1" ] \
        && command -v runuser >/dev/null 2>&1 && id "$OPT_USER" >/dev/null 2>&1 \
        && [ -x "$OPT_HOOK_DIR/hook-job-completed.sh" ] && [ -f "$OPT_CONFIG_DIR/policy.env" ]; then
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
            cleanup_rt="$(mktemp -d "${runtime_root}/qeminga-uninstall.XXXXXX")"
            _UNINSTALL_TEMP_RT="$cleanup_rt"
            trap 'cleanup_uninstall_temp_rt' EXIT
            chmod 0700 "$cleanup_rt"
            chown -h "${OPT_USER}:${OPT_USER}" "$cleanup_rt"
            cleanup_rt_created=1
        fi
        say "running cleanup hook to remove stray qeminga session domains"
        if ! runuser -u "$OPT_USER" -- env -u DBUS_SESSION_BUS_ADDRESS \
            "HOME=$OPT_STATE_DIR" \
            "XDG_RUNTIME_DIR=$cleanup_rt" \
            "XDG_CONFIG_HOME=$OPT_STATE_DIR/.config" \
            "XDG_CACHE_HOME=$OPT_STATE_DIR/.cache" \
            "XDG_DATA_HOME=$OPT_STATE_DIR/.local/share" \
            "LIBVIRT_DEFAULT_URI=qemu:///session" \
            "QEMINGA_RUNNER_POLICY=$OPT_CONFIG_DIR/policy.env" \
            "$OPT_HOOK_DIR/hook-job-completed.sh" --domains-only; then
            cleanup_rc=1
            warn "cleanup hook could not confirm all qeminga domains are gone; preserving $OPT_STATE_DIR/images"
        fi
        if [ "$cleanup_rt_created" -eq 1 ]; then
            cleanup_uninstall_temp_rt
            trap - EXIT
        elif [ "$cleanup_rc" -eq 0 ]; then
            stop_temp_session_libvirt_daemons "$cleanup_rt" 0 || true
        fi
    elif [ "$REC_OWNED_STATE_DIR" = "1" ] && [ -d "$OPT_STATE_DIR/images" ]; then
        local leftover=""
        shopt -s nullglob
        for leftover in "$OPT_STATE_DIR/images"/qeminga-e2e-*; do
            [ -e "$leftover" ] && cleanup_rc=1 && break
        done
        shopt -u nullglob
        if [ "$cleanup_rc" -ne 0 ]; then
            warn "cleanup hook unavailable while VM directories remain under $OPT_STATE_DIR/images; preserving $OPT_STATE_DIR/images"
        fi
    fi

    # Optional deregistration from GitHub if a removal token was supplied (only
    # when this installation actually owns OPT_INSTALL_DIR).
    if [ "$REC_OWNED_INSTALL_DIR" = "1" ] && [ -n "$OPT_TOKEN_FILE" ] \
        && [ ! -L "$OPT_INSTALL_DIR" ] && [ ! -L "$OPT_INSTALL_DIR/config.sh" ] \
        && [ -x "$OPT_INSTALL_DIR/config.sh" ] && id "$OPT_USER" >/dev/null 2>&1; then
        command -v runuser >/dev/null 2>&1 || die "runuser is required to deregister the runner as $OPT_USER"
        local rm_token
        rm_token="$(read_secret_file --token-file "$OPT_TOKEN_FILE")"
        say "deregistering runner from GitHub"
        chown -h -R -P "${OPT_USER}:${OPT_USER}" "$OPT_INSTALL_DIR"
        run_runner_config_with_token "$rm_token" remove --unattended \
            || warn "deregistration failed (remove manually in GitHub Settings -> Actions -> Runners)"
        unset rm_token
    elif [ "$REC_OWNED_INSTALL_DIR" != "1" ] && [ -n "$OPT_TOKEN_FILE" ]; then
        warn "skipping runner deregistration: $OPT_INSTALL_DIR is not owned by this installation (already removed or never created)"
    fi

    # Persist each resource's release (RECORD_STATE=partial-uninstall with its
    # OWNED_* flag cleared to 0) BEFORE unlinking/removing the resource and
    # BEFORE daemon-reload, so a failed record write leaves the resource intact
    # and an interrupted removal never lets a retry act on an independently
    # created replacement service or directory.
    if [ "$REC_OWNED_UNIT" = "1" ]; then
        REC_OWNED_UNIT="0"
        write_uninstall_record "$OPT_CONFIG_DIR/install.env"
        if [ ! -L "$unit_path" ]; then
            rm -f "$unit_path"
        else
            warn "refusing to remove symlinked systemd unit path '$unit_path'"
        fi
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi
    fi

    if [ "$REC_OWNED_INSTALL_DIR" = "1" ]; then
        REC_OWNED_INSTALL_DIR="0"
        write_uninstall_record "$OPT_CONFIG_DIR/install.env"
        rm -rf --one-file-system -- "$OPT_INSTALL_DIR"
    fi

    if [ "$cleanup_rc" -eq 0 ]; then
        if [ "$REC_OWNED_HOOK_DIR" = "1" ]; then
            REC_OWNED_HOOK_DIR="0"
            write_uninstall_record "$OPT_CONFIG_DIR/install.env"
            rm -rf --one-file-system -- "$OPT_HOOK_DIR"
        fi
        if [ "$REC_OWNED_STATE_DIR" = "1" ]; then
            REC_OWNED_STATE_DIR="0"
            write_uninstall_record "$OPT_CONFIG_DIR/install.env"
            rm -rf --one-file-system -- "$OPT_STATE_DIR"
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
            rm -rf --one-file-system -- "$OPT_CONFIG_DIR"
        else
            # Retain a minimal UID/GID ownership record while the managed
            # account survives uninstall so a subsequent default install or a
            # later `uninstall --purge-user` can verify and manage it safely.
            find "$OPT_CONFIG_DIR" -mindepth 1 -maxdepth 1 ! -name 'install.env' \
                -exec rm -rf --one-file-system -- {} +
            write_user_only_record "$OPT_CONFIG_DIR/install.env" \
                "$OPT_USER" "$REC_USER_UID" "$REC_USER_GID" "$REC_USER_CREATED" "$OPT_CONFIG_DIR"
            chown -h root:root "$OPT_CONFIG_DIR"
            chmod 0700 "$OPT_CONFIG_DIR"
        fi
        echo "uninstalled ${OPT_SERVICE}"
    else
        # Preserve images/, libvirt session .config/, hooks, and config in
        # partial-uninstall state (with unit and runner dir already released) so
        # the operator can inspect domains and re-run uninstall safely.
        write_uninstall_record "$OPT_CONFIG_DIR/install.env"
        if [ "$REC_OWNED_STATE_DIR" = "1" ]; then
            rm -rf --one-file-system -- \
                "$OPT_STATE_DIR/work" "$OPT_STATE_DIR/image-cache" \
                "$OPT_STATE_DIR/.cache" "$OPT_STATE_DIR/.local"
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
        uninstall) cmd_uninstall "$@" ;;
        -h | --help) usage ;;
        *) die "unknown subcommand '$sub' (run with --help)" ;;
    esac
fi
