#!/usr/bin/env bash
# Shared candidate-artifact verification, pinned guest-image metadata, and
# SHA-256-verified image fetch logic for both the hosted TCG smoke lane
# (scripts/ci/libvirt-tcg-smoke.sh) and the self-hosted KVM smoke lane
# (scripts/ci/libvirt-kvm-smoke.sh).
#
# Keeping these pins and verification routines in one file ensures any update
# to artifact verification, packaging files, or guest image pins reaches both
# lanes in one change. Connection setup, domain XML, and accelerator proofs
# stay specific to each lane script.
#
# Expects the sourcing lane script to define:
#   REPO  — repository root path
#   die() — fatal error logger + exit 1
#   say() — stage logger

# shellcheck disable=SC2034 # consumed by sourcing lane scripts
SOURCE_REPOSITORY="vicaya/qeminga"
# shellcheck disable=SC2034 # consumed by sourcing lane scripts
BUILD_COMMAND="cargo build --release --locked --features seccomp"
PACKAGING_FILES="packaging/systemd/qeminga.service packaging/udev/99-qeminga.rules packaging/sysusers.d/qeminga.conf packaging/tmpfiles.d/qeminga.conf packaging/config.toml packaging/config-data-protection.toml"

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

# shellcheck disable=SC2034 # consumed by sourcing lane scripts
NO_DIGEST="$(printf '0%.0s' {1..64})"

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

# ---- guest image ----------------------------------------------------------

# The first of the cache and the sources whose bytes have the expected
# digest becomes DEST (and fills the cache); nothing else is ever used.
# A partial or rejected download is removed before failing or trying the next URL.
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
            rm -f "$tmp"
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
