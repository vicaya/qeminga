# shellcheck shell=bash
# Provider "gemini": Google Antigravity CLI (`agy -p`) with a Gemini API key
# (settings modelProvider=gemini + GEMINI_API_KEY, the documented headless
# setup). Pool options: "model", "base_url" (GOOGLE_GEMINI_BASE_URL).
#
# Install: the platform manifest of Google's installer
# (https://antigravity.google/cli/install.sh) names the latest build and
# its SHA-512; the archive is verified before use. Pin a build with
# AGY_DOWNLOAD_URL and AGY_SHA512 together.

# shellcheck disable=SC2034 # read by run.sh
PROVIDER_EXHAUSTED_REGEX='"retryable":true|unavailable'
AGY_MANIFEST_BASE=${AGY_MANIFEST_BASE:-https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests}

gemini_dir() { printf '%s/agy' "$AI_TOOLS_DIR"; }

gemini_platform() {
    local os arch
    case "$(uname -s)" in
        Linux) os=linux ;;
        Darwin) os=darwin ;;
        *) return 1 ;;
    esac
    case "$(uname -m)" in
        x86_64 | amd64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) return 1 ;;
    esac
    if [ "$os" = linux ] && { [ -e /lib/libc.musl-x86_64.so.1 ] || [ -e /lib/libc.musl-aarch64.so.1 ]; }; then
        printf '%s_%s_musl' "$os" "$arch"
    else
        printf '%s_%s' "$os" "$arch"
    fi
}

provider_install() {
    local dir url sha platform manifest got
    dir=$(gemini_dir)
    [ -x "$dir/agy" ] && return 0
    mkdir -p "$dir"
    if [ -n "${AGY_DOWNLOAD_URL:-}" ]; then
        url=$AGY_DOWNLOAD_URL sha=${AGY_SHA512:-}
        [ -n "$sha" ] || { ai_log "AGY_DOWNLOAD_URL needs AGY_SHA512"; return 1; }
    else
        platform=$(gemini_platform) || { ai_log "agy: unsupported platform"; return 1; }
        manifest=$(curl -fsSL --retry 3 "$AGY_MANIFEST_BASE/$platform.json") || return 1
        url=$(jq -r '.url // ""' <<<"$manifest")
        sha=$(jq -r '.sha512 // ""' <<<"$manifest")
        ai_log "agy: release $(jq -r '.version // "?"' <<<"$manifest") for $platform"
    fi
    case "$url" in
        https://*) ;;
        *) ai_log "agy: refusing non-HTTPS download URL"; return 1 ;;
    esac
    curl -fsSL --retry 3 -o "$dir/pkg" "$url" || return 1
    got=$(sha512sum "$dir/pkg" 2>/dev/null || shasum -a 512 "$dir/pkg")
    if [ "${got%% *}" != "$(printf '%s' "$sha" | tr 'A-F' 'a-f')" ]; then
        ai_log "agy: SHA-512 mismatch; not installing"
        return 1
    fi
    case "$url" in
        *.tar.gz*) tar -xzf "$dir/pkg" -C "$dir" antigravity && mv "$dir/antigravity" "$dir/agy" ;;
        *) mv "$dir/pkg" "$dir/agy" ;;
    esac
    rm -f "$dir/pkg"
    chmod +x "$dir/agy"
}

# provider_run KEY PROMPT_FILE FINAL_FILE MODEL OPTIONS_JSON
provider_run() {
    local key=$1 prompt=$2 final=$3 model=$4 options=$5 stream rc base_url
    # Headless: Gemini API key, never wait for an artifact review.
    local settings='{"modelProvider":"gemini","artifactReviewPolicy":"always-proceed","showTips":false,"showFeedbackSurvey":false}'
    local -a args=(-p "$(cat "$prompt")" --settings "$settings" --dangerously-skip-permissions
        --disable-slash-commands --output-format stream-json)
    [ -n "$model" ] && args+=(--model "$model")
    base_url=$(jq -r '.base_url // ""' <<<"$options")
    stream="$AI_ATTEMPT_DIR/agy.jsonl"
    local -a extra=()
    [ -n "$base_url" ] && extra+=(GOOGLE_GEMINI_BASE_URL="$base_url")
    env -u GOOGLE_API_KEY -u GOOGLE_GEMINI_BASE_URL -u AGY_ADC_AUTH "${extra[@]}" \
        GEMINI_API_KEY="$key" \
        "$(gemini_dir)/agy" "${args[@]}" </dev/null |
        tee "$stream" |
        jq --unbuffered -Rr 'fromjson? |
            if .event == "step_update" then "· \(.step_update.step_type) \(.step_update.state)"
            elif .event == "result" then
                (if .result.status == "ERROR" then "error: \(.result.error)" else "result: \(.result.status)" end)
            else empty end'
    rc=${PIPESTATUS[0]}
    jq -Rrs '[split("\n")[] | fromjson? | select(.event == "result")] | last | .result.response // empty' \
        "$stream" >"$final" || true
    if [ "$rc" -eq 0 ] && jq -Rse '[split("\n")[] | fromjson? | select(.event == "result")] | last | .result.status == "ERROR"' \
        "$stream" >/dev/null; then
        rc=1
    fi
    jq -Rr 'fromjson? | select(.event == "result" and .result.status == "ERROR") | .result.error // ""' \
        "$stream" >"$AI_ATTEMPT_DIR/error.txt" || true
    return "$rc"
}
