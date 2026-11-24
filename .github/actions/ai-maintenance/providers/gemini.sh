# shellcheck shell=bash
# Provider "gemini": Google Antigravity CLI (`agy -p`) with a Gemini API key
# (settings modelProvider=gemini + GEMINI_API_KEY, the documented headless
# setup). Pool options: "model" ("<model> [effort]": --model, --effort; a
# level the model does not offer falls back to the nearest one it does),
# "base_url" (GOOGLE_GEMINI_BASE_URL).
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

# gemini_agy PROMPT_FILE MODEL EFFORT STREAM -> runs agy once; stderr is
# kept in $AI_ATTEMPT_DIR/agy.err and echoed.
gemini_agy() {
    local prompt=$1 model=$2 effort=$3 stream=$4 rc
    # Headless: Gemini API key, never wait for an artifact review.
    local settings='{"modelProvider":"gemini","artifactReviewPolicy":"always-proceed","showTips":false,"showFeedbackSurvey":false}'
    local -a args=(-p "$(cat "$prompt")" --settings "$settings" --dangerously-skip-permissions
        --disable-slash-commands --output-format stream-json)
    [ -n "$model" ] && args+=(--model "$model")
    [ -n "$effort" ] && args+=(--effort "$effort")
    env -u GOOGLE_API_KEY -u GOOGLE_GEMINI_BASE_URL -u AGY_ADC_AUTH "${GEMINI_EXTRA_ENV[@]}" \
        GEMINI_API_KEY="$GEMINI_KEY" \
        "$(gemini_dir)/agy" "${args[@]}" </dev/null 2>"$AI_ATTEMPT_DIR/agy.err" |
        tee "$stream" |
        jq --unbuffered -Rr 'fromjson? |
            if .event == "step_update" then "· \(.step_update.step_type) \(.step_update.state)"
            elif .event == "result" then
                (if .result.status == "ERROR" then "error: \(.result.error)" else "result: \(.result.status)" end)
            else empty end'
    rc=${PIPESTATUS[0]}
    cat "$AI_ATTEMPT_DIR/agy.err" >&2
    return "$rc"
}

# provider_run KEY PROMPT_FILE FINAL_FILE MODEL OPTIONS_JSON EFFORT
provider_run() {
    local key=$1 prompt=$2 final=$3 model=$4 options=$5 effort=${6:-} stream rc base_url allowed nearest
    base_url=$(jq -r '.base_url // ""' <<<"$options")
    stream="$AI_ATTEMPT_DIR/agy.jsonl"
    GEMINI_KEY=$key
    GEMINI_EXTRA_ENV=()
    [ -n "$base_url" ] && GEMINI_EXTRA_ENV+=(GOOGLE_GEMINI_BASE_URL="$base_url")
    gemini_agy "$prompt" "$model" "$effort" "$stream"
    rc=$?
    # agy checks the effort against the model before any request and names
    # the levels that model allows ("... has no "max" effort (available:
    # low, high)"); retry once with the nearest allowed level.
    allowed=$(sed -n 's/.*has no "[a-z]*" effort (available: \([a-z, ]*\)).*/\1/p' "$AI_ATTEMPT_DIR/agy.err" | head -1)
    if [ "$rc" -ne 0 ] && [ -n "$effort" ] && [ -n "$allowed" ]; then
        nearest=$(ai_nearest_effort "$effort" "$allowed")
        if [ -n "$nearest" ] && [ "$nearest" != "$effort" ]; then
            ai_log "agy: effort '$effort' is not available for this model (allowed: $allowed); using '$nearest'"
            gemini_agy "$prompt" "$model" "$nearest" "$stream"
            rc=$?
            ai_report_effort "$nearest"
        fi
    fi
    GEMINI_KEY=
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
