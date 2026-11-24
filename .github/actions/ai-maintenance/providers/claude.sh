# shellcheck shell=bash
# Provider "claude": Claude Code CLI (`claude -p`) with an Anthropic API key.
# Pool options: "model", "effort" (--effort), "base_url" (ANTHROPIC_BASE_URL,
# for a gateway).
# Version: CLAUDE_CODE_VERSION (npm @anthropic-ai/claude-code).

# shellcheck disable=SC2034 # read by run.sh
PROVIDER_EXHAUSTED_REGEX='credit balance is too low|rate_limit_error|overloaded_error|invalid x-api-key'

claude_dir() { printf '%s/claude' "$AI_TOOLS_DIR"; }

provider_install() {
    ai_npm_install "$(claude_dir)" "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION:-2.1.319}"
}

# provider_run KEY PROMPT_FILE FINAL_FILE MODEL OPTIONS_JSON EFFORT
provider_run() {
    local key=$1 prompt=$2 final=$3 model=$4 options=$5 effort=${6:-} stream rc base_url
    local -a args=(-p --output-format stream-json --verbose --dangerously-skip-permissions)
    [ -n "$model" ] && args+=(--model "$model")
    [ -n "$effort" ] && args+=(--effort "$effort")
    base_url=$(jq -r '.base_url // ""' <<<"$options")
    stream="$AI_ATTEMPT_DIR/claude.jsonl"
    mkdir -p "$AI_ATTEMPT_DIR/claude-config"
    local -a extra=()
    [ -n "$base_url" ] && extra+=(ANTHROPIC_BASE_URL="$base_url")
    # Claude Code refuses to skip permissions as root outside a sandbox;
    # a root self-hosted runner is the sandbox here.
    [ "$(id -u)" = 0 ] && extra+=(IS_SANDBOX=1)
    # Only the pool key may authenticate: drop any other Anthropic
    # credential or endpoint the runner's environment might carry. The
    # JSON stream is kept for the log; a readable trace goes to stdout.
    env -u ANTHROPIC_AUTH_TOKEN -u CLAUDE_CODE_OAUTH_TOKEN -u ANTHROPIC_BASE_URL \
        -u CLAUDE_CODE_USE_BEDROCK -u CLAUDE_CODE_USE_VERTEX "${extra[@]}" \
        ANTHROPIC_API_KEY="$key" \
        CLAUDE_CONFIG_DIR="$AI_ATTEMPT_DIR/claude-config" \
        DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
        "$(claude_dir)/node_modules/.bin/claude" "${args[@]}" <"$prompt" |
        tee "$stream" |
        jq --unbuffered -Rr 'fromjson? |
            if .type == "assistant" then .message.content[]?
                | if .type == "text" then .text elif .type == "tool_use" then "→ \(.name)" else empty end
            elif .type == "result" and .is_error then "error: \(.result // .subtype)"
            else empty end'
    rc=${PIPESTATUS[0]}
    jq -Rrs '[split("\n")[] | fromjson? | select(.type == "result")] | last | .result // empty' \
        "$stream" >"$final" || true
    if [ "$rc" -eq 0 ] && jq -Rse '[split("\n")[] | fromjson? | select(.type == "result")] | last | .is_error == true' \
        "$stream" >/dev/null; then
        rc=1
    fi
    # The CLI's own error, for run.sh to classify (see AI_EXHAUSTED_REGEX).
    jq -Rr 'fromjson? | select(.type == "result" and .is_error) | "\(.subtype // "") \(.result // "")"' \
        "$stream" >"$AI_ATTEMPT_DIR/error.txt" || true
    return "$rc"
}
