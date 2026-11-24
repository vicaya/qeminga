# shellcheck shell=bash
# Provider "gpt": OpenAI Codex CLI (`codex exec`) with an OpenAI API key.
# Pool options: "model", "base_url" (OPENAI_BASE_URL, for a gateway).
# Version: CODEX_VERSION (npm @openai/codex).

# shellcheck disable=SC2034 # read by run.sh
PROVIDER_EXHAUSTED_REGEX='insufficient_quota|exceeded your current quota|incorrect api key'

gpt_dir() { printf '%s/codex' "$AI_TOOLS_DIR"; }

provider_install() {
    ai_npm_install "$(gpt_dir)" "@openai/codex@${CODEX_VERSION:-0.167.0}"
}

# provider_run KEY PROMPT_FILE FINAL_FILE MODEL OPTIONS_JSON
provider_run() {
    local key=$1 prompt=$2 final=$3 model=$4 options=$5 base_url
    # The runner is the sandbox: Codex's own sandbox would block the
    # network and writes outside the checkout that builds need.
    local -a args=(exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check
        --ephemeral --color never -o "$final")
    [ -n "$model" ] && args+=(-m "$model")
    base_url=$(jq -r '.base_url // ""' <<<"$options")
    mkdir -p "$AI_ATTEMPT_DIR/codex-home"
    local -a extra=()
    [ -n "$base_url" ] && extra+=(OPENAI_BASE_URL="$base_url")
    env -u OPENAI_BASE_URL -u OPENAI_ORG_ID -u OPENAI_PROJECT_ID "${extra[@]}" \
        OPENAI_API_KEY="$key" CODEX_API_KEY="$key" \
        CODEX_HOME="$AI_ATTEMPT_DIR/codex-home" \
        "$(gpt_dir)/node_modules/.bin/codex" "${args[@]}" - <"$prompt"
}
