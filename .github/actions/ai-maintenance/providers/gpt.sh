# shellcheck shell=bash
# Provider "gpt": OpenAI Codex CLI (`codex exec`) with an OpenAI API key.
# Pool options: "model" ("<model> [effort]": -m, model_reasoning_effort, with
# "max" mapped to "xhigh", the highest Codex accepts), "base_url"
# (OPENAI_BASE_URL).
# Version: CODEX_VERSION (npm @openai/codex).

# shellcheck disable=SC2034 # read by run.sh
PROVIDER_EXHAUSTED_REGEX='insufficient_quota|exceeded your current quota|incorrect api key'
# shellcheck disable=SC2034 # read by run.sh
PROVIDER_INSTALL_ENV='CODEX_VERSION'

gpt_dir() { printf '%s/codex' "$AI_TOOLS_DIR"; }

provider_install() {
    ai_npm_install "$(gpt_dir)" "@openai/codex@${CODEX_VERSION:-0.167.0}"
}

# provider_run KEY PROMPT_FILE FINAL_FILE MODEL OPTIONS_JSON EFFORT
provider_run() {
    local key=$1 prompt=$2 final=$3 model=$4 options=$5 effort=${6:-} base_url
    # The runner is the sandbox: Codex's own sandbox would block the
    # network and writes outside the checkout that builds need.
    local -a args=(exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check
        --ephemeral --color never -o "$final")
    [ -n "$model" ] && args+=(-m "$model")
    if [ "$effort" = max ]; then
        effort=xhigh
        ai_report_effort xhigh
    fi
    [ -n "$effort" ] && args+=(-c "model_reasoning_effort=\"$effort\"")
    base_url=$(jq -r '.base_url // ""' <<<"$options")
    mkdir -p "$AI_ATTEMPT_DIR/codex-home"
    local -a extra=()
    [ -n "$base_url" ] && extra+=(OPENAI_BASE_URL="$base_url")
    # The key is exported, never an argument (see claude.sh).
    (
        unset OPENAI_BASE_URL OPENAI_ORG_ID OPENAI_PROJECT_ID
        [ "${#extra[@]}" -eq 0 ] || export "${extra[@]}"
        export OPENAI_API_KEY="$key" CODEX_API_KEY="$key" CODEX_HOME="$AI_ATTEMPT_DIR/codex-home"
        exec "$(gpt_dir)/node_modules/.bin/codex" "${args[@]}" - <"$prompt"
    )
}
