#!/usr/bin/env bash
# Runs one maintenance pass: picks an API key from the pool according to
# the routing strategy, runs that provider's coding-agent CLI on the
# checkout in the working directory, and falls back to the next key when
# the current one is exhausted. Writes the agent's changes as a patch
# (result-dir) for open-pr.sh, which runs in a separate job without the
# keys. See README.md.
#
# Environment:
#   AI_KEY_POOL            required, JSON (lib.sh)
#   AI_INSTRUCTIONS        the maintenance instructions (or AI_INSTRUCTIONS_FILE)
#   AI_EXTRA_PROMPT_FILE   optional Markdown appended to the prompt (review feedback)
#   AI_ROUTING             ordered (default) | round-robin
#   AI_ROUTING_SEED        rotation seed for round-robin (default GITHUB_RUN_NUMBER)
#   AI_FALLBACK_ON         exhausted (default) | any
#   AI_MODELS              optional JSON object, provider -> model
#   AI_ATTEMPT_TIMEOUT     timeout(1) duration per attempt (default 60m)
#   AI_STATE_DIR           scratch directory outside the checkout
#   AI_PROVIDERS_DIR       adapter directory (default: providers/ next to this file)
#
# Exit status: 0 when an agent finished (with or without changes), 1 when
# every candidate failed, 2 on a configuration error. Outputs (to
# GITHUB_OUTPUT when set): status=changed|unchanged|failed, provider,
# model, title, summary-file, result-dir, logs-dir, base-sha.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

group() { if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::group::$*"; else echo "== $*"; fi; }
endgroup() { if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "::endgroup::"; fi; }
out() { [ -n "${GITHUB_OUTPUT:-}" ] && printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"; return 0; }

# --- configuration --------------------------------------------------------
pool_raw=${AI_KEY_POOL:-}
instructions=${AI_INSTRUCTIONS:-}
if [ -z "$instructions" ] && [ -n "${AI_INSTRUCTIONS_FILE:-}" ]; then
    instructions=$(cat "$AI_INSTRUCTIONS_FILE") || exit 2
fi
# Nothing the agent starts may inherit the pool or other secrets.
unset AI_KEY_POOL AI_INSTRUCTIONS GH_TOKEN GITHUB_TOKEN

[ -n "$pool_raw" ] || { ai_log "AI_KEY_POOL is empty: set the repository secret"; exit 2; }
[ -n "$instructions" ] || { ai_log "no maintenance instructions: set the instructions secret"; exit 2; }

pool=$(ai_normalize_pool "$pool_raw") || exit 2
pool_raw=
keys=$(ai_all_keys "$pool")
# Keys inside the pool secret are not masked individually by GitHub.
if [ "${GITHUB_ACTIONS:-}" = true ]; then
    jq -r '.[]' <<<"$keys" | while IFS= read -r k; do printf '::add-mask::%s\n' "$k"; done
fi

routing=${AI_ROUTING:-ordered}
fallback_on=${AI_FALLBACK_ON:-exhausted}
case "$fallback_on" in exhausted | any) ;; *) ai_log "AI_FALLBACK_ON must be exhausted or any"; exit 2 ;; esac
models=${AI_MODELS:-}
[ -n "$models" ] || models='{}'
jq -e 'type == "object"' <<<"$models" >/dev/null 2>&1 || { ai_log "AI_MODELS must be a JSON object"; exit 2; }
attempt_timeout=${AI_ATTEMPT_TIMEOUT:-60m}
providers_dir=${AI_PROVIDERS_DIR:-$here/providers}
state=${AI_STATE_DIR:-${RUNNER_TEMP:-/tmp}/ai-maintenance}
mkdir -p "$state" || exit 2
export AI_TOOLS_DIR=$state/tools

candidates=$(ai_route "$pool" "$routing" "${AI_ROUTING_SEED:-${GITHUB_RUN_NUMBER:-0}}") || exit 2

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { ai_log "not inside a git checkout"; exit 2; }
base=$(git rev-parse HEAD)
out base-sha "$base"

# --- credentials the agent must not see -------------------------------------
# actions/checkout leaves a token in the repository config unless it runs
# with persist-credentials: false; the agent would be able to push with it.
strip_git_credentials() {
    local k
    for k in $(git config --local --name-only --get-regexp '^http\..*\.extraheader$' 2>/dev/null); do
        git config --local --unset-all "$k" && ai_log "removed persisted git credential ($k)"
    done
    for k in $(git config --local --name-only --get-regexp '^includeif\.' 2>/dev/null); do
        git config --local --unset-all "$k" && ai_log "removed persisted git credential include ($k)"
    done
}
strip_git_credentials

# --- prompt ---------------------------------------------------------------
prompt=$state/prompt.md
{
    cat "$here/preamble.md"
    printf '\n## Maintenance instructions\n\n%s\n' "$instructions"
    if [ -n "${AI_EXTRA_PROMPT_FILE:-}" ] && [ -s "$AI_EXTRA_PROMPT_FILE" ]; then
        printf '\n'
        cat "$AI_EXTRA_PROMPT_FILE"
    fi
} >"$prompt"
instructions=

reset_tree() {
    if [ "$(git rev-parse HEAD)" != "$base" ] || [ -n "$(git status --porcelain)" ]; then
        ai_log "resetting the working tree to $base"
        git checkout -q --detach "$base" 2>/dev/null || true
        git reset -q --hard "$base" && git clean -qfd
    fi
}

# --- attempts -------------------------------------------------------------
attempts=$state/attempts.jsonl
: >"$attempts"
record() { # provider entry key model result
    jq -nc --arg p "$1" --argjson e "$2" --argjson k "$3" --arg m "$4" --arg r "$5" \
        '{provider: $p, entry: $e, key: $k, model: $m, result: $r}' >>"$attempts"
}

n=0 winner='' winner_model='' final=''
declare -A install_failed=()
while IFS=$'\t' read -r entry keyidx provider; do
    [ -n "$entry" ] || continue
    n=$((n + 1))
    adapter_name=$(ai_canonical_provider "$provider")
    adapter=$providers_dir/$adapter_name.sh
    label="${provider}[$((keyidx + 1))]"
    if [ ! -f "$adapter" ]; then
        ai_log "attempt $n: no adapter for provider '$provider' (expected $adapter); skipping"
        record "$provider" "$entry" "$keyidx" "" unsupported
        continue
    fi
    if [ -n "${install_failed[$adapter_name]:-}" ]; then
        record "$provider" "$entry" "$keyidx" "" install-failed
        continue
    fi
    options=$(ai_options "$pool" "$entry")
    model=$(ai_model "$models" "$options" "$adapter_name")
    dir=$state/attempt-$n
    rm -rf "$dir" && mkdir -p "$dir"
    reset_tree

    group "attempt $n: $label${model:+ ($model)}"
    (
        # shellcheck source=/dev/null
        . "$adapter"
        export AI_ATTEMPT_DIR=$dir
        provider_install >"$dir/install.log" 2>&1 || { cat "$dir/install.log" >&2; exit 90; }
        # timeout(1) runs a fresh bash that loads the adapter again and
        # takes the key from the environment; on expiry it signals that
        # bash's whole process group, the agent CLI included.
        # shellcheck disable=SC2016 # expanded by the child bash
        AI_ATTEMPT_KEY=$(ai_key "$pool" "$entry" "$keyidx") AI_LIB=$here/lib.sh AI_ADAPTER=$adapter \
            timeout --kill-after=60s "$attempt_timeout" bash -c '
                . "$AI_LIB"; . "$AI_ADAPTER"
                k=$AI_ATTEMPT_KEY; unset AI_ATTEMPT_KEY AI_LIB AI_ADAPTER
                provider_run "$k" "$@"' _ "$prompt" "$dir/final.md" "$model" "$options" 2>&1
    ) | tee "$dir/attempt.log"
    rc=${PIPESTATUS[0]}
    endgroup

    if [ "$rc" -eq 90 ]; then
        ai_log "attempt $n: could not install the $adapter_name CLI; skipping its keys"
        install_failed[$adapter_name]=1
        record "$provider" "$entry" "$keyidx" "$model" install-failed
        continue
    fi
    if [ "$rc" -eq 0 ]; then
        ai_log "attempt $n: $label finished"
        record "$provider" "$entry" "$keyidx" "$model" success
        winner=$provider winner_model=$model final=$dir/final.md
        break
    fi
    # Classify on the CLI's own error and the end of the log, not on
    # everything the agent printed along the way.
    { cat "$dir/error.txt" 2>/dev/null; tail -n 200 "$dir/attempt.log"; } >"$dir/classify.txt"
    extra=$(
        # shellcheck source=/dev/null
        . "$adapter" >/dev/null 2>&1
        printf '%s' "${PROVIDER_EXHAUSTED_REGEX:-}"
    )
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        result=timeout
    elif ai_is_exhausted "$dir/classify.txt" "$extra"; then
        result=exhausted
    else
        result=failed
    fi
    record "$provider" "$entry" "$keyidx" "$model" "$result"
    if [ "$result" = exhausted ] || [ "$fallback_on" = any ]; then
        ai_log "attempt $n: $label $result (exit $rc); trying the next key"
        continue
    fi
    ai_log "attempt $n: $label $result (exit $rc); not falling back (AI_FALLBACK_ON=$fallback_on)"
    break
done <<<"$candidates"

# --- results --------------------------------------------------------------
summary=$state/summary.md
{
    if [ -n "$final" ] && [ -s "$final" ]; then cat "$final"; else echo "Nightly maintenance"; fi
} | ai_scrub "$keys" | head -c 60000 >"$summary"

# Logs for upload, with every key replaced (GitHub masks keys in the
# console only, not in files).
logs=$state/logs
rm -rf "$logs" && mkdir -p "$logs"
cp "$attempts" "$logs/attempts.jsonl"
for d in "$state"/attempt-*; do
    [ -d "$d" ] || continue
    mkdir -p "$logs/${d##*/}"
    for f in "$d"/*.log "$d"/*.jsonl "$d"/*.txt "$d"/*.md; do
        [ -f "$f" ] && ai_scrub "$keys" <"$f" >"$logs/${d##*/}/${f##*/}"
    done
done
out logs-dir "$logs"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### AI maintenance"
        echo
        echo "| # | provider | key | model | result |"
        echo "|---|---|---|---|---|"
        jq -r '"| \(input_line_number) | \(.provider) | #\(.key + 1) | \(if .model == "" then "default" else .model end) | \(.result) |"' "$attempts"
    } >>"$GITHUB_STEP_SUMMARY"
fi

if [ -z "$winner" ]; then
    reset_tree
    ai_log "no provider completed the run ($n attempts)"
    out status failed
    exit 1
fi

# Title: the first non-empty line of the agent's final message.
title=$(sed -e 's/^#* *//' -e 's/[[:space:]]*$//' "$summary" | grep -m1 -v '^$' | cut -c1-72)
[ -n "$title" ] || title="Nightly maintenance"
# The result travels to the pull-request job as files: the agent's work as
# one binary patch against the base commit (its own commits and anything
# left uncommitted), the scrubbed final message, and metadata.
result_dir=$state/result
rm -rf "$result_dir" && mkdir -p "$result_dir"
git add -A
git diff --cached --binary "$base" >"$result_dir/changes.patch"
git reset -q
if [ -s "$result_dir/changes.patch" ]; then
    status=changed
    if ai_contains_key "$keys" <"$result_dir/changes.patch"; then
        ai_log "the agent's changes contain an API key from the pool; refusing to publish them"
        rm -f "$result_dir/changes.patch"
        out status failed
        exit 1
    fi
else
    status=unchanged
    rm -f "$result_dir/changes.patch"
fi
cp "$summary" "$result_dir/summary.md"
jq -n --arg status "$status" --arg provider "$winner" --arg model "$winner_model" \
    --arg title "$title" --arg base "$base" \
    '{status: $status, provider: $provider, model: $model, title: $title, base_sha: $base}' \
    >"$result_dir/meta.json"
ai_log "result: $status (provider $winner)"
out status "$status"
out provider "$winner"
out model "$winner_model"
out title "$title"
out summary-file "$summary"
out result-dir "$result_dir"
exit 0
