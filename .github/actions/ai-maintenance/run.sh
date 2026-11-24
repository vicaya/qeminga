#!/usr/bin/env bash
# Runs one maintenance pass: picks an API key from the pool according to
# the routing strategy, runs that provider's coding-agent CLI in a fresh
# container on a copy of the checkout in the working directory, and falls
# back to the next key when the current one is exhausted. Writes the
# agent's changes as a patch (result-dir) for publish.sh, which runs in a
# separate job without the keys. See README.md.
#
# Isolation: this script holds the pool and never runs agent code. Each
# attempt gets its own container from an image built once per run, with
# only its own key, its own copy of the checkout and an output directory;
# nothing of the runner (its files, processes, credentials or the other
# keys) is visible inside, and the agent is an unprivileged user there.
# The agent's tree, git configuration included, is only ever read inside a
# container; the runner reads the plain files the attempt left (never
# through a symlink) and checks the exported patch by applying it to its
# own copy.
#
# Environment:
#   AI_KEY_POOL            required, JSON (lib.sh)
#   AI_INSTRUCTIONS        the maintenance instructions (or AI_INSTRUCTIONS_FILE)
#   AI_PRIVATE_INSTRUCTIONS  true: publish no free-form agent text and no
#                          transcripts (the instructions stay unpublished)
#   AI_EXTRA_PROMPT_FILE   optional Markdown appended to the prompt (review feedback)
#   AI_ROUTING             ordered (default) | round-robin
#   AI_ROUTING_SEED        rotation seed for round-robin (default GITHUB_RUN_NUMBER)
#   AI_FALLBACK_ON         exhausted (default) | any
#   AI_MODELS              optional JSON object, provider -> "<model> [effort]"
#                          (effort: low, medium, high, xhigh, max)
#   AI_ATTEMPT_TIMEOUT     timeout(1) duration per attempt (default 60m)
#   AI_SANDBOX_IMAGE       base image of the attempt containers (default ubuntu:24.04)
#   AI_SANDBOX_SETUP       shell script run as root while building the image,
#                          in a throwaway copy of the checkout (repository tools)
#   AI_STATE_DIR           scratch directory outside the checkout
#   AI_PROVIDERS_DIR       adapter directory (default: providers/ next to this file)
#
# Exit status: 0 when an agent finished (with or without changes), 1 when
# every candidate failed, 2 on a configuration error. Outputs (to
# GITHUB_OUTPUT when set): status=changed|unchanged|failed, provider,
# model, effort (the one the CLI used), title, summary-file, result-dir,
# logs-dir, base-sha.
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
unset AI_KEY_POOL AI_INSTRUCTIONS GH_TOKEN GITHUB_TOKEN

[ -n "$pool_raw" ] || { ai_log "AI_KEY_POOL is empty: set the repository secret"; exit 2; }
[ -n "$instructions" ] || { ai_log "no maintenance instructions: set the instructions secret"; exit 2; }

pool=$(ai_normalize_pool "$pool_raw") || exit 2
pool_raw=
keys=$(ai_all_keys "$pool")
# Everything withheld from published output: the keys and the instructions.
secrets=$(ai_secret_fragments "$instructions" | jq -c --argjson k "$keys" '$k + .')
# Keys inside the pool secret are not masked individually by GitHub.
if [ "${GITHUB_ACTIONS:-}" = true ]; then
    jq -r '.[] | select(test("\n") | not)' <<<"$secrets" | while IFS= read -r k; do printf '::add-mask::%s\n' "$k"; done
fi

routing=${AI_ROUTING:-ordered}
fallback_on=${AI_FALLBACK_ON:-exhausted}
case "$fallback_on" in exhausted | any) ;; *) ai_log "AI_FALLBACK_ON must be exhausted or any"; exit 2 ;; esac
private=${AI_PRIVATE_INSTRUCTIONS:-false}
case "$private" in true | false) ;; *) ai_log "AI_PRIVATE_INSTRUCTIONS must be true or false"; exit 2 ;; esac
models=$(ai_normalize_models "${AI_MODELS:-}") || exit 2
attempt_timeout=${AI_ATTEMPT_TIMEOUT:-60m}
providers_dir=$(cd "${AI_PROVIDERS_DIR:-$here/providers}" && pwd) || exit 2
state=${AI_STATE_DIR:-${RUNNER_TEMP:-/tmp}/ai-maintenance}
mkdir -p "$state" && state=$(cd "$state" && pwd) || exit 2
export AI_TOOLS_DIR=$state/tools
mkdir -p "$AI_TOOLS_DIR" || exit 2
image=${AI_SANDBOX_IMAGE:-ubuntu:24.04}
case "$image" in
    '' | *[!A-Za-z0-9._/:@-]*) ai_log "AI_SANDBOX_IMAGE must be an image reference"; exit 2 ;;
esac
command -v docker >/dev/null || { ai_log "docker is required: every attempt runs in a container"; exit 2; }

candidates=$(ai_route "$pool" "$routing" "${AI_ROUTING_SEED:-${GITHUB_RUN_NUMBER:-0}}") || exit 2

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { ai_log "not inside a git checkout"; exit 2; }
top=$(git rev-parse --show-toplevel)
subdir=$(git rev-parse --show-prefix)
base=$(git rev-parse HEAD)
out base-sha "$base"

attempts=$state/attempts.jsonl
: >"$attempts"
record() { # provider entry key model effort effort_used result
    jq -nc --arg p "$1" --argjson e "$2" --argjson k "$3" --arg m "$4" --arg f "$5" --arg u "$6" --arg r "$7" \
        '{provider: $p, entry: $e, key: $k, model: $m, effort: $f, effort_used: $u, result: $r}' >>"$attempts"
}

# --- the sandbox image ---------------------------------------------------------
image_tag=ai-maintenance-agent:${GITHUB_RUN_ID:-local}-$$
build_image() {
    local ctx=$state/image
    rm -rf "$ctx" && mkdir -p "$ctx" || return 1
    printf '%s\n' "${AI_SANDBOX_SETUP:-}" >"$ctx/setup.sh"
    # The setup script runs in a throwaway, writable copy of the checkout
    # at /repo (for files such as rust-toolchain.toml) and may leave
    # KEY=VALUE lines in /etc/ai-maintenance/env for the attempts.
    cat >"$ctx/Dockerfile" <<EOF
FROM $image
RUN if command -v apt-get >/dev/null; then \\
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \\
        bash ca-certificates git jq procps >/dev/null && rm -rf /var/lib/apt/lists/*; \\
    fi; mkdir -p /etc/ai-maintenance && touch /etc/ai-maintenance/env
COPY setup.sh /usr/local/share/ai-maintenance/setup.sh
RUN --mount=type=bind,from=repo,target=/repo,rw cd /repo && bash -euo pipefail /usr/local/share/ai-maintenance/setup.sh
EOF
    docker build -t "$image_tag" --build-context repo="$top" "$ctx"
}
group "building the sandbox image from $image"
build_image
build_rc=$?
endgroup
if [ "$build_rc" -ne 0 ]; then
    ai_log "the sandbox image did not build; no attempt was made"
    out status failed
    exit 1
fi
trap 'docker image rm -f "$image_tag" >/dev/null 2>&1' EXIT

# docker run arguments shared by the attempt and export containers: an
# unprivileged user without capabilities, the action's scripts read-only,
# and every path mounted at the place it has on the runner.
# The agent never runs as root: on a runner that does (a root self-hosted
# runner, the privileged test suite) it gets an unprivileged id and its
# directories are handed to that id.
uid_gid="$(id -u):$(id -g)"
[ "$(id -u)" = 0 ] && uid_gid=${AI_SANDBOX_USER:-65532:65532}
own() { [ "$(id -u)" != 0 ] || chown -R "$uid_gid" "$@"; }
container_args() { # NAME WORKDIR -> sets docker_args
    docker_args=(run --rm --init --name "$1" --user "$uid_gid" --cap-drop ALL
        --security-opt no-new-privileges -v "$here:$here:ro" -w "$2")
}
# The runner's Node.js, for the npm-installed CLIs, as one read-only file.
node_args=()
if node=$(command -v node 2>/dev/null) && node=$(readlink -f "$node") && [ -f "$node" ]; then
    node_args=(-v "$node:/opt/ai-maintenance/node/bin/node:ro" -e AI_NODE_BIN=/opt/ai-maintenance/node/bin)
fi
providers_args=()
case "$providers_dir/" in "$here/"*) ;; *) providers_args=(-v "$providers_dir:$providers_dir:ro") ;; esac

# --- prompt ---------------------------------------------------------------
prompt_dir=$state/prompt
rm -rf "$prompt_dir" && mkdir -p "$prompt_dir"
prompt=$prompt_dir/prompt.md
{
    cat "$here/preamble.md"
    printf '\n## Maintenance instructions\n\n%s\n' "$instructions"
    if [ -n "${AI_EXTRA_PROMPT_FILE:-}" ] && [ -s "$AI_EXTRA_PROMPT_FILE" ]; then
        printf '\n'
        cat "$AI_EXTRA_PROMPT_FILE"
    fi
} >"$prompt"
instructions=

# A fresh copy of the checkout for each attempt. actions/checkout leaves a
# token in the repository config unless it runs with persist-credentials:
# false; the copy never carries one.
fresh_tree() { # dir
    rm -rf "$1" && cp -a "$top/." "$1" || return 1
    local k
    for k in $(git -C "$1" config --local --name-only --get-regexp '^(http\..*\.extraheader|includeif\..*)$' 2>/dev/null); do
        git -C "$1" config --local --unset-all "$k"
    done
    return 0
}

# --- attempts -------------------------------------------------------------
n=0 winner='' winner_model='' winner_effort='' winner_dir=''
declare -A install_failed=()
while IFS=$'\t' read -r entry keyidx provider; do
    [ -n "$entry" ] || continue
    n=$((n + 1))
    adapter_name=$(ai_canonical_provider "$provider")
    adapter=$providers_dir/$adapter_name.sh
    label="${provider}[$((keyidx + 1))]"
    if [ ! -f "$adapter" ]; then
        ai_log "attempt $n: no adapter for provider '$provider' (expected $adapter); skipping"
        record "$provider" "$entry" "$keyidx" "" "" "" unsupported
        continue
    fi
    if [ -n "${install_failed[$adapter_name]:-}" ]; then
        record "$provider" "$entry" "$keyidx" "" "" "" install-failed
        continue
    fi
    options=$(ai_options "$pool" "$entry")
    pair=$(ai_parse_model_spec "$(ai_model "$models" "$options" "$adapter_name")") || exit 2
    model=${pair%%$'\t'*} effort=${pair#*$'\t'}
    dir=$state/attempt-$n
    rm -rf "$dir" && mkdir -p "$dir/out/home"

    # The CLI is installed on the runner (no key involved) and mounted
    # read-only.
    if ! (
        # shellcheck source=/dev/null
        . "$adapter"
        provider_install
    ) >"$dir/install.log" 2>&1; then
        cat "$dir/install.log" >&2
        ai_log "attempt $n: could not install the $adapter_name CLI; skipping its keys"
        install_failed[$adapter_name]=1
        record "$provider" "$entry" "$keyidx" "$model" "$effort" "" install-failed
        continue
    fi
    if ! fresh_tree "$dir/tree" || ! own "$dir/tree" "$dir/out"; then
        ai_log "attempt $n: could not copy the checkout"
        record "$provider" "$entry" "$keyidx" "$model" "$effort" "" failed
        break
    fi

    group "attempt $n: $label${model:+ model $model}${effort:+ effort $effort}"
    cname=ai-maintenance-${GITHUB_RUN_ID:-local}-$$-$n
    container_args "$cname" "$dir/tree/$subdir"
    docker_args+=(-e AI_ATTEMPT_KEY -e "AI_ATTEMPT_DIR=$dir/out" -e "AI_TOOLS_DIR=$AI_TOOLS_DIR"
        -e "HOME=$dir/out/home" -v "$dir/tree:$dir/tree" -v "$dir/out:$dir/out"
        -v "$AI_TOOLS_DIR:$AI_TOOLS_DIR:ro" -v "$prompt_dir:$prompt_dir:ro"
        "${providers_args[@]}" "${node_args[@]}" "$image_tag"
        bash "$here/attempt.sh" "$adapter" "$prompt" "$model" "$options" "$effort")
    # The key reaches docker through its environment, never its arguments.
    # Private instructions: the agent's output goes to the log file only.
    if [ "$private" = true ]; then
        echo "(agent output not shown: the instructions are private)"
        AI_ATTEMPT_KEY=$(ai_key "$pool" "$entry" "$keyidx") \
            timeout --kill-after=30s "$attempt_timeout" docker "${docker_args[@]}" >"$dir/attempt.log" 2>&1
        rc=$?
    else
        AI_ATTEMPT_KEY=$(ai_key "$pool" "$entry" "$keyidx") \
            timeout --kill-after=30s "$attempt_timeout" docker "${docker_args[@]}" 2>&1 | tee "$dir/attempt.log"
        rc=${PIPESTATUS[0]}
    fi
    docker rm -f "$cname" >/dev/null 2>&1
    endgroup

    # The effort the CLI ran with, when the adapter had to change it.
    used=''
    if ai_regular_file "$dir/out/effort"; then
        used=$(head -c 16 "$dir/out/effort" | tr -d '\n')
        case "$used" in *[!a-z]*) used='' ;; esac
    fi
    [ -n "$used" ] || used=$effort
    if [ "$rc" -eq 0 ]; then
        ai_log "attempt $n: $label finished"
        record "$provider" "$entry" "$keyidx" "$model" "$effort" "$used" success
        winner=$provider winner_model=$model winner_effort=$used winner_dir=$dir
        break
    fi
    # Classify on the CLI's own error and the end of the log, not on
    # everything the agent printed along the way.
    {
        ai_regular_file "$dir/out/error.txt" && head -c 100000 "$dir/out/error.txt"
        tail -n 200 "$dir/attempt.log"
    } >"$dir/classify.txt"
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
    record "$provider" "$entry" "$keyidx" "$model" "$effort" "$used" "$result"
    rm -rf "$dir/tree"
    if [ "$result" = exhausted ] || [ "$fallback_on" = any ]; then
        ai_log "attempt $n: $label $result (exit $rc); trying the next key"
        continue
    fi
    ai_log "attempt $n: $label $result (exit $rc); not falling back (AI_FALLBACK_ON=$fallback_on)"
    break
done <<<"$candidates"

# --- results --------------------------------------------------------------
summary=$state/summary.md
final=$winner_dir/out/final.md
private_summary='Nightly maintenance

Made by the AI maintenance workflow. Its instructions are private, so the
agent'"'"'s own summary is not published: see the changes and their checks.'
{
    if [ "$private" = true ]; then
        printf '%s\n' "$private_summary"
    elif [ -n "$winner_dir" ] && ai_regular_file "$final" && [ -s "$final" ]; then
        head -c 200000 "$final"
    else
        echo "Nightly maintenance"
    fi
} | ai_scrub "$secrets" | head -c 60000 >"$summary"

# Logs for upload, with every key and the instructions withheld (GitHub
# masks secrets in the console only, not in files). Private instructions:
# the attempts table only.
logs=$state/logs
rm -rf "$logs" && mkdir -p "$logs"
cp "$attempts" "$logs/attempts.jsonl"
if [ "$private" = false ]; then
    for d in "$state"/attempt-*; do
        [ -d "$d" ] || continue
        mkdir -p "$logs/${d##*/}"
        for f in "$d"/attempt.log "$d"/install.log "$d"/out/*.jsonl "$d"/out/*.txt "$d"/out/final.md; do
            ai_regular_file "$f" && ai_scrub "$secrets" <"$f" >"$logs/${d##*/}/${f##*/}"
        done
    done
fi
out logs-dir "$logs"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### AI maintenance"
        echo
        echo "| # | provider | key | model | effort | result |"
        echo "|---|---|---|---|---|---|"
        jq -r 'def d: if . == "" then "default" else . end;
            (if .effort_used != "" and .effort_used != .effort
             then "\(.effort | d) (used \(.effort_used))" else (.effort | d) end) as $e
            | "| \(input_line_number) | \(.provider) | #\(.key + 1) | \(.model | d) | \($e) | \(.result) |"' "$attempts"
    } >>"$GITHUB_STEP_SUMMARY"
fi

if [ -z "$winner" ]; then
    ai_log "no provider completed the run ($n attempts)"
    out status failed
    exit 1
fi

result_dir=$state/result
rm -rf "$result_dir" && mkdir -p "$result_dir"
refuse() {
    ai_log "$1; refusing to publish the agent's changes"
    rm -f "$result_dir/changes.patch"
    out status failed
    exit 1
}

# Title: the first non-empty line of the agent's final message.
title=$(sed -e 's/^#* *//' -e 's/[[:space:]]*$//' "$summary" | grep -m1 -v '^$' | cut -c1-72)
[ -n "$title" ] || title="Nightly maintenance"

# The result travels to the pull-request job as files: the agent's work as
# one binary patch against the base commit (its own commits and anything
# left uncommitted), the scrubbed final message, and metadata. The patch
# is made in a container without a key or network, from the agent's tree.
export_dir=$state/export
rm -rf "$export_dir" && mkdir -p "$export_dir" && own "$export_dir"
container_args "ai-maintenance-${GITHUB_RUN_ID:-local}-$$-export" "$winner_dir/tree"
docker_args+=(--network none -v "$winner_dir/tree:$winner_dir/tree" -v "$export_dir:$export_dir"
    "$image_tag" bash "$here/export.sh" "$base" "$export_dir/changes.patch")
docker "${docker_args[@]}" || refuse "the changes could not be exported"
ai_regular_file "$export_dir/changes.patch" || refuse "the export left no patch"
if [ -s "$export_dir/changes.patch" ]; then
    status=changed
    cp "$export_dir/changes.patch" "$result_dir/changes.patch"
    # Check what will be published, byte for byte: apply the patch to a
    # copy of the checkout, as publish.sh will, and scan the patch and
    # every added or modified file's new contents (binary files are
    # encoded in the patch text). A scan that fails refuses as well.
    ai_contains_key "$keys" "$result_dir/changes.patch" && refuse "the patch contains an API key from the pool"
    verify=$state/verify
    { rm -rf "$verify" && cp -a "$top/." "$verify" && git -C "$verify" update-index -q --refresh; } ||
        refuse "no copy to check the changes in"
    git -C "$verify" apply --index --binary --whitespace=nowarn "$result_dir/changes.patch" ||
        refuse "the exported patch does not apply to $base"
    changed=$state/changed
    git -C "$verify" diff --cached --raw -z --no-abbrev --no-renames --diff-filter=AMT "$base" >"$changed" ||
        refuse "could not list the changed files"
    while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
        sha=$(cut -d' ' -f4 <<<"$meta")
        git -C "$verify" cat-file blob "$sha" >"$state/blob" || refuse "could not read the new contents of $path"
        ai_contains_key "$keys" "$state/blob" && refuse "$path contains an API key from the pool"
    done <"$changed"
    rm -rf "$verify" "$state/blob" "$changed"
else
    status=unchanged
fi
cp "$summary" "$result_dir/summary.md"
jq -n --arg status "$status" --arg provider "$winner" --arg model "$winner_model" --arg effort "$winner_effort" \
    --arg title "$title" --arg base "$base" \
    '{status: $status, provider: $provider, model: $model, effort: $effort, title: $title, base_sha: $base}' \
    >"$result_dir/meta.json"
ai_log "result: $status (provider $winner)"
out status "$status"
out provider "$winner"
out model "$winner_model"
out effort "$winner_effort"
out title "$title"
out summary-file "$summary"
out result-dir "$result_dir"
exit 0
