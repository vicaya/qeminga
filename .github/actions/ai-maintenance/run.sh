#!/usr/bin/env bash
# Runs one maintenance pass: picks an API key from the pool according to
# the routing strategy, runs that provider's coding-agent CLI in a fresh
# container on a copy of the checkout in the working directory, and falls
# back to the next key when the current one is exhausted. Writes the
# agent's changes as a patch (result-dir) for publish.sh, which runs in a
# separate job without the keys. See README.md.
#
# Isolation: this script holds the pool and runs neither agent code nor
# anything it downloads. Each provider's CLI is installed in a container
# that sees only that provider's own, fresh tools directory, which only
# that provider's attempts then see, read-only; each attempt gets its own container
# from an image built once per run, with only its own key, its own copy of
# the checkout and an output directory; nothing of the runner (its files,
# processes, credentials or the other keys) is visible inside, and the
# agent is an unprivileged user there. The agent's tree, git configuration
# included, is only ever read inside a container; the runner reads the
# plain files the attempt left (never through a symlink, and only those it
# expects, under names it chooses) and checks the exported patch by
# applying it to its own copy. Container output reaches the job log with
# workflow commands suspended, or not at all with private instructions.
#
# Environment:
#   AI_KEY_POOL            required, JSON (lib.sh)
#   AI_INSTRUCTIONS        the maintenance instructions (or AI_INSTRUCTIONS_FILE)
#   AI_PRIVATE_INSTRUCTIONS  true: publish no free-form agent text and no
#                          transcripts (the instructions stay unpublished)
#   AI_EXTRA_PROMPT_FILE   optional Markdown appended to the prompt (review feedback);
#                          when set, a readable file (empty adds nothing)
#   AI_ROUTING             ordered (default) | round-robin
#   AI_ROUTING_SEED        rotation seed for round-robin (default GITHUB_RUN_NUMBER)
#   AI_FALLBACK_ON         exhausted (default) | any
#   AI_MODELS              optional JSON object, provider -> "<model> [effort]"
#                          (effort: low, medium, high, xhigh, max)
#   AI_ATTEMPT_TIMEOUT     timeout(1) duration per attempt (default 60m)
#   AI_SANDBOX_IMAGE       base image of the attempt containers (default ubuntu:24.04)
#   AI_SANDBOX_SETUP       shell script run as root while building the image,
#                          in a throwaway copy of the checkout (repository tools)
#   AI_STATE_DIR           scratch directory outside the checkout, the
#                          runner's own (or sticky, like /tmp); each invocation
#                          works in a fresh, owner-only directory under it
#                          (default: RUNNER_TEMP/ai-maintenance, else TMPDIR)
#   AI_KEEP_RAW_STATE      true keeps the raw files (prompt, attempts, tools)
#                          after the run, for debugging; by default only the
#                          sanitized output is left
#   AI_PROVIDERS_DIR       adapter directory (default: providers/ next to this file)
#
# Exit status: 0 when an agent finished (with or without changes), 1 when
# every candidate failed, 2 on a configuration error. Outputs (to
# GITHUB_OUTPUT when set): status=changed|unchanged|failed, provider,
# model, effort (the one the CLI used), title, summary-file, result-dir,
# logs-dir, base-sha, state-dir (this invocation's own directory).
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
providers_dir=$(cd "${AI_PROVIDERS_DIR:-$here/providers}" && pwd) || exit 2

# adapter_var ADAPTER NAME -> a setting the adapter declares; fails when
# the adapter cannot be read.
adapter_var() (
    # shellcheck source=/dev/null
    . "$1" >/dev/null 2>&1 || exit 1
    printf '%s' "${!2:-}"
)

# Withheld from everything published, and refused in a change: the keys
# and the credentials in the entries' options (lib.sh, ai_option_secrets).
# Withheld too: the instructions. Every producer must have delivered a
# list: a failed one would leave a valid-looking list without its values.
withheld_failed() { ai_log "could not list the values to withhold ($1); nothing was run"; exit 2; }
# The option paths each pool provider's adapter declares as credentials;
# an adapter that is there but cannot be read stops the run.
pool_providers=$(jq -r '[.[].provider] | unique[]' <<<"$pool") || withheld_failed "the pool's providers"
declared='{}'
while IFS= read -r p; do
    [ -n "$p" ] || continue
    a=$providers_dir/$(ai_canonical_provider "$p").sh
    [ -f "$a" ] || continue
    names=$(adapter_var "$a" PROVIDER_SECRET_OPTIONS) || withheld_failed "the adapter $a could not be read"
    declared=$(jq -Rsc --arg p "$p" --argjson d "$declared" '$d + {($p): [splits("\\s+") | select(length > 0)]}' <<<"$names") ||
        withheld_failed "the credential options $a declares"
done <<<"$pool_providers"
{ pool_keys=$(ai_all_keys "$pool") && ai_string_array "$pool_keys"; } || withheld_failed "the pool's keys"
{ option_secrets=$(ai_option_secrets "$pool" "$declared") && ai_string_array "$option_secrets"; } ||
    withheld_failed "the credentials in the pool's options"
{ fragments=$(ai_secret_fragments "$instructions") && ai_string_array "$fragments"; } || withheld_failed "the instructions"
{ credentials=$(printf '%s\n%s\n' "$pool_keys" "$option_secrets" | jq -cs '.[0] + .[1] | unique') &&
    ai_string_array "$credentials"; } || withheld_failed "the credentials"
# The change checks scan for one-line patterns (keys: with the forms the
# credentials take inside JSON strings) and match multiline credentials
# exactly (credential_texts).
{ credential_json=$(ai_json_forms "$credentials") && ai_string_array "$credential_json"; } ||
    withheld_failed "the credentials' JSON forms"
{ keys=$(ai_credential_patterns "$credentials") && ai_string_array "$keys"; } || withheld_failed "the credential patterns"
keys=$(printf '%s\n%s\n' "$keys" "$credential_json" | jq -cs 'add | unique') || withheld_failed "the credential patterns"
credential_texts=$(jq -c '[.[] | select(test("\n"))]' <<<"$credentials") || withheld_failed "the multiline credentials"
# Secrets reach the commands that handle them through standard input or an
# owner-only file, never through their arguments, which every account on
# the runner can read.
{ fragment_json=$(ai_json_forms "$fragments") && ai_string_array "$fragment_json"; } ||
    withheld_failed "the instructions' JSON forms"
{ secrets=$(printf '%s\n%s\n%s\n%s\n' "$credentials" "$keys" "$fragments" "$fragment_json" | jq -cs 'add | unique') &&
    ai_string_array "$secrets"; } || withheld_failed "the secrets"
# Keys inside the pool secret are not masked individually by GitHub.
if [ "${GITHUB_ACTIONS:-}" = true ]; then
    masks=$(ai_mask_lines "$credentials" "$secrets") || withheld_failed "the masks"
    while IFS= read -r k; do [ -z "$k" ] || printf '::add-mask::%s\n' "$k"; done <<<"$masks"
fi

routing=${AI_ROUTING:-ordered}
fallback_on=${AI_FALLBACK_ON:-exhausted}
case "$fallback_on" in exhausted | any) ;; *) ai_log "AI_FALLBACK_ON must be exhausted or any"; exit 2 ;; esac
private=${AI_PRIVATE_INSTRUCTIONS:-false}
case "$private" in true | false) ;; *) ai_log "AI_PRIVATE_INSTRUCTIONS must be true or false"; exit 2 ;; esac
models=$(ai_normalize_models "${AI_MODELS:-}") || exit 2
# Review feedback, when supplied, must be a readable file (an empty one
# adds nothing): a review round without it would not address the review.
extra=${AI_EXTRA_PROMPT_FILE:-}
if [ -n "$extra" ] && { [ ! -f "$extra" ] || [ ! -r "$extra" ]; }; then
    ai_log "the review feedback file ($extra) is missing or unreadable"
    exit 2
fi
attempt_timeout=${AI_ATTEMPT_TIMEOUT:-60m}
# The runner's Node.js, for the npm-installed CLIs, as one read-only file,
# and its npm for the install containers.
node_args=() npm_args=() npm_dir=''
if node=$(command -v node 2>/dev/null) && node=$(readlink -f "$node") && [ -f "$node" ]; then
    node_args=(-v "$node:/opt/ai-maintenance/node/bin/node:ro" -e AI_NODE_BIN=/opt/ai-maintenance/node/bin)
    if npm_js=$(command -v npm 2>/dev/null) && npm_js=$(readlink -f "$npm_js") && [ -f "$npm_js" ] &&
        [ "${npm_js##*/}" = npm-cli.js ]; then
        npm_dir=${npm_js%/bin/npm-cli.js}
        npm_args=(-v "$npm_dir:/opt/ai-maintenance/npm:ro" -e AI_NPM_CLI=/opt/ai-maintenance/npm/bin/npm-cli.js)
    fi
fi

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { ai_log "not inside a git checkout"; exit 2; }
top=$(git rev-parse --show-toplevel)
# Every copy of the checkout must be self-contained. The .git of a linked
# worktree or a submodule is a file naming a repository elsewhere, which a
# copy would share: the credential cleanup below would edit the original,
# and the container would not see it.
if [ ! -d "$top/.git" ] || [ -L "$top/.git" ] || [ -e "$top/.git/commondir" ]; then
    ai_log "$top is a linked worktree or a submodule (its .git is not a repository directory); run on a plain clone"
    exit 2
fi
subdir=$(git rev-parse --show-prefix)
base=$(git rev-parse HEAD)
out base-sha "$base"
# Every directory a container mounts or an image build reads, as the
# kernel resolves it: the checkout, the action, the adapters, npm.
shared_dirs=()
for d in "$top" "$here" "$providers_dir" ${npm_dir:+"$npm_dir"}; do
    shared_dirs+=("$(cd "$d" && pwd -P)") || exit 2
done

# A fresh, owner-only directory for this invocation: an earlier one in the
# same job (with the same AI_STATE_DIR) leaves its attempts, private or
# not, in its own, and nothing of them is read, reused or uploaded here.
# The containers reach their mounts through the docker daemon, so no other
# account needs to search it. It goes in a directory no one else can
# rename it in: the runner's own, or a sticky one such as /tmp.
state_root=${AI_STATE_DIR:-${RUNNER_TEMP:+$RUNNER_TEMP/ai-maintenance}}
state_root=${state_root:-${TMPDIR:-/tmp}}
# Never at or under a directory the containers see (the checkout, which
# the image build and every attempt copy whole, the action, the adapters,
# npm): the keys written below would be readable there. Checked on the
# path as the kernel will resolve it, before anything is made there.
# shared_dir PATH -> the shared directory PATH is in, if any.
shared_dir() {
    local s
    for s in "${shared_dirs[@]}"; do
        case "$1/" in "$s"/*) printf '%s' "$s"; return 0 ;; esac
    done
    return 1
}
refuse_shared() {
    ai_log "the state directory ($state_root) is inside $1, which the containers see; set AI_STATE_DIR to a directory outside it"
    exit 2
}
if want=$(realpath -m -- "$state_root") && in=$(shared_dir "$want"); then refuse_shared "$in"; fi
mkdir -p "$state_root" || exit 2
# trusted_dir DIR: owned by this user or root, and not writable by anyone
# else unless sticky (then no one else can rename what is in it).
trusted_dir() {
    local uid mode
    read -r uid mode < <(stat -c '%u %a' "$1" 2>/dev/null) || return 1
    { [ "$uid" = "$(id -u)" ] || [ "$uid" = 0 ]; } &&
        { [ $((8#$mode & 8#022)) -eq 0 ] || [ $((8#$mode & 8#1000)) -ne 0 ]; }
}
# Every directory on the way to it, as the kernel resolves it: anyone who
# can replace one could swap the run's directory for another.
state_ok=false
if [ ! -L "$state_root" ] && root_phys=$(cd "$state_root" && pwd -P); then
    state_ok=true d=$root_phys
    while :; do
        trusted_dir "$d" || { state_ok=false; break; }
        [ "$d" != / ] || break
        d=$(dirname "$d")
    done
fi
if [ "$state_ok" = true ] && in=$(shared_dir "$root_phys"); then refuse_shared "$in"; fi
if [ "$state_ok" != true ]; then
    ai_log "the state directory ($state_root) and every directory above it must belong to this user or root and be writable by no one else (unless sticky, like /tmp); it may not be a symlink"
    exit 2
fi
state=$(mktemp -d "$root_phys/ai-maintenance-run.XXXXXX") || exit 2
out state-dir "$state"
secrets_file=$state/secrets.json
# When the invocation ends, however it ends, only the sanitized output is
# left: the result, the uploaded logs, the scrubbed summary and the
# attempts table. The rest (the prompt, the agent's trees and raw output,
# the tools) is removed, write-protected files included. AI_KEEP_RAW_STATE
# keeps that rest for debugging, but never the file listing every key nor
# an attempt's pool options, which no diagnosis needs.
image_tag='' image_built=''
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
    [ -z "$image_built" ] || docker image rm -f "$image_tag" >/dev/null 2>&1
    rm -f "$secrets_file"
    rm -rf "$state"/attempt-*/in
    [ "${AI_KEEP_RAW_STATE:-}" != true ] || return 0
    local p
    for p in "$state"/* "$state"/.[!.]*; do
        [ -e "$p" ] || [ -L "$p" ] || continue
        case "${p##*/}" in result | logs | summary.md | attempts.jsonl) continue ;; esac
        [ -L "$p" ] || chmod -R u+rwx "$p" 2>/dev/null
        rm -rf "$p"
    done
}
trap cleanup EXIT
(umask 077 && printf '%s' "$secrets" >"$secrets_file") || exit 2
# One tools directory per provider, created by this run.
tools_root=$state/tools
mkdir -p "$tools_root" || exit 2
image=${AI_SANDBOX_IMAGE:-ubuntu:24.04}
case "$image" in
    '' | *[!A-Za-z0-9._/:@-]*) ai_log "AI_SANDBOX_IMAGE must be an image reference"; exit 2 ;;
esac
command -v docker >/dev/null || { ai_log "docker is required: every attempt runs in a container"; exit 2; }

candidates=$(ai_route "$pool" "$routing" "${AI_ROUTING_SEED:-${GITHUB_RUN_NUMBER:-0}}") || exit 2

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
        bash ca-certificates curl git jq procps >/dev/null && rm -rf /var/lib/apt/lists/*; \\
    fi; mkdir -p /etc/ai-maintenance && touch /etc/ai-maintenance/env
COPY setup.sh /usr/local/share/ai-maintenance/setup.sh
RUN --mount=type=bind,from=repo,target=/repo,rw cd /repo && bash -euo pipefail /usr/local/share/ai-maintenance/setup.sh
EOF
    docker build -t "$image_tag" --build-context repo="$top" "$ctx"
}
# Output of anything that ran in a container (or on the checkout, which
# a review round's agent wrote) reaches the job log only between these:
# the runner obeys no workflow command ("::...") until it sees the
# one-time token again, which nothing inside a container is given.
suspend_commands() {
    [ "${GITHUB_ACTIONS:-}" = true ] || return 0
    command_token=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    printf '::stop-commands::%s\n' "$command_token"
}
resume_commands() { [ "${GITHUB_ACTIONS:-}" != true ] || printf '\n::%s::\n' "$command_token"; }
show_capture() { # FILE: the end of a captured output, scrubbed
    suspend_commands
    ai_tail_lines "$1" 100000 | ai_scrub "$secrets_file"
    resume_commands
}

group "building the sandbox image from $image"
suspend_commands
build_image 2>&1
build_rc=$?
resume_commands
endgroup
if [ "$build_rc" -ne 0 ]; then
    ai_log "the sandbox image did not build; no attempt was made"
    out status failed
    exit 1
fi
image_built=1

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
providers_args=()
case "$providers_dir/" in "$here/"*) ;; *) providers_args=(-v "$providers_dir:$providers_dir:ro") ;; esac

# --- prompt ---------------------------------------------------------------
prompt_dir=$state/prompt
rm -rf "$prompt_dir" && mkdir -p "$prompt_dir"
prompt=$prompt_dir/prompt.md
# Every part is checked: a prompt without its preamble (the repository
# rules), the instructions or the review feedback would send the agent
# off without them.
if ! {
    cat "$here/preamble.md" &&
        printf '\n## Maintenance instructions\n\n%s\n' "$instructions" &&
        if [ -n "$extra" ] && [ -s "$extra" ]; then printf '\n' && cat "$extra"; fi
} >"$prompt"; then
    ai_log "could not write the prompt; no attempt was made"
    out status failed
    exit 2
fi
instructions=
# The agent's user reads it (mounted read-only) whatever the umask was.
own "$prompt_dir" || exit 2

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

# install_cli ADAPTER TOOLS LOG: installs the provider's CLI into TOOLS, a
# fresh directory of its own, in a container that sees nothing else of the
# run (no key, no prompt, no state, no other provider's tools), with only
# the variables the adapter lists in PROVIDER_INSTALL_ENV. The container is
# removed whatever happens, and a failed installation is discarded.
install_cli() {
    local v name rc
    local -a pass=()
    for v in $(adapter_var "$1" PROVIDER_INSTALL_ENV); do
        case "$v" in
            [A-Z_]*) case "$v" in *[!A-Z0-9_]*) continue ;; esac ;;
            *) continue ;;
        esac
        case "$v" in AI_*) continue ;; esac
        [ -z "${!v+x}" ] || pass+=(-e "$v")
    done
    { rm -rf "$2" && mkdir -p "$2" && own "$2"; } || return 1
    name=ai-maintenance-${GITHUB_RUN_ID:-local}-$$-install-$n
    container_args "$name" /tmp
    docker_args+=(-e "AI_TOOLS_DIR=$2" -e HOME=/tmp/ai-maintenance-home
        -v "$2:$2" "${providers_args[@]}" "${node_args[@]}" "${npm_args[@]}" "${pass[@]}"
        "$image_tag" bash "$here/install.sh" "$1")
    timeout --kill-after=30s "${AI_INSTALL_TIMEOUT:-20m}" docker "${docker_args[@]}" >"$3" 2>&1
    rc=$?
    # Stopping the client does not stop the container: it is removed before
    # anything else runs, so nothing keeps writing to the directory.
    docker rm -f "$name" >/dev/null 2>&1
    [ "$rc" -eq 0 ] || rm -rf "$2"
    return "$rc"
}

# --- attempts -------------------------------------------------------------
n=0 winner='' winner_model='' winner_effort='' winner_dir=''
declare -A install_failed=() installed=()
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
    # The entry's options (a gateway URL with credentials, a custom
    # adapter's token) reach the attempt in an owner-only file, mounted
    # read-only, never as an argument; it is removed once the attempt ends.
    { (umask 077 && mkdir "$dir/in" && printf '%s' "$options" >"$dir/in/options.json") && own "$dir/in"; } || exit 2

    # The adapter's transcript, uploaded under a fixed name.
    transcript=$(adapter_var "$adapter" PROVIDER_TRANSCRIPT)
    case "$transcript" in '' | .* | *[!A-Za-z0-9._-]*) transcript='' ;; esac
    printf '%s\n' "$transcript" >"$dir/transcript-name"

    tools=$tools_root/$adapter_name
    if [ -n "${installed[$adapter_name]:-}" ]; then
        printf 'installed by an earlier attempt of this run\n' >"$dir/install.log"
    elif install_cli "$adapter" "$tools" "$dir/install.log"; then
        installed[$adapter_name]=1
    else
        show_capture "$dir/install.log" >&2
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
    docker_args+=(-e AI_ATTEMPT_KEY -e "AI_ATTEMPT_DIR=$dir/out" -e "AI_TOOLS_DIR=$tools"
        -e "HOME=$dir/out/home" -v "$dir/tree:$dir/tree" -v "$dir/out:$dir/out"
        -v "$tools:$tools:ro" -v "$prompt_dir:$prompt_dir:ro" -v "$dir/in:$dir/in:ro"
        "${providers_args[@]}" "${node_args[@]}" "$image_tag"
        bash "$here/attempt.sh" "$adapter" "$prompt" "$model" "$dir/in/options.json" "$effort")
    # The key reaches docker through its environment, never its arguments.
    # Both output streams go to the attempt log, a file of the runner, and
    # are shown with workflow commands suspended; with private
    # instructions, not at all.
    if [ "$private" = true ]; then
        echo "(agent output not shown: the instructions are private)"
        AI_ATTEMPT_KEY=$(ai_key "$pool" "$entry" "$keyidx") \
            timeout --kill-after=30s "$attempt_timeout" docker "${docker_args[@]}" >"$dir/attempt.log" 2>&1
        rc=$?
    else
        suspend_commands
        AI_ATTEMPT_KEY=$(ai_key "$pool" "$entry" "$keyidx") \
            timeout --kill-after=30s "$attempt_timeout" docker "${docker_args[@]}" 2>&1 | tee "$dir/attempt.log"
        rc=${PIPESTATUS[0]}
        resume_commands
    fi
    docker rm -f "$cname" >/dev/null 2>&1
    rm -rf "$dir/in"
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
    extra=$(adapter_var "$adapter" PROVIDER_EXHAUSTED_REGEX)
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
} | ai_scrub "$secrets_file" | head -c 60000 >"$summary"

# Logs for upload, with every key and the instructions withheld (GitHub
# masks secrets in the console only, not in files). Only the files the run
# expects are uploaded, under names it chooses: the agent names nothing in
# the artifact. Private instructions: the attempts table only.
logs=$state/logs
rm -rf "$logs" && mkdir -p "$logs"
cp "$attempts" "$logs/attempts.jsonl"
upload() { # SOURCE DEST: scrubbed, at most 20 MB, cut at a line end
    ai_regular_file "$1" || return 0
    ai_head_lines "$1" 20000000 | ai_scrub "$secrets_file" >"$2"
}
upload_jsonl() { # SOURCE DEST: the same, scrubbed value by value (JSON lines)
    ai_regular_file "$1" || return 0
    ai_head_lines "$1" 20000000 | ai_scrub_jsonl "$secrets_file" >"$2"
}
if [ "$private" = false ]; then
    for ((i = 1; i <= n; i++)); do
        d=$state/attempt-$i
        [ -d "$d" ] || continue
        l=$logs/${d##*/}
        mkdir -p "$l"
        upload "$d/attempt.log" "$l/attempt.log"
        upload "$d/install.log" "$l/install.log"
        upload "$d/out/final.md" "$l/final.md"
        upload "$d/out/error.txt" "$l/error.txt"
        t=$(head -n 1 "$d/transcript-name" 2>/dev/null)
        [ -z "$t" ] || upload_jsonl "$d/out/$t" "$l/transcript.jsonl"
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
title=$(sed -e 's/^#* *//' -e 's/[[:space:]]*$//' "$summary" | grep -m1 -v '^$' | tr -d '[:cntrl:]' | cut -c1-72)
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
# The export runs git on the agent's tree, whose configuration can run
# commands: its output is captured like the agent's.
if ! docker "${docker_args[@]}" >"$state/export.log" 2>&1; then
    [ "$private" = true ] || show_capture "$state/export.log" >&2
    refuse "the changes could not be exported"
fi
ai_regular_file "$export_dir/changes.patch" || refuse "the export left no patch"
if [ -s "$export_dir/changes.patch" ]; then
    status=changed
    cp "$export_dir/changes.patch" "$result_dir/changes.patch"
    # Check what will be published, byte for byte: apply the patch to a
    # copy of the checkout, as publish.sh will, and scan the patch and
    # every added or modified file's new contents (binary files are
    # encoded in the patch text). A scan that fails refuses as well.
    { ai_contains_key "$keys" "$result_dir/changes.patch" || ai_contains_text "$credential_texts" "$result_dir/changes.patch"; } &&
        refuse "the patch contains an API key or credential from the pool"
    # Private instructions: the change may not quote a line of them either
    # (in its text, a file's contents or a file name).
    quoted='[]' quoted_whole='[]'
    if [ "$private" = true ]; then
        quoted=$(ai_scan_fragments "$secrets")
        quoted_whole=$(ai_scan_texts "$secrets")
    fi
    ai_contains_key "$quoted" "$result_dir/changes.patch" && refuse "the patch quotes the private instructions"
    verify=$state/verify
    { rm -rf "$verify" && cp -a "$top/." "$verify" && git -C "$verify" update-index -q --refresh; } ||
        refuse "no copy to check the changes in"
    git -C "$verify" apply --index --binary --whitespace=nowarn "$result_dir/changes.patch" >/dev/null 2>&1 ||
        refuse "the exported patch does not apply to $base"
    # Workflow files run with the repository's secrets once pushed: they
    # are never part of a maintenance change (README, Limits).
    git -C "$verify" diff --cached --name-only -z --no-renames "$base" >"$state/names" ||
        refuse "could not list the changed files"
    # The names as published, byte for byte (the patch may quote them):
    # checked before any of them is logged.
    { ai_contains_key "$keys" "$state/names" || ai_contains_text "$credential_texts" "$state/names"; } &&
        refuse "a changed file's name contains an API key or credential from the pool"
    { ai_contains_key "$quoted" "$state/names" || ai_contains_text "$quoted_whole" "$state/names"; } &&
        refuse "a changed file's name quotes the private instructions"
    while IFS= read -r -d '' path; do
        ai_protected_path "$path" && refuse "the changes touch $(ai_printable "$path") (under $AI_PROTECTED_PATHS)"
    done <"$state/names"
    changed=$state/changed
    git -C "$verify" diff --cached --raw -z --no-abbrev --no-renames --diff-filter=AMT "$base" >"$changed" ||
        refuse "could not list the changed files"
    while IFS= read -r -d '' meta && IFS= read -r -d '' path; do
        sha=$(cut -d' ' -f4 <<<"$meta")
        git -C "$verify" cat-file blob "$sha" >"$state/blob" ||
            refuse "could not read the new contents of $(ai_printable "$path")"
        { ai_contains_key "$keys" "$state/blob" || ai_contains_text "$credential_texts" "$state/blob"; } &&
            refuse "$(ai_printable "$path") contains an API key or credential from the pool"
        { ai_contains_key "$quoted" "$state/blob" || ai_contains_text "$quoted_whole" "$state/blob"; } &&
            refuse "a changed file quotes the private instructions"
    done <"$changed"
    rm -rf "$verify" "$state/blob" "$changed" "$state/names"
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
