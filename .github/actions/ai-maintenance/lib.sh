# shellcheck shell=bash
# Shared helpers for the ai-maintenance action: key-pool parsing, routing
# strategies, provider resolution, failure classification and secret
# scrubbing. Sourced by run.sh and test/selftest.sh; needs bash and jq.
#
# Key pool (secret AI_KEY_POOL), in priority order:
#
#   [ {"claude": ["k1", "k2"]}, {"gpt": ["k3"]}, {"gemini": ["k4"]},
#     {"provider2": {"keys": ["k5"], "model": "m high", "base_url": "https://..."}} ]
#
# An entry's value is a key, a list of keys, or an object with "keys" plus
# provider options; "model" is "<model> [effort]" (ai_parse_model_spec). A
# plain object ({"claude": [...], "gpt": [...]}) is
# accepted too; its keys keep their written order. A provider may appear
# more than once (for example primary Claude keys, then GPT, then backup
# Claude keys).

# Reasoning-effort levels. Each adapter maps them onto its CLI (Codex has
# no "max" and uses "xhigh" for it).
AI_EFFORT_LEVELS="low medium high xhigh max"

# The routing strategies run.sh accepts. Add a strategy by adding its name
# here and a branch in ai_route.
AI_ROUTING_STRATEGIES="ordered round-robin"

# Errors that mean "this key cannot serve the run right now": quota, rate
# limit, billing, overload, or a bad or revoked key. Matched
# case-insensitively against the attempt's log when the attempt fails.
AI_EXHAUSTED_REGEX='rate[ _-]?limit|too many requests|(^|[^0-9])429([^0-9]|$)|quota|resource[ _]exhausted|credit balance|billing|overloaded|(^|[^0-9])529([^0-9]|$)|(^|[^0-9])401([^0-9]|$)|unauthori[sz]ed|authentication[ _]error|invalid[ _-]?(x-)?api[ _-]?key|incorrect api key|api key not valid|api_key_invalid|permission[ _]denied|usage limit'

ai_log() { printf '[ai-maintenance] %s\n' "$*" >&2; }

# ai_normalize_pool JSON -> prints the canonical pool
#   [{"provider": "claude", "keys": ["k1", ...], "options": {...}}, ...]
# or fails with a message that never echoes the input (it holds secrets).
ai_normalize_pool() {
    local out
    if ! out=$(jq -ce '
        def entry($p; $v):
            if ($v | type) == "string" then {provider: $p, keys: [$v], options: {}}
            elif ($v | type) == "array" then {provider: $p, keys: $v, options: {}}
            elif ($v | type) == "object" then
                {provider: $p,
                 keys: (if ($v.keys | type) == "string" then [$v.keys] else $v.keys end),
                 options: ($v | del(.keys))}
            else error("POOL: bad value for provider \($p)") end;
        (if type == "array" then . elif type == "object" then [.] else error("POOL: pool must be a JSON array or object") end)
        | [ .[] | if type == "object" then to_entries[] else error("POOL: each pool entry must be an object") end
              | entry(.key | ascii_downcase; .value) ]
        | if length == 0 then error("POOL: pool is empty") else . end
        | map(if (.provider | test("^[a-z0-9][a-z0-9_-]*$")) | not then error("POOL: provider names must match [a-z0-9][a-z0-9_-]*") else . end)
        | map(if (.keys | type) != "array" or (.keys | length) == 0
                 or any(.keys[]; type != "string" or length == 0 or test("\\s"))
              then error("POOL: provider \(.provider) needs a non-empty list of non-empty keys without whitespace")
              else . end)
        | map(if .options.effort != null
              then error("POOL: provider \(.provider): write the effort after the model, as \"model\": \"<model> <effort>\"")
              else . end)
        | map(if (.options | has("model")) and (.options.model | type) != "string"
              then error("POOL: provider \(.provider): \"model\" must be a string, \"<model> [effort]\"")
              else . end)
        | map(if (.options.model // "") | test("[[:cntrl:]]")
              then error("POOL: provider \(.provider): \"model\" must be one line of \"<model> [effort]\"")
              else . end)
    ' <<<"$1" 2>&1); then
        # jq's own messages can quote the offending value (a key), so only
        # the messages raised above, all prefixed "POOL: ", are shown.
        local why
        why=$(printf '%s\n' "$out" | sed -n 's/^.*POOL: //p' | head -1 | cut -c1-200)
        ai_log "invalid AI_KEY_POOL: ${why:-not valid JSON, or an entry of unexpected shape}"
        ai_log "expected e.g. [{\"claude\":[\"k1\",\"k2\"]},{\"gpt\":[\"k3\"]},{\"gemini\":[\"k4\"]}]"
        return 2
    fi
    # Every entry's model setting, parsed exactly as at attempt time, before
    # any attempt runs.
    # The parser's own message quotes the value, which may hold a key
    # pasted into the wrong field: only the entry number, the field and the
    # expected format are shown.
    local i provider
    while IFS=$'\t' read -r i provider; do
        if ! ai_parse_model_spec "$(jq -r --argjson i "$i" '.[$i].options.model // ""' <<<"$out")" >/dev/null 2>&1; then
            ai_log "invalid AI_KEY_POOL: entry $((i + 1)) ($provider): \"model\" must be one line of \"<model> [effort]\", the effort one of: $AI_EFFORT_LEVELS"
            return 2
        fi
    done < <(jq -r 'to_entries[] | [.key, .value.provider] | @tsv' <<<"$out")
    printf '%s\n' "$out"
}

# ai_normalize_models JSON -> the models map with canonical provider names
#   {"gpt": "<model> [effort]", ...}
# Values must be strings that ai_parse_model_spec accepts; provider names
# resolve through the same aliases as the pool ("openai" is "gpt"), and two
# names for one provider are an error rather than a silent choice.
ai_normalize_models() {
    local raw=${1:-} out='{}' key canon spec
    [ -n "$raw" ] || { printf '{}\n'; return 0; }
    # Checked on the JSON strings themselves: extracting a value through a
    # command substitution would drop a trailing newline unseen.
    if ! jq -e 'type == "object" and all(.[]; type == "string" and (test("[[:cntrl:]]") | not))
                and all(keys[]; ascii_downcase | test("^[a-z0-9][a-z0-9_-]*$"))' <<<"$raw" >/dev/null 2>&1; then
        ai_log "models must be a JSON object of provider name -> \"<model> [effort]\" string, one line each"
        return 2
    fi
    while IFS= read -r key; do
        canon=$(ai_canonical_provider "$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')")
        spec=$(jq -r --arg k "$key" '.[$k]' <<<"$raw")
        ai_parse_model_spec "$spec" >/dev/null || return 2
        if jq -e --arg c "$canon" 'has($c)' <<<"$out" >/dev/null; then
            ai_log "models: two names for provider $canon; keep one"
            return 2
        fi
        out=$(jq -c --arg c "$canon" --arg s "$spec" '. + {($c): $s}' <<<"$out")
    done < <(jq -r 'keys_unsorted[]' <<<"$raw")
    printf '%s\n' "$out"
}

# ai_route POOL STRATEGY SEED -> one candidate per line: "ENTRY<TAB>KEY<TAB>PROVIDER"
# (indices into the canonical pool; keys themselves are never printed).
#   ordered      entries in pool order, each entry's keys in order; fall
#                back to the next key, then the next entry.
#   round-robin  same provider priority, but each entry's key list is
#                rotated by SEED (the run number), spreading load across
#                keys of one provider from night to night.
ai_route() {
    local pool=$1 strategy=$2 seed=${3:-0}
    case "$seed" in '' | *[!0-9]*) seed=0 ;; esac
    case "$strategy" in
        ordered | round-robin) ;;
        *)
            ai_log "unknown routing strategy '$strategy' (known: $AI_ROUTING_STRATEGIES)"
            return 2
            ;;
    esac
    jq -r --arg s "$strategy" --argjson seed "$seed" '
        to_entries[] | .key as $e | .value as $v | ($v.keys | length) as $n
        | (if $s == "round-robin" then $seed % $n else 0 end) as $off
        | range(0; $n) | [$e, ((. + $off) % $n), $v.provider] | @tsv
    ' <<<"$pool"
}

# ai_key POOL ENTRY KEY -> the key (stdout only; callers capture it).
ai_key() { jq -r --argjson e "$2" --argjson k "$3" '.[$e].keys[$k]' <<<"$1"; }

# ai_options POOL ENTRY -> the entry's options object (compact JSON).
ai_options() { jq -c --argjson e "$2" '.[$e].options' <<<"$1"; }

# ai_all_keys POOL -> JSON array of every key, for masking and scrubbing.
ai_all_keys() { jq -c '[.[].keys[]] | unique' <<<"$1"; }

# ai_canonical_provider NAME -> adapter name. Aliases let a pool say
# "anthropic", "openai" or "google"; any other name is used as written,
# so a new provider only needs providers/<name>.sh.
ai_canonical_provider() {
    case "$1" in
        anthropic | claude-code) echo claude ;;
        openai | codex | chatgpt) echo gpt ;;
        google | antigravity | agy) echo gemini ;;
        *) echo "$1" ;;
    esac
}

# ai_is_exhausted LOGFILE [EXTRA_REGEX] -> success when the log shows a
# quota, rate-limit, billing, overload or credential failure.
ai_is_exhausted() {
    local re=$AI_EXHAUSTED_REGEX
    [ -n "${2:-}" ] && re="$re|$2"
    [ -f "$1" ] && grep -Eiq -- "$re" "$1"
}

# ai_scrub SECRETS_FILE < in > out: replaces every secret (pool keys, the
# instructions) with "***", longest first. The secrets come from a file
# (a JSON array), never from an argument, which other accounts can read.
ai_scrub() {
    jq -Rjs --slurpfile keys "$1" \
        'reduce ($keys[0] | map(select(length > 0)) | sort_by(-length) | .[]) as $k (.; split($k) | join("***"))'
}

# ai_contains_key KEYS_JSON FILE: success when FILE's bytes hold any key,
# and also when FILE cannot be scanned (a scan that did not happen is not
# a clean result).
ai_contains_key() {
    local patterns rc
    patterns=$(mktemp) || return 0
    if ! jq -r '.[] | select(length > 0)' <<<"$1" >"$patterns"; then
        rm -f "$patterns"
        return 0
    fi
    if [ ! -s "$patterns" ]; then
        rm -f "$patterns"
        return 1
    fi
    LC_ALL=C grep -qsaF -f "$patterns" -- "$2"
    rc=$?
    rm -f "$patterns"
    [ "$rc" -ne 1 ]
}

# ai_secret_fragments TEXT -> JSON array of what to withhold from published
# output: the whole (trimmed) instructions, then each line of 20 or more
# characters, so a quoted line is caught on its own.
ai_secret_fragments() {
    printf '%s' "${1:-}" | jq -Rsc '
        def trim: gsub("^\\s+|\\s+$"; "");
        [(trim), (split("\n")[] | trim | select(length >= 20))] | map(select(length > 0))'
}

# Paths a maintenance change may not touch: workflow files run with the
# repository's secrets as soon as they are pushed, so they take a separate,
# reviewed path (see README, Limits). Compared case-insensitively.
AI_PROTECTED_PATHS=".github/workflows/"

# ai_protected_path PATH: success when PATH is under a protected prefix.
ai_protected_path() {
    local p=${1,,} prefix
    for prefix in $AI_PROTECTED_PATHS; do
        case "$p" in "${prefix,,}"*) return 0 ;; esac
    done
    return 1
}

# ai_printable TEXT -> TEXT with control characters (newlines included)
# replaced by "?", at most 200 characters: for names the agent chose
# (file paths) in log lines, which must stay one line.
ai_printable() { local t=${1//[[:cntrl:]]/?}; printf '%s' "${t:0:200}"; }

# ai_scan_fragments SECRETS_JSON -> what a change is scanned for with
# private instructions: the single lines of 20 or more characters (a
# shorter one would match ordinary code).
ai_scan_fragments() { jq -c '[.[] | select(length >= 20 and (test("\n") | not))] | unique' <<<"$1"; }

# ai_scan_texts SECRETS_JSON -> the multi-line fragments of 20 or more
# characters (the whole instructions), matched exactly by ai_contains_text.
ai_scan_texts() { jq -c '[.[] | select(length >= 20 and test("\n"))] | unique' <<<"$1"; }

# ai_contains_text TEXTS_JSON FILE: success when FILE holds any of the
# texts (which may span lines) exactly, and when FILE cannot be scanned.
ai_contains_text() {
    local texts rc
    [ "$(jq length <<<"$1" 2>/dev/null)" != 0 ] || return 1
    texts=$(mktemp) || return 0
    printf '%s' "$1" >"$texts"
    jq -Rse --slurpfile t "$texts" '. as $f | any($t[0][]; . as $x | $f | contains($x))' "$2" >/dev/null 2>&1
    rc=$?
    rm -f "$texts"
    [ "$rc" -ne 1 ]
}

# ai_head_lines FILE LIMIT, ai_tail_lines FILE LIMIT: at most LIMIT bytes
# from the start (end) of FILE. When FILE is longer, the cut falls at a
# line end, so that no key (which has no whitespace) or line of the
# instructions is cut in two and escapes the exact-match scrubber.
ai_head_lines() {
    if [ "$(wc -c <"$1")" -le "$2" ]; then cat "$1"; else head -c "$2" "$1" | sed '$d'; fi
}
ai_tail_lines() {
    if [ "$(wc -c <"$1")" -le "$2" ]; then cat "$1"; else tail -c "$2" "$1" | sed '1d'; fi
}

# ai_regular_file PATH: success for a regular file that is not a symlink.
# Files an attempt wrote are read only through this check.
ai_regular_file() { [ -f "$1" ] && [ ! -L "$1" ]; }

# ai_report_effort LEVEL: for adapters, the effort the CLI actually ran
# with when it differs from the one requested.
ai_report_effort() { [ -z "${AI_ATTEMPT_DIR:-}" ] || printf '%s\n' "$1" >"$AI_ATTEMPT_DIR/effort"; }

# The rule for "a maintenance pull request" (watch.sh, gate.sh, publish.sh):
# its head branch is in this repository and starts with the branch prefix.
# shellcheck disable=SC2016,SC2034 # jq text, used by the scripts that source this file
AI_MAINTENANCE_PR_JQ='def maintenance_pr($repo; $prefix):
    (.head.repo.full_name // "") == $repo and ((.head.ref // "") | startswith($prefix));'


ai_effort_levels_json() { printf '%s' "$AI_EFFORT_LEVELS" | jq -Rc 'split(" ")'; }

# ai_nearest_effort REQUESTED "a, b, ..." -> the highest allowed level at
# or below REQUESTED, else the lowest allowed one (levels ordered as in
# AI_EFFORT_LEVELS; unknown names are ignored).
ai_nearest_effort() {
    jq -nr --arg r "$1" --arg a "$2" --argjson levels "$(ai_effort_levels_json)" '
        ($levels | index($r)) as $ri
        | [$a | split(",")[] | gsub("\\s"; "") | select(. != "") | . as $l | $levels | index($l)
           | select(. != null)] | sort as $allowed
        | if ($allowed | length) == 0 then ""
          else (([$allowed[] | select(. <= $ri)] | last) // $allowed[0]) as $i | $levels[$i] end'
}

ai_is_effort() { case " $AI_EFFORT_LEVELS " in *" ${1:-} "*) return 0 ;; esac; return 1; }

# ai_parse_model_spec SPEC -> "MODEL<TAB>EFFORT". A spec is a model with an
# optional trailing effort level ("claude-opus-5-5 high"), a model alone,
# or a level alone ("high": the CLI's default model at that effort). Either
# part may come out empty (the CLI's default). Anything else: status 2.
ai_parse_model_spec() {
    local -a w
    case "${1:-}" in
        *[[:cntrl:]]*)
            ai_log "model '${1//[[:cntrl:]]/?}': one line of '<model> [effort]', separated by spaces"
            return 2
            ;;
    esac
    read -ra w <<<"${1:-}"
    case ${#w[@]} in
        0) printf '\t\n' ;;
        1)
            if ai_is_effort "${w[0]}"; then printf '\t%s\n' "${w[0]}"; else printf '%s\t\n' "${w[0]}"; fi
            ;;
        2)
            if ai_is_effort "${w[1]}" && ! ai_is_effort "${w[0]}"; then
                printf '%s\t%s\n' "${w[0]}" "${w[1]}"
            else
                ai_log "model '$1': write '<model> <effort>', with the effort one of: $AI_EFFORT_LEVELS"
                return 2
            fi
            ;;
        *)
            ai_log "model '$1': write '<model> <effort>', with the effort one of: $AI_EFFORT_LEVELS"
            return 2
            ;;
    esac
}

# ai_model MODELS_JSON OPTIONS_JSON PROVIDER -> the model spec for this
# attempt (see ai_parse_model_spec): the pool entry's "model", else
# MODELS_JSON[provider], else empty (the CLI's defaults).
ai_model() {
    local models=${1:-} options=${2:-}
    [ -n "$models" ] || models='{}'
    [ -n "$options" ] || options='{}'
    jq -nr --argjson m "$models" --argjson o "$options" --arg p "$3" \
        '$o.model // ($m | if type == "object" then .[$p] else null end) // ""'
}

# ai_npm_install DIR SPEC: installs an npm CLI (SPEC = package@version)
# into DIR once per run; DIR/node_modules/.bin then holds its binary. In
# the install container, npm is the runner's, mounted as AI_NPM_CLI.
ai_npm_install() {
    local dir=$1 spec=$2
    local -a npm=(npm)
    [ -z "${AI_NPM_CLI:-}" ] || npm=(node "$AI_NPM_CLI")
    if [ -f "$dir/.installed" ] && [ "$(cat "$dir/.installed")" = "$spec" ]; then
        return 0
    fi
    command -v "${npm[0]}" >/dev/null || { ai_log "npm is required to install $spec"; return 1; }
    mkdir -p "$dir"
    "${npm[@]}" install --prefix "$dir" --no-audit --no-fund --loglevel=error "$spec" >&2 || return 1
    printf '%s\n' "$spec" >"$dir/.installed"
}

# ai_sandbox_env: for the scripts that run inside the sandbox image
# (attempt.sh, install.sh): loads the variables the image's repository
# setup left in /etc/ai-maintenance/env (PATH, CARGO_HOME, ...), puts the
# mounted Node.js first on PATH and creates HOME.
ai_sandbox_env() {
    if [ -f /etc/ai-maintenance/env ]; then
        set -a
        # shellcheck source=/dev/null
        . /etc/ai-maintenance/env
        set +a
    fi
    [ -z "${AI_NODE_BIN:-}" ] || PATH=$AI_NODE_BIN:$PATH
    export PATH
    mkdir -p "$HOME"
}
