# shellcheck shell=bash
# Shared helpers for the ai-maintenance action: key-pool parsing, routing
# strategies, provider resolution, failure classification and secret
# scrubbing. Sourced by run.sh and test/selftest.sh; needs bash and jq.
#
# Key pool (secret AI_KEY_POOL), in priority order:
#
#   [ {"claude": ["k1", "k2"]}, {"gpt": ["k3"]}, {"gemini": ["k4"]},
#     {"provider2": {"keys": ["k5"], "model": "m", "base_url": "https://..."}} ]
#
# An entry's value is a key, a list of keys, or an object with "keys" plus
# provider options. A plain object ({"claude": [...], "gpt": [...]}) is
# accepted too; its keys keep their written order. A provider may appear
# more than once (for example primary Claude keys, then GPT, then backup
# Claude keys).

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
    ' <<<"$1" 2>&1); then
        # jq's own messages can quote the offending value (a key), so only
        # the messages raised above, all prefixed "POOL: ", are shown.
        local why
        why=$(printf '%s\n' "$out" | sed -n 's/^.*POOL: //p' | head -1 | cut -c1-200)
        ai_log "invalid AI_KEY_POOL: ${why:-not valid JSON, or an entry of unexpected shape}"
        ai_log "expected e.g. [{\"claude\":[\"k1\",\"k2\"]},{\"gpt\":[\"k3\"]},{\"gemini\":[\"k4\"]}]"
        return 2
    fi
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

# ai_scrub KEYS_JSON < in > out: replaces every key with "***".
ai_scrub() {
    jq -Rjs --argjson keys "$1" \
        'reduce ($keys[] | select(length > 0)) as $k (.; split($k) | join("***"))'
}

# ai_contains_key KEYS_JSON < in: success when the input holds any key.
ai_contains_key() {
    jq -Rse --argjson keys "$1" '. as $t | any($keys[] | select(length > 0); . as $k | $t | contains($k))' >/dev/null
}

# ai_model MODELS_JSON OPTIONS_JSON PROVIDER -> model for this attempt:
# the pool entry's "model", else MODELS_JSON[provider], else empty (the
# CLI's default).
ai_model() {
    local models=${1:-} options=${2:-}
    [ -n "$models" ] || models='{}'
    [ -n "$options" ] || options='{}'
    jq -nr --argjson m "$models" --argjson o "$options" --arg p "$3" \
        '$o.model // ($m | if type == "object" then .[$p] else null end) // ""'
}

# ai_npm_install DIR SPEC: installs an npm CLI (SPEC = package@version)
# into DIR once per run; DIR/node_modules/.bin then holds its binary.
ai_npm_install() {
    local dir=$1 spec=$2
    if [ -f "$dir/.installed" ] && [ "$(cat "$dir/.installed")" = "$spec" ]; then
        return 0
    fi
    command -v npm >/dev/null || { ai_log "npm is required to install $spec"; return 1; }
    mkdir -p "$dir"
    npm install --prefix "$dir" --no-audit --no-fund --loglevel=error "$spec" >&2 || return 1
    printf '%s\n' "$spec" >"$dir/.installed"
}
