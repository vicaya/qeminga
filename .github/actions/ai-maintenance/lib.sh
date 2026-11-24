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

# The patterns the withheld values are found by, longest first, for the
# scrubbers and for the cut (ai_cut_lines) alike: a multiline value is
# matched without its leading and trailing white space, so the line break
# after it, which may separate it from the next line or event, stays.
# Inside a decoded JSON string there is no such separator to keep:
# patterns_and_values also has each value as configured, matched first.
# shellcheck disable=SC2016 # jq text
AI_PATTERNS_JQ='def patterns: map(if test("\n") then gsub("^\\s+|\\s+$"; "") else . end)
    | map(select(length > 0)) | unique | sort_by(-length);
  def patterns_and_values: map(., (select(test("\n")) | gsub("^\\s+|\\s+$"; "")))
    | map(select(length > 0)) | unique | sort_by(-length);'

# ai_scrub SECRETS_FILE < in > out: replaces every secret (pool keys, the
# instructions) with "***", longest first (AI_PATTERNS_JQ). The secrets
# come from a file (a JSON array), never from an argument, which other
# accounts can read.
ai_scrub() {
    jq -Rjs --slurpfile keys "$1" "$AI_PATTERNS_JQ"'
        reduce ($keys[0] | patterns | .[]) as $k (.; split($k) | join("***"))'
}

# ai_contains_key KEYS_JSON FILE: success when FILE's bytes hold any key,
# and also when FILE cannot be scanned (a scan that did not happen is not
# a clean result). The keys are single-line patterns: one with a line
# break (which would become several, an empty one among them) is not
# scanned for and counts as found; multiline values go to ai_contains_text.
ai_contains_key() {
    local patterns rc
    jq -e 'all(.[]; test("\n") | not)' <<<"$1" >/dev/null 2>&1 || return 0
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

# ai_cut_lines FILE LIMIT head|tail SECRETS_FILE: at most LIMIT bytes from
# the start (head) or end (tail) of FILE, in whole lines, for the
# scrubber. When FILE is longer, the cut falls at a line end, and never
# inside a withheld value (AI_PATTERNS_JQ): cut in two, a value would
# escape the exact-match scrubber. Only a multiline value has line ends of
# its own: the cut is chosen on a copy in which each of its line breaks
# inside such a value is a space (the same characters and bytes), and the
# file is read with a lookahead, beyond the LIMIT bytes, of the longest
# such value, so that one running past what was read lies wholly beyond
# the cut. Lengths are counted in UTF-8 bytes; the text kept is the
# original.
ai_cut_lines() {
    local size extra=0 window eof=false
    size=$(wc -c <"$1") || return 1
    if [ "$size" -le "$2" ]; then cat -- "$1"; return; fi
    extra=$(jq -r "$AI_PATTERNS_JQ"' [patterns[] | select(test("\n")) | utf8bytelength] | max // 0' "$4") || return 1
    # The tail reads one byte more: the line end before its first line.
    window=$(($2 + extra + 1))
    [ "$size" -gt "$window" ] || eof=true
    if [ "$3" = head ]; then head -c "$window" -- "$1"; else tail -c "$window" -- "$1"; fi |
        jq -Rjs --arg end "$3" --argjson limit "$2" --argjson eof "$eof" --slurpfile keys "$4" "$AI_PATTERNS_JQ"'
            . as $raw
            | (reduce ($keys[0] | patterns | map(select(test("\n"))) | .[]) as $k
                (.; split($k) | join($k | gsub("\n"; " ")))) as $m
            | ($m | split("\n")) as $p | ($m | length) as $mlen
            | if $end == "head" then
                # The lines, each with its line end, that fit in the limit.
                (reduce $p[:-1][] as $line ({b: 0, c: 0, done: false};
                    if .done then . else (($line | utf8bytelength) + 1) as $lb
                    | if .b + $lb <= $limit then .b += $lb | .c += ($line | length) + 1 else .done = true end end)) as $r
                | $raw[:$r.c]
              else
                # The last lines that fit in the limit, from a line start:
                # the first line read is a whole one only at the start of
                # the file.
                (reduce range(($p | length) - 1; -1; -1) as $i ({b: -1, c: -1, start: $mlen, done: false};
                    if .done then . else
                      .b += ($p[$i] | utf8bytelength) + 1 | .c += ($p[$i] | length) + 1
                      | if .b <= $limit and ($i > 0 or $eof) then .start = $mlen - .c else .done = true end
                    end)) as $r
                | $raw[$r.start:]
              end'
}

# ai_head_lines FILE LIMIT, ai_tail_lines FILE LIMIT: at most LIMIT bytes
# from the start (end) of FILE, in whole lines: for text already scrubbed.
ai_head_lines() {
    local size
    size=$(wc -c <"$1") || return 1
    if [ "$size" -le "$2" ]; then cat -- "$1"
    elif [ "$(tail -c +"$2" -- "$1" | head -c 1 | od -An -tx1 | tr -d ' \n')" = 0a ]; then head -c "$2" -- "$1"
    else head -c "$2" -- "$1" | sed '$d'; fi
}
ai_tail_lines() {
    local size
    size=$(wc -c <"$1") || return 1
    if [ "$size" -le "$2" ]; then cat -- "$1"
    elif [ "$(tail -c +"$((size - $2))" -- "$1" | head -c 1 | od -An -tx1 | tr -d ' \n')" = 0a ]; then tail -c "$2" -- "$1"
    else tail -c "$2" -- "$1" | sed '1d'; fi
}

# ai_publish_lines SOURCE DEST LIMIT SECRETS_FILE head|tail [jsonl]: the
# start (end) of SOURCE cut to size (ai_cut_lines), scrubbed (ai_scrub, or
# ai_scrub_jsonl for JSON lines), then held to LIMIT bytes in whole lines:
# scrubbing can make text longer ("***" for a shorter value, a JSON number
# quoted). Fails, leaving no DEST, when any step fails.
ai_publish_lines() {
    local scrub=ai_scrub cap=ai_head_lines rc=0
    [ "${6:-}" = jsonl ] && scrub=ai_scrub_jsonl
    [ "$5" = tail ] && cap=ai_tail_lines
    { ai_cut_lines "$1" "$3" "$5" "$4" | "$scrub" "$4" >"$2.part"; } &&
        "$cap" "$2.part" "$3" >"$2" || rc=1
    rm -f -- "$2.part"
    [ "$rc" -eq 0 ] || rm -f -- "$2"
    return "$rc"
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
# MODELS_JSON[provider], else empty (the CLI's defaults). The options go in
# on standard input: they may hold credentials.
ai_model() {
    local models=${1:-} options=${2:-}
    [ -n "$models" ] || models='{}'
    [ -n "$options" ] || options='{}'
    jq -r --argjson m "$models" --arg p "$3" \
        '.model // ($m | if type == "object" then .[$p] else null end) // ""' <<<"$options"
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

# ai_option_secrets POOL [DECLARED] -> JSON array of the credentials in the
# entries' options, withheld like keys (masked, scrubbed, refused in a
# change):
#   - every string option, at any depth, whose own name looks like a
#     credential (AI_CREDENTIAL_NAME, or a last word "key": signing_key,
#     signingKey, TLSKey, SIGNING-KEY; the names of the objects above it do not
#     count, so an "auth" object's "method" stays public);
#   - every option an adapter declares (DECLARED, {"provider": ["a.b", ...]},
#     from PROVIDER_SECRET_OPTIONS: dotted paths, array indices left out);
#   - the user-info of any URL value ("user:pass" and the password alone,
#     or a lone token), and URL query parameters whose decoded name looks
#     like a credential, each as written and percent-decoded (query values
#     also with "+" as a space), since a client sends, and may print, the
#     decoded form.
# Values are whole, line breaks included. The model and every other
# setting stay public.
AI_CREDENTIAL_NAME='token|secret|passw|credential|cookie|authorization|bearer|api[_-]?key|private[_-]?key|access[_-]?key'
ai_option_secrets() {
    local declared=${2:-}
    [ -n "$declared" ] || declared='{}'
    jq -c --arg re "$AI_CREDENTIAL_NAME" --argjson declared "$declared" '
        def hex: ascii_downcase | explode | map(if . >= 97 then . - 87 else . - 48 end) | .[0] * 16 + .[1];
        # UTF-8 bytes -> string; an invalid sequence is an error.
        def utf8:
            def cp($n): .[1:$n] | if length == $n - 1 and all(. >= 128 and . < 192) then map(. - 128) else error("utf8") end;
            def dec:
                if length == 0 then []
                else .[0] as $b
                    | if $b < 128 then [$b] + (.[1:] | dec)
                      elif $b >= 194 and $b < 224 then (cp(2)) as $c | [($b - 192) * 64 + $c[0]] + (.[2:] | dec)
                      elif $b >= 224 and $b < 240 then (cp(3)) as $c | [($b - 224) * 4096 + $c[0] * 64 + $c[1]] + (.[3:] | dec)
                      elif $b >= 240 and $b < 245 then (cp(4)) as $c | [($b - 240) * 262144 + $c[0] * 4096 + $c[1] * 64 + $c[2]] + (.[4:] | dec)
                      else error("utf8") end
                end;
            dec | implode;
        def pct_decode:
            [scan("%[0-9A-Fa-f]{2}|[^%]+|%")]
            | reduce .[] as $t ({s: "", b: []};
                if ($t | test("^%[0-9A-Fa-f]{2}$")) then .b += [$t[1:] | hex]
                else .s += ((.b | utf8) + $t) | .b = [] end)
            | .s + (.b | utf8);
        def decoded: try pct_decode catch empty;
        def url: test("^[A-Za-z][A-Za-z0-9+.-]*://");
        # A credential name: the list, or a last word "key" (snake, kebab,
        # camel or upper case).
        def credname: test($re; "i") or test("(^|[_-])key$"; "i") or test("[A-Za-z0-9]Key$");
        [ .[] | ($declared[.provider] // []) as $decl
          | .options | del(.model) | paths(strings) as $p | getpath($p) as $v
          | [$p[] | strings] as $names
          | (if (($names | last // "") | credname) or any($decl[]; . == ($names | join(".")))
             then $v else empty end),
            ($v | select(url) | capture("^[^:]+://(?<u>[^/?#@]*)@")? | .u
                | ., decoded,
                  (if test(":") then
                      (sub("^[^:]*:"; "") | ., decoded),
                      ((sub(":.*$"; "") | decoded) as $user | sub("^[^:]*:"; "") | decoded | "\($user):\(.)")
                   else empty end)),
            ($v | select(url) | scan("[?&]([^=&#]+)=([^&#]*)")
                | select(.[0] | ., (gsub("\\+"; " ") | decoded) | credname) | .[1]
                | ., decoded, (gsub("\\+"; " ") | decoded))
        ] | map(select(type == "string" and length > 0)) | unique' <<<"$1"
}

# ai_string_array JSON: success when JSON is an array of strings (a
# producer of withheld values that failed leaves something else).
ai_string_array() { jq -e 'type == "array" and all(.[]; type == "string")' <<<"${1:-}" >/dev/null 2>&1; }

# ai_credential_patterns CREDENTIALS -> the single-line patterns the change
# checks scan for (ai_contains_key): each one-line credential, and each
# line of 20 or more characters of a multiline one (the whole of which is
# matched exactly with ai_contains_text), except PEM armor lines
# ("-----BEGIN ... KEY-----"), which are the same in every key.
ai_credential_patterns() {
    jq -c '[.[] | if test("\n") then (split("\n")[] | gsub("^\\s+|\\s+$"; "")
                    | select(length >= 20 and (test("^-----[A-Z0-9 ]+-----$") | not)))
                  else . end]
        | map(select(length > 0)) | unique' <<<"$1"
}

# ai_json_forms VALUES -> the forms the values take inside a JSON string
# when they differ from the value itself (a quote, a backslash, a line
# break, other control characters): as jq and Node write them, with "/" as
# "\/", with "<", ">" and "&" as \u escapes (Go), and with everything past
# ASCII as \u escapes (Python). All are single lines.
ai_json_forms() {
    jq -c '
        def hex4: [(. / 4096 | floor) % 16, (. / 256 | floor) % 16, (. / 16 | floor) % 16, . % 16]
            | map("0123456789abcdef"[. : . + 1]) | join("");
        def uesc: "\\u" + hex4;
        def ascii: explode | map(if . < 128 then [.] | implode
                                 elif . > 65535 then (. - 65536) as $c
                                     | ((55296 + ($c / 1024 | floor)) | uesc) + ((56320 + $c % 1024) | uesc)
                                 else uesc end) | join("");
        [ .[] | . as $v | tojson[1:-1]
          | ., gsub("/"; "\\/"), (gsub("<"; "\\u003c") | gsub(">"; "\\u003e") | gsub("&"; "\\u0026")), ascii
          | select(. != $v) ] | unique' <<<"$1"
}

# ai_scrub_jsonl SECRETS_FILE: ai_scrub for JSON lines (transcripts).
# First the whole stream, as written, is scrubbed of every multiline value,
# which plain text lines may carry across lines; it is matched without its
# leading and trailing white space, so the line break that ends it, and
# separates it from the next event, stays. A value that is one line once
# trimmed ("42\n") is left to the second pass, which can tell a JSON
# number from text. Then a line that is JSON is
# scrubbed value by value, on the decoded strings (keys included; a number
# whose text is a withheld value becomes "***", other numbers and booleans
# keep their types), and written back as JSON; any other line as text.
ai_scrub_jsonl() {
    jq -Rjs --slurpfile keys "$1" "$AI_PATTERNS_JQ"'
        reduce ($keys[0] | patterns | map(select(test("\n"))) | .[]) as $k (.; split($k) | join("***"))' |
        jq -Rr --slurpfile keys "$1" "$AI_PATTERNS_JQ"'
            ($keys[0] | patterns_and_values) as $ks
            | ($ks | map({(.): true}) | add // {}) as $set
            | def scrub: reduce $ks[] as $k (.; split($k) | join("***"));
              def deep: if type == "string" then scrub
                        elif type == "number" and $set[tostring] then "***"
                        elif type == "object" then with_entries(.key |= scrub | .value |= deep)
                        elif type == "array" then map(deep) else . end;
              . as $line | try (fromjson | deep | tojson) catch ($line | scrub)'
}

# ai_mask_lines CREDENTIALS SECRETS -> the runner's ::add-mask:: values, in
# its escaped form ("%" "\r" "\n" as %25 %0D %0A): every one-line secret, and
# each multiline credential whole and line by line (lines of 4 or more
# characters; the console shows output a line at a time).
ai_mask_lines() {
    printf '%s\n%s\n' "$1" "$2" | jq -rs '
        def esc: gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A");
        [(.[1][] | select(test("\n") | not)),
         (.[0][] | select(test("\n")) | ., (split("\n")[] | gsub("^\\s+|\\s+$"; "") | select(length >= 4)))]
        | unique | .[] | esc'
}
