#!/usr/bin/env bash
# End-to-end cases for scripts/check-shell.sh that need the real, pinned
# linter binary and cannot live in the repository's own lint set because
# the lint must fail on them. Each case builds a throwaway git repository,
# runs the linter over it and checks its exit status: 0 for a clean
# repository, non-zero for one with a finding the linter must not miss.
# The clean counterparts that can be checked in are tests/fixtures/shell/.
#
#   scripts/ci/check-shell-selftest.sh   (exit 0 = every case as expected)
#
# CI's shellcheck job runs it after the linter; tests/ci_workflow.rs
# checks that it does.
set -euo pipefail

linter="$(cd "$(dirname "$0")/.." && pwd)/check-shell.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=0

# The cases must not depend on the caller's git configuration (a global
# core.excludesFile, for one): only the repositories' own state counts.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
unset GIT_DIR GIT_WORK_TREE

# repo NAME: a fresh repository; the caller writes its files.
repo() {
    mkdir "$work/$1"
    git -C "$work/$1" init -q
}

# A case passes only for the reason it states, never because discovery or
# execution failed some other way:
#   check NAME pass COUNT       exit 0, and exactly COUNT scripts linted
#   check NAME fail FILE CODE   exit 1 (findings), with CODE reported for
#                               FILE (as `In ./FILE line ...`)
check() {
    local name=$1 expected=$2 log="$work/$1.log" rc=0 why=""
    # Every fixture is tracked, so no exclude rule can hide it.
    git -C "$work/$name" add -f -A
    "$linter" "$work/$name" >"$log" 2>&1 </dev/null || rc=$?
    case "$expected" in
        pass)
            if [ "$rc" -ne 0 ]; then
                why="exit $rc"
            elif ! grep -Eq ", $3 scripts\$" "$log"; then
                why="not exactly $3 scripts linted"
            fi ;;
        fail)
            if [ "$rc" -ne 1 ]; then
                why="exit $rc, not 1 (findings)"
            elif ! grep -Fqx "In ./$3 line" <(sed -n 's/^\(In .* line\) [0-9]*:$/\1/p' "$log"); then
                why="no findings for ./$3"
            elif ! grep -Eq "\\<$4\\>" "$log"; then
                why="$4 not reported"
            fi ;;
    esac
    if [ -z "$why" ]; then
        echo "ok: $name ($expected)"
    else
        echo "FAILED: $name: expected $expected: $why" >&2
        cat "$log" >&2
        failed=1
    fi
}

# A clean baseline passes.
repo clean
cat >"$work/clean/ok.sh" <<'EOF'
#!/bin/sh
echo "$1"
EOF
check clean pass 1

# A root-level name that looks like an option is read as a file by every
# tool: its header directive (sh) applies, so the Bash array is a finding.
repo dash-name
cat >"$work/dash-name/-helper.sh" <<'EOF'
#!/bin/bash
# shellcheck shell=sh
words=(a b)
echo "${words[0]}"
EOF
check dash-name fail -helper.sh SC3030

# A root-level script named `-` is linted as that file, not as stdin.
repo stdin-name
cat >"$work/stdin-name/-" <<'EOF'
#!/bin/sh
echo $1
EOF
check stdin-name fail - SC2086

# The detected dialect still applies when a here-document in the body
# carries a directive line; the same file without --shell=bash is SC1008.
repo heredoc
cat >"$work/heredoc/gen" <<'EOF'
#!/usr/bin/env -S 'bash' -eu
words=(a b)
cat <<'TEXT'
# shellcheck shell=sh
TEXT
echo "${words[1]}"
EOF
check heredoc pass 1

# A header directive still wins over the shebang: Bash syntax under a
# `shell=sh` directive is a finding.
repo directive
cat >"$work/directive/run" <<'EOF'
#!/bin/bash

# shellcheck shell=sh
if [[ -n "${1:-}" ]]; then echo "$1"; fi
EOF
check directive fail run SC3010

exit "$failed"
