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

# case NAME EXPECTED(pass|fail): lints the repository built in "$work/NAME".
check() {
    local name=$1 expected=$2 rc=0
    "$linter" "$work/$name" >"$work/$name.log" 2>&1 </dev/null || rc=$?
    if { [ "$expected" = pass ] && [ "$rc" -eq 0 ]; } \
            || { [ "$expected" = fail ] && [ "$rc" -ne 0 ]; }; then
        echo "ok: $name ($expected, exit $rc)"
    else
        echo "FAILED: $name: expected $expected, exit $rc" >&2
        cat "$work/$name.log" >&2
        failed=1
    fi
}

# repo NAME: a fresh repository; files are added by the caller.
repo() {
    mkdir "$work/$1"
    git -C "$work/$1" init -q
}

# A clean baseline passes.
repo clean
cat >"$work/clean/ok.sh" <<'EOF'
#!/bin/sh
echo "$1"
EOF
check clean pass

# A root-level name that looks like an option is read as a file by every
# tool: its header directive (sh) applies, so the Bash array is a finding.
repo dash-name
cat >"$work/dash-name/-helper.sh" <<'EOF'
#!/bin/bash
# shellcheck shell=sh
words=(a b)
echo "${words[0]}"
EOF
check dash-name fail

# A root-level script named `-` is linted as that file, not as stdin.
repo stdin-name
cat >"$work/stdin-name/-" <<'EOF'
#!/bin/sh
echo $1
EOF
check stdin-name fail

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
check heredoc pass

# A header directive still wins over the shebang: Bash syntax under a
# `shell=sh` directive is a finding.
repo directive
cat >"$work/directive/run" <<'EOF'
#!/bin/bash

# shellcheck shell=sh
if [[ -n "${1:-}" ]]; then echo "$1"; fi
EOF
check directive fail

exit "$failed"
