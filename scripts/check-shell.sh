#!/usr/bin/env bash
# Lints every shell script in the repository with shellcheck: the CI
# helpers under scripts/ci/, the policy and interoperability scripts under
# scripts/, and any other file that is a shell script by name (`*.sh`) or
# by the interpreter its `#!` line runs (sh, bash or dash, directly or
# through `env`, with or without arguments). The files considered are
# git's: tracked and untracked ones, never ignored ones (build output,
# fuzzer artifacts) and never symbolic links (the file a link points to is
# the unit of linting). A file list that cannot be established fails the
# run rather than shrinking it.
#
# Findings of every severity fail. A deliberate exception is a
# `# shellcheck disable=SCxxxx # reason` directive directly above the
# command it covers; `.shellcheckrc` files, the repository's or the
# user's, are not read (`--norc`).
#
# The shellcheck release is pinned (SHELLCHECK_VERSION below; CI installs
# exactly it): releases differ in what they report. Another version prints
# a warning, and fails the run under CI (CI=true).
#
# Usage: scripts/check-shell.sh [DIR]          (exit 0 = clean, 1 = findings)
#        scripts/check-shell.sh --list [DIR]   (print the scripts it would lint)
# DIR defaults to the repository root.
#
# tests/ci_workflow.rs checks the listing against the repository and
# against fixtures.
set -euo pipefail

SHELLCHECK_VERSION=0.11.0

list=0
if [ "${1:-}" = --list ]; then
    list=1
    shift
fi
cd "${1:-$(dirname "$0")/..}"

# Whether $1 is a shell script by name or by its `#!` line's interpreter:
# the first word, or for `env` the first word after its options and
# NAME=value assignments.
is_shell_script() {
    local first="" interpreter="" i=1
    local -a words
    case "$1" in
        *.sh) return 0 ;;
    esac
    IFS= read -r first < "$1" 2>/dev/null || [ -n "$first" ] || return 1
    case "$first" in
        '#!'*) ;;
        *) return 1 ;;
    esac
    read -r -a words <<< "${first#'#!'}" || true
    [ "${#words[@]}" -gt 0 ] || return 1
    interpreter=${words[0]##*/}
    if [ "$interpreter" = env ]; then
        interpreter=""
        while [ "$i" -lt "${#words[@]}" ]; do
            case "${words[i]}" in
                -u | --unset | -C | --chdir) i=$((i + 2)) ;;
                -* | *=*) i=$((i + 1)) ;;
                *) interpreter=${words[i]##*/}; break ;;
            esac
        done
    fi
    case "$interpreter" in
        sh | bash | dash) return 0 ;;
    esac
    return 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# git warns and still exits 0 for a directory it cannot read, so anything
# it prints fails the listing too.
if ! git ls-files -z --cached --others --exclude-standard >"$tmp/paths" 2>"$tmp/err" \
        || [ -s "$tmp/err" ]; then
    cat "$tmp/err" >&2
    echo "check-shell: cannot list the files of $PWD" >&2
    exit 1
fi
sort -z -u "$tmp/paths" >"$tmp/sorted"

scripts=()
while IFS= read -r -d '' file; do
    # A tracked file deleted from the work tree, or a link.
    if [ -L "$file" ] || [ ! -e "$file" ]; then
        continue
    fi
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        echo "check-shell: cannot read $file" >&2
        exit 1
    fi
    if is_shell_script "$file"; then
        scripts+=("$file")
    fi
done <"$tmp/sorted"

if [ "$list" -eq 1 ]; then
    if [ "${#scripts[@]}" -gt 0 ]; then
        printf '%s\n' "${scripts[@]}"
    fi
    exit 0
fi

if [ "${#scripts[@]}" -eq 0 ]; then
    echo "check-shell: no shell scripts found" >&2
    exit 1
fi
command -v shellcheck >/dev/null || {
    echo "check-shell: shellcheck is not on PATH (install $SHELLCHECK_VERSION from https://github.com/koalaman/shellcheck/releases)" >&2
    exit 1
}
found=$(shellcheck --version | sed -n 's/^version: //p')
if [ "$found" != "$SHELLCHECK_VERSION" ]; then
    echo "check-shell: shellcheck $found is not the pinned $SHELLCHECK_VERSION; findings may differ from CI" >&2
    if [ "${CI:-}" = true ]; then
        exit 1
    fi
fi
echo "check-shell: shellcheck $found, ${#scripts[@]} scripts"
shellcheck --norc "${scripts[@]}"
