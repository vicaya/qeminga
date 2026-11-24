#!/usr/bin/env bash
# Lints every shell script in the repository with shellcheck: the CI
# helpers under scripts/ci/, the policy and interoperability scripts under
# scripts/, and any other file that is a shell script by name (`*.sh`) or
# by the interpreter its `#!` line runs (sh, bash or dash, directly or
# through `env`, with or without arguments). The files considered are
# git's: tracked and untracked ones, never ignored ones (build output,
# fuzzer artifacts) and never symbolic links (the file a link points to is
# the unit of linting); embedded repositories and submodules are separate
# repositories and are not entered. A file list that cannot be established fails the
# run rather than shrinking it.
#
# Findings of every severity fail. A deliberate exception is a
# `# shellcheck disable=SCxxxx # reason` directive directly above the
# command it covers; `.shellcheckrc` files, the repository's or the
# user's, are not read (`--norc`), and neither is SHELLCHECK_OPTS.
#
# The shellcheck release is pinned (SHELLCHECK_VERSION below; CI installs
# exactly it): releases differ in what they report. Another version prints
# a warning, and fails the run under CI (CI=true).
#
# Each script is linted as the dialect its `#!` line runs (`--shell`),
# because shellcheck cannot read every shebang recognised here, unless the
# file names its dialect with a `# shellcheck shell=` directive.
#
# Usage: scripts/check-shell.sh [DIR]           (exit 0 = clean, else findings)
#        scripts/check-shell.sh --list [DIR]    (the scripts it would lint, one per line)
#        scripts/check-shell.sh --list0 [DIR]   (the same, NUL-terminated, for machines)
# DIR defaults to the repository root.
#
# tests/ci_workflow.rs checks the listing against the repository and
# against fixtures.
set -euo pipefail
# Byte order for the listing; nothing from the caller's environment may
# change what shellcheck reports (`--norc` below covers .shellcheckrc).
export LC_ALL=C
unset SHELLCHECK_OPTS

SHELLCHECK_VERSION=0.11.0

mode=lint
case "${1:-}" in
    --list) mode=list; shift ;;
    --list0) mode=list0; shift ;;
esac
cd "${1:-$(dirname "$0")/..}"

# Splits $1 into the array `words` as `env -S` does: whitespace separates,
# and '...', "..." and backslash escapes are honoured. Nothing is expanded
# or evaluated.
split_words() {
    local text=$1 c word="" quote="" in_word=0 i
    words=()
    for ((i = 0; i < ${#text}; i++)); do
        c=${text:i:1}
        if [ -n "$quote" ]; then
            if [ "$c" = "$quote" ]; then
                quote=""
            elif [ "$c" = "\\" ] && [ "$quote" = '"' ]; then
                i=$((i + 1))
                word+=${text:i:1}
            else
                word+=$c
            fi
            continue
        fi
        case "$c" in
            "'" | '"') quote=$c; in_word=1 ;;
            "\\") i=$((i + 1)); word+=${text:i:1}; in_word=1 ;;
            ' ' | $'\t')
                if [ "$in_word" -eq 1 ]; then
                    words+=("$word")
                    word=""
                    in_word=0
                fi ;;
            *) word+=$c; in_word=1 ;;
        esac
    done
    if [ "$in_word" -eq 1 ]; then
        words+=("$word")
    fi
}

# Sets `dialect` to the shell $1's `#!` line runs (sh, bash or dash), or
# to "" when it runs none of them: the first word, or for `env` the first
# word after its options (a split string, `-S STRING`, `-SSTRING` or
# `--split-string=STRING`, is split again) and NAME=value assignments.
shebang_dialect() {
    local first="" interpreter="" word
    local -a words args
    dialect=""
    IFS= read -r first < "$1" 2>/dev/null || [ -n "$first" ] || return 0
    case "$first" in
        '#!'*) ;;
        *) return 0 ;;
    esac
    split_words "${first#'#!'}"
    [ "${#words[@]}" -gt 0 ] || return 0
    interpreter=${words[0]##*/}
    if [ "$interpreter" = env ]; then
        interpreter=""
        args=("${words[@]:1}")
        while [ "${#args[@]}" -gt 0 ]; do
            word=${args[0]}
            args=("${args[@]:1}")
            case "$word" in
                --split-string=* | -S?*)
                    case "$word" in
                        --split-string=*) split_words "${word#--split-string=}" ;;
                        *) split_words "${word#-S}" ;;
                    esac
                    args=("${words[@]}" "${args[@]}") ;;
                -u | --unset | -C | --chdir) args=("${args[@]:1}") ;;
                -* | *=*) ;;
                *) interpreter=${word##*/}; break ;;
            esac
        done
    fi
    case "$interpreter" in
        sh | bash | dash) dialect=$interpreter ;;
    esac
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
dialects=()
while IFS= read -r -d '' file; do
    # A tracked file deleted from the work tree, or a link.
    if [ -L "$file" ] || [ ! -e "$file" ]; then
        continue
    fi
    # git lists a directory only for an embedded repository (an untracked
    # nested checkout, `dir/`) or a submodule: separate repositories, each
    # linted by its own checks.
    if [ -d "$file" ]; then
        continue
    fi
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        echo "check-shell: cannot read $file" >&2
        exit 1
    fi
    # A shell script by name (`*.sh`) or by its `#!` interpreter.
    shebang_dialect "$file"
    case "$file" in
        *.sh) ;;
        *) [ -n "$dialect" ] || continue ;;
    esac
    # An explicit `# shellcheck shell=` directive names the dialect itself;
    # otherwise the detected one is passed on, because shellcheck cannot
    # read every shebang this script recognises (SC1008 for `env -S 'bash'`).
    if grep -Eq '^[[:space:]]*#[[:space:]]*shellcheck[[:space:]]([^#]*[[:space:]])?shell=' "$file"; then
        dialect=""
    fi
    scripts+=("$file")
    dialects+=("$dialect")
done <"$tmp/sorted"

case "$mode" in
    list)
        if [ "${#scripts[@]}" -gt 0 ]; then
            printf '%s\n' "${scripts[@]}"
        fi
        exit 0 ;;
    list0)
        if [ "${#scripts[@]}" -gt 0 ]; then
            printf '%s\0' "${scripts[@]}"
        fi
        exit 0 ;;
esac

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

# One shellcheck run per dialect; every run happens and the worst status
# is the result.
status=0
for want in "" sh bash dash; do
    group=()
    for i in "${!scripts[@]}"; do
        if [ "${dialects[i]}" = "$want" ]; then
            group+=("${scripts[i]}")
        fi
    done
    [ "${#group[@]}" -gt 0 ] || continue
    rc=0
    if [ -z "$want" ]; then
        shellcheck --norc -- "${group[@]}" || rc=$?
    else
        shellcheck --norc --shell="$want" -- "${group[@]}" || rc=$?
    fi
    if [ "$rc" -gt "$status" ]; then
        status=$rc
    fi
done
exit "$status"
