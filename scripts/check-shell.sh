#!/usr/bin/env bash
# Lints every shell script in the repository with shellcheck: the CI
# helpers under scripts/ci/, the policy and interoperability scripts under
# scripts/, and any other file that is a shell script by name (`*.sh`) or
# by its `#!` line (sh, bash, dash). Build output (`target/`) and `.git/`
# are skipped. Findings of every severity fail; a deliberate exception is
# a `# shellcheck disable=SCxxxx # reason` directive directly above the
# command it covers.
#
# Usage: scripts/check-shell.sh          (exit 0 = clean, 1 = findings)
#        scripts/check-shell.sh --list   (print the scripts it would lint)
#
# tests/ci_workflow.rs checks that the listing covers every shell script.
set -euo pipefail

cd "$(dirname "$0")/.."

is_shell_script() {
    local first
    case "$1" in
        *.sh) return 0 ;;
    esac
    IFS= read -r first < "$1" 2>/dev/null || [ -n "${first:-}" ] || return 1
    case "$first" in
        '#!'*/sh | '#!'*/bash | '#!'*/dash | '#!'*' sh' | '#!'*' bash' | '#!'*' dash') return 0 ;;
    esac
    return 1
}

scripts=()
while IFS= read -r -d '' file; do
    file=${file#./}
    if is_shell_script "$file"; then
        scripts+=("$file")
    fi
done < <(find . \( -name target -o -name .git \) -prune -o -type f -print0 | sort -z)

if [ "${1:-}" = --list ]; then
    printf '%s\n' "${scripts[@]}"
    exit 0
fi

if [ "${#scripts[@]}" -eq 0 ]; then
    echo "check-shell: no shell scripts found" >&2
    exit 1
fi
command -v shellcheck >/dev/null || {
    echo "check-shell: shellcheck is not on PATH (apt-get install shellcheck)" >&2
    exit 1
}
echo "check-shell: $(shellcheck --version | sed -n 's/^version: //p'), ${#scripts[@]} scripts"
shellcheck "${scripts[@]}"
