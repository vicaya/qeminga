#!/usr/bin/env bash
# Classifies a change for CI. Reads changed paths on stdin (one per line)
# and exits 0 when every one of them is Markdown that no check reads, so
# the build, test and mutants jobs can be skipped for a documentation
# change; exits 1 otherwise. The fail-safe is to run everything: any other
# file, a Markdown file a test parses, or no paths at all is "code".
#
#   git diff --name-only "$base" "$head" | scripts/ci/docs-only.sh
#
# tests/ci_workflow.rs covers the classification.
set -euo pipefail

# Markdown that tests read: tests/packaging.rs parses the design's
# configuration block and the packaging README, so a change to either can
# turn a test red and must run the suite.
READ_BY_TESTS="docs/design.md packaging/README.md"

n=0
while IFS= read -r path; do
    [ -n "$path" ] || continue
    n=$((n + 1))
    case "$path" in
        *.md) ;;
        *) echo "code: $path" >&2; exit 1 ;;
    esac
    for f in $READ_BY_TESTS; do
        if [ "$path" = "$f" ]; then
            echo "read by tests: $path" >&2
            exit 1
        fi
    done
done
if [ "$n" -eq 0 ]; then
    echo "no changed paths known: running everything" >&2
    exit 1
fi
echo "documentation only ($n Markdown files)" >&2
