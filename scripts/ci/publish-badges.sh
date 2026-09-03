#!/bin/sh
# Publishes the coverage and test-count badges for one source branch to
# the `badges` branch of the repository, under `<branch>/`, so a private
# repository can show them in its README without an external service.
#
#   scripts/ci/publish-badges.sh BRANCH coverage-summary.json coverage.log
#
# coverage-summary.json is written by scripts/ci/coverage-gate.py (the
# badge shows its production-line percentage); coverage.log is the
# captured test output (its "test result:" lines are summed).
#
# Every publication is generated on top of the current tip of the badges
# branch and pushed with a plain fast-forward. If the push is rejected
# because another publication landed meanwhile, the tip is fetched again
# and the files are regenerated on top of it; nothing is ever rebased or
# merged. Environment:
#   BADGES_REMOTE    git remote to push to (default: origin)
#   BADGES_BRANCH    branch that holds the badges (default: badges)
#   BADGES_ATTEMPTS  push attempts before giving up (default: 5)
#   BADGES_BEFORE_PUSH  a command run before each push attempt (tests use
#                       it to simulate a concurrent publication)
#   GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL (and COMMITTER) for the commit
set -eu

branch=${1:?branch}
summary_json=${2:?coverage-summary.json}
coverage_log=${3:?coverage.log}
remote=${BADGES_REMOTE:-origin}
badges_branch=${BADGES_BRANCH:-badges}
attempts=${BADGES_ATTEMPTS:-5}
here=$(cd "$(dirname "$0")" && pwd)

percent=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["production_lines"]["percent"])' "$summary_json")
percent=$(printf '%s' "$percent" | awk '{printf "%.1f", $1}')
passed=$(grep -E '^test result: ok\.' "$coverage_log" \
    | sed -E 's/^test result: ok\. ([0-9]+) passed.*/\1/' \
    | awk '{s += $1} END {print s + 0}')
whole=${percent%.*}
if [ "$whole" -ge 90 ]; then color=brightgreen
elif [ "$whole" -ge 80 ]; then color=green
elif [ "$whole" -ge 70 ]; then color=yellowgreen
elif [ "$whole" -ge 60 ]; then color=yellow
else color=red
fi
sha=$(git rev-parse --short HEAD)

work=$(mktemp -d)
cleanup() { git worktree remove --force "$work" 2>/dev/null || rm -rf "$work"; }
trap cleanup EXIT INT TERM

n=0
while :; do
    n=$((n + 1))
    git worktree remove --force "$work" 2>/dev/null || true
    rm -rf "$work"
    if git fetch -q "$remote" "$badges_branch" 2>/dev/null; then
        git worktree add -q --detach "$work" FETCH_HEAD
    else
        # First publication: an empty orphan branch.
        git worktree add -q --detach "$work"
        (cd "$work" && git checkout -q --orphan "$badges_branch" && git rm -rfq . >/dev/null)
    fi

    out="$work/$branch"
    mkdir -p "$out"
    "$here/badge.sh" coverage "${percent}%" "$color" > "$out/coverage.svg"
    "$here/badge.sh" tests "$passed passed" brightgreen > "$out/tests.svg"
    printf '{"branch":"%s","commit":"%s","production_lines_percent":%s,"tests_passed":%s}\n' \
        "$branch" "$sha" "$percent" "$passed" > "$out/summary.json"

    if ! git -C "$work" add -A || git -C "$work" diff --cached --quiet; then
        echo "badges unchanged for $branch (coverage ${percent}%, ${passed} tests)"
        exit 0
    fi
    git -C "$work" commit -q -m "badges: $branch at $sha (${percent}% production lines, ${passed} tests)"
    if [ -n "${BADGES_BEFORE_PUSH:-}" ]; then
        sh -c "$BADGES_BEFORE_PUSH"
    fi
    if git -C "$work" push -q "$remote" "HEAD:refs/heads/$badges_branch" 2>/dev/null; then
        echo "published $branch to $remote/$badges_branch (coverage ${percent}%, ${passed} tests, commit $sha, attempt $n)"
        exit 0
    fi
    if [ "$n" -ge "$attempts" ]; then
        echo "publish-badges: push rejected $n times; giving up" >&2
        exit 1
    fi
    echo "publish-badges: push rejected (another publication landed); regenerating on the new tip"
done
