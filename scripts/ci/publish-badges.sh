#!/bin/sh
# Publishes the coverage and test-count badges for one branch to the
# `badges` branch of the repository (path `<branch>/`), so a private
# repository can show them in its README without an external service.
#
#   scripts/ci/publish-badges.sh BRANCH coverage.json coverage.log
#
# coverage.json is `cargo llvm-cov report --json --summary-only`;
# coverage.log is the captured `cargo llvm-cov` test output (the
# "test result:" lines are summed). Environment:
#   BADGES_REMOTE   git remote to push to (default: origin)
#   BADGES_BRANCH   branch that holds the badges (default: badges)
#   GIT_AUTHOR_NAME / GIT_AUTHOR_EMAIL (and COMMITTER) for the commit
set -eu

branch=${1:?branch}
coverage_json=${2:?coverage.json}
coverage_log=${3:?coverage.log}
remote=${BADGES_REMOTE:-origin}
badges_branch=${BADGES_BRANCH:-badges}
here=$(cd "$(dirname "$0")" && pwd)

percent=$(jq -r '.data[0].totals.lines.percent' "$coverage_json")
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
printf '{"branch":"%s","commit":"%s","lines_percent":%s,"tests_passed":%s}\n' \
    "$branch" "$sha" "$percent" "$passed" > "$out/summary.json"
echo "coverage ${percent}% (${color}), ${passed} tests passed, commit ${sha}"

cd "$work"
git add -A
if git diff --cached --quiet; then
    echo "badges unchanged"
    exit 0
fi
git commit -q -m "badges: $branch at $sha (${percent}% lines, ${passed} tests)"
n=0
until git push -q "$remote" "HEAD:refs/heads/$badges_branch"; do
    n=$((n + 1))
    [ "$n" -lt 4 ] || { echo "push failed after $n attempts" >&2; exit 1; }
    git fetch -q "$remote" "$badges_branch" && git rebase -q FETCH_HEAD
done
echo "published to $remote/$badges_branch/$branch"
