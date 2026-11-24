#!/usr/bin/env bash
# Pauses nightly runs while maintenance pull requests are open: counts the
# open pull requests that watch.sh would handle (head branch in this
# repository, with the maintenance prefix; lib.sh AI_MAINTENANCE_PR_JQ) and
# outputs skip=true when there are MAX or more.
#
# Environment: GH_TOKEN, GITHUB_REPOSITORY, BRANCH_PREFIX, MAX.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

: "${GITHUB_REPOSITORY:?}" "${BRANCH_PREFIX:?}" "${MAX:?}"
case "$MAX" in '' | *[!0-9]*) ai_log "MAX must be a number"; exit 2 ;; esac
open=$(gh api --paginate "repos/$GITHUB_REPOSITORY/pulls?state=open&per_page=100" \
    --jq '.[] | {head: {ref: .head.ref, repo: {full_name: .head.repo.full_name}}}' |
    jq -s --arg repo "$GITHUB_REPOSITORY" --arg prefix "$BRANCH_PREFIX" \
        "$AI_MAINTENANCE_PR_JQ [.[] | select(maintenance_pr(\$repo; \$prefix))] | length")
echo "open maintenance pull requests: $open (limit $MAX)"
if [ "$open" -ge "$MAX" ]; then
    [ -n "${GITHUB_OUTPUT:-}" ] && echo "skip=true" >>"$GITHUB_OUTPUT"
    echo "::notice::Skipped: $open maintenance pull request(s) already open."
fi
exit 0
