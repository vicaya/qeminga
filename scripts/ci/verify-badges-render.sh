#!/bin/sh
# Checks that the README badges render in the repository as GitHub shows
# it: fetch the README rendered by GitHub (the same HTML the web page
# embeds), extract the badge image URLs GitHub rewrote, replace the
# `badges/main/` path by the directory just published for BRANCH, and
# require that each URL answers 200 with an SVG image content type for
# an authenticated client (the repository is private).
#
#   GH_TOKEN=... scripts/ci/verify-badges-render.sh OWNER/REPO BRANCH
set -eu
repo=${1:?owner/repo}
branch=${2:?branch}
html=$(curl -sS -f -H "Authorization: Bearer ${GH_TOKEN:?}" \
    -H "Accept: application/vnd.github.html+json" \
    "https://api.github.com/repos/$repo/readme?ref=$branch")
urls=$(printf '%s' "$html" | grep -o '<img[^>]*src="[^"]*"' | sed -E 's/.*src="([^"]*)".*/\1/' \
    | grep -E 'coverage\.svg|tests\.svg' || true)
if [ -z "$urls" ]; then
    echo "verify-badges-render: no badge <img> in the rendered README:" >&2
    printf '%s\n' "$html" | grep -o '<img[^>]*>' >&2 || true
    exit 1
fi
status=0
for url in $urls; do
    url=$(printf '%s' "$url" | sed 's|&amp;|\&|g')
    case "$url" in
        *camo.githubusercontent.com*)
            # A Camo URL embeds the original address; it cannot be
            # re-pointed at another branch directory. Fetch it as is only
            # when it already names the published directory.
            target=$url ;;
        *) target=$(printf '%s' "$url" | sed "s|/badges/main/|/badges/$branch/|") ;;
    esac
    # Fetch as a signed-in viewer would: GitHub serves private raw content
    # only to an authenticated client (a browser sends the session cookie,
    # this check sends the token) and redirects to raw.githubusercontent.
    headers=$(curl -sS -o /dev/null -D - -L -H "Authorization: Bearer ${GH_TOKEN}" "$target" || true)
    code=$(printf '%s' "$headers" | grep -i '^HTTP/' | tail -1 | awk '{print $2}')
    ctype=$(printf '%s' "$headers" | grep -i '^content-type:' | tail -1 | tr -d '\r')
    echo "$target -> $code ${ctype:-?}"
    case "$code:$ctype" in
        200:*image/svg*) ;;
        *) status=1 ;;
    esac
done
if [ "$status" -ne 0 ]; then
    echo "verify-badges-render: a badge does not render as an SVG image (see above)" >&2
fi
exit "$status"
