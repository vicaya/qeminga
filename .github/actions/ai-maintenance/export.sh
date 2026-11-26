#!/usr/bin/env bash
# Runs inside a container without a key or network after a successful
# attempt (run.sh starts it): writes everything the agent changed since
# BASE, its own commits and uncommitted files alike, as one binary patch.
# The repository is the agent's copy, so its git configuration is not
# trusted; it is read here, never on the runner, and the runner only
# checks and applies the resulting patch.
#
#   export.sh BASE PATCH_FILE
set -euo pipefail

base=$1 patch=$2
git -c core.hooksPath=/dev/null add -A
git -c core.hooksPath=/dev/null diff --cached --binary --no-color --no-ext-diff --no-textconv \
    --src-prefix=a/ --dst-prefix=b/ "$base" >"$patch"
