#!/usr/bin/env bash
# Runs inside one attempt's container (run.sh starts it): loads the
# provider adapter and runs the agent with this attempt's key, which is the
# only credential the container receives. Writes the adapter's files to
# AI_ATTEMPT_DIR, the container's output directory.
#
#   attempt.sh ADAPTER PROMPT_FILE MODEL OPTIONS_JSON EFFORT
#
# Environment: AI_ATTEMPT_KEY, AI_ATTEMPT_DIR, AI_TOOLS_DIR, HOME, and
# AI_NODE_BIN (a directory to put first on PATH) when the runner's Node.js
# is mounted.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# The image's repository setup may leave variables here (PATH, CARGO_HOME, ...).
if [ -f /etc/ai-maintenance/env ]; then
    set -a
    # shellcheck source=/dev/null
    . /etc/ai-maintenance/env
    set +a
fi
[ -z "${AI_NODE_BIN:-}" ] || PATH=$AI_NODE_BIN:$PATH
export PATH
mkdir -p "$HOME"

# shellcheck source=lib.sh
. "$here/lib.sh"
# shellcheck source=/dev/null
. "$1"
key=${AI_ATTEMPT_KEY:-}
unset AI_ATTEMPT_KEY
provider_run "$key" "$2" "$AI_ATTEMPT_DIR/final.md" "$3" "$4" "$5"
