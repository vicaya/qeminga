#!/usr/bin/env bash
# Runs inside one attempt's container (run.sh starts it): loads the
# provider adapter and runs the agent with this attempt's key, which is the
# only credential the container receives. Writes the adapter's files to
# AI_ATTEMPT_DIR, the container's output directory.
#
#   attempt.sh ADAPTER PROMPT_FILE MODEL OPTIONS_FILE EFFORT
#
# OPTIONS_FILE holds the pool entry's options (JSON); the adapter gets them
# as a value, never as a process argument.
#
# Environment: AI_ATTEMPT_KEY, AI_ATTEMPT_DIR, AI_TOOLS_DIR, HOME, and
# AI_NODE_BIN (a directory to put first on PATH) when the runner's Node.js
# is mounted.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=.github/actions/ai-maintenance/lib.sh
. "$here/lib.sh"
ai_sandbox_env
# shellcheck source=/dev/null
. "$1"
key=${AI_ATTEMPT_KEY:-}
unset AI_ATTEMPT_KEY
options=$(cat "$4") || exit 2
provider_run "$key" "$2" "$AI_ATTEMPT_DIR/final.md" "$3" "$options" "$5"
