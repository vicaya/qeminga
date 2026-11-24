#!/usr/bin/env bash
# Runs inside a container of the sandbox image (run.sh starts it, once per
# provider): installs that provider's CLI into AI_TOOLS_DIR, the only
# directory of the runner it can see and write. No key, prompt or other
# file of the run is mounted, so package install scripts (npm lifecycle
# scripts, for one) run without anything to take. The attempts then mount
# AI_TOOLS_DIR read-only.
#
#   install.sh ADAPTER
#
# Environment: AI_TOOLS_DIR, HOME, AI_NODE_BIN and AI_NPM_CLI (the
# runner's Node.js and npm, mounted read-only), and the variables the
# adapter lists in PROVIDER_INSTALL_ENV (versions, download pins).
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"
ai_sandbox_env
# shellcheck source=/dev/null
. "$1"
provider_install
