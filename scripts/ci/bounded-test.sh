#!/bin/sh
# Cargo "runner" for the mutants job: runs a test binary under a
# virtual-memory cap (4 GiB unless QEMINGA_TEST_VMEM_KIB says otherwise),
# so a mutant that allocates without bound aborts its own test run instead
# of exhausting the runner, which GitHub then shuts down mid-job with no
# diagnostics (T5.6). Selected with CARGO_TARGET_<triple>_RUNNER; the cap
# is inherited by anything the tests spawn.
set -e
ulimit -v "${QEMINGA_TEST_VMEM_KIB:-4194304}"
exec "$@"
