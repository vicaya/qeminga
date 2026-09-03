#!/usr/bin/env bash
# Coverage measurement and floor (T5.7); the same command locally and in CI.
#
#   scripts/ci/coverage.sh [OUT_DIR]
#
# Runs every unprivileged suite under cargo-llvm-cov with COVERAGE_FEATURES
# (default seccomp-log,suspend_ram,test-fakes: the LLVM profile runtime
# calls prctl(2) with an argument the enforced filter refuses, so an
# enforced, instrumented daemon is killed before it writes its profile;
# the enforced filter is exercised by the privileged suite), writes into
# OUT_DIR (default: target/coverage): lcov.info (all instrumented lines),
# lcov-production.info (inline `mod tests` blocks removed), coverage.json
# (cargo-llvm-cov totals), coverage-summary.json and coverage-summary.md
# (production-line figures), coverage.log (test output). The reports are
# always written; the exit status is the floor check on production lines
# (COVERAGE_FLOOR_LINES, default 85).
set -euo pipefail
out=${1:-target/coverage}
features=${COVERAGE_FEATURES:-seccomp-log,suspend_ram,test-fakes}
floor=${COVERAGE_FLOOR_LINES:-85}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
status=0
cargo llvm-cov --features "$features" --locked --lcov --output-path "$out/lcov.info" 2>&1 | tee "$out/coverage.log" || status=$?
if [ "$status" -ne 0 ]; then
    echo "coverage.sh: tests failed under cargo llvm-cov (status $status)" >&2
    exit "$status"
fi
cargo llvm-cov report --json --summary-only --output-path "$out/coverage.json"
python3 "$here/coverage-gate.py" "$out/lcov.info" --floor "$floor" \
    --json "$out/coverage-summary.json" --markdown "$out/coverage-summary.md" \
    --filtered "$out/lcov-production.info"
