#!/usr/bin/env bash
# Manual libvirt interoperability check (design AC16, §3; task T5.4).
#
# Runs, against a named domain that has qeminga installed and running:
#   virsh domfsfreeze, virsh domfsthaw, virsh domifaddr --source agent,
#   virsh qemu-agent-command guest-info / guest-ping, and finally
#   virsh domshutdown --mode agent (unless --no-shutdown).
# Exits non-zero unless every step succeeds. Writes a log to stdout that
# can be attached to the pull request.
#
#   scripts/e2e-libvirt.sh [--connect URI] [--no-shutdown] DOMAIN
#
# Hosted CI has no nested virtualisation, so this stays a manual job; see
# docs/testing.md for the VM recipe.
set -euo pipefail

connect=""
shutdown=1
while [ $# -gt 0 ]; do
    case "$1" in
        --connect) connect="--connect=$2"; shift 2 ;;
        --no-shutdown) shutdown=0; shift ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) break ;;
    esac
done
[ $# -eq 1 ] || { echo "usage: $0 [--connect URI] [--no-shutdown] DOMAIN" >&2; exit 64; }
domain="$1"

v() { virsh ${connect:+"$connect"} "$@"; }

fail=0
step() {
    local name="$1"; shift
    echo "== $name: $*"
    if out="$("$@" 2>&1)"; then
        echo "$out"
        echo "-- ok: $name"
    else
        echo "$out"
        echo "-- FAILED: $name"
        fail=1
    fi
}

echo "qeminga libvirt interoperability run: $(date -u +%Y-%m-%dT%H:%M:%SZ) domain=$domain host=$(hostname)"
v version | sed 's/^/# /' || true

step "guest-ping" v qemu-agent-command "$domain" '{"execute":"guest-ping"}'
step "guest-info" v qemu-agent-command "$domain" '{"execute":"guest-info"}'
info="$(v qemu-agent-command "$domain" '{"execute":"guest-info"}' 2>/dev/null || true)"
case "$info" in
    *'"supported_commands"'*) echo "-- guest-info advertises supported_commands" ;;
    *) echo "-- FAILED: guest-info lacks supported_commands"; fail=1 ;;
esac
case "$info" in
    *'guest-exec'*) echo "-- FAILED: guest-exec must not be advertised"; fail=1 ;;
    *) echo "-- guest-exec is not advertised" ;;
esac

step "guest-exec is refused (AC1)" bash -c "v qemu-agent-command '$domain' '{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\"/bin/true\"}}' 2>&1 | grep -q CommandNotFound"

step "domfsfreeze" v domfsfreeze "$domain"
step "guest-fsfreeze-status is frozen" bash -c "v qemu-agent-command '$domain' '{\"execute\":\"guest-fsfreeze-status\"}' | grep -q frozen"
step "domfsthaw" v domfsthaw "$domain"
step "guest-fsfreeze-status is thawed" bash -c "v qemu-agent-command '$domain' '{\"execute\":\"guest-fsfreeze-status\"}' | grep -q thawed"
step "domifaddr --source agent" v domifaddr "$domain" --source agent
step "guest-get-osinfo" v qemu-agent-command "$domain" '{"execute":"guest-get-osinfo"}'
step "domfsinfo" v domfsinfo "$domain"

if [ "$shutdown" -eq 1 ]; then
    step "domshutdown --mode agent" v domshutdown "$domain" --mode agent
    echo "== waiting up to 120 s for the domain to stop"
    for _ in $(seq 1 120); do
        if ! v domstate "$domain" | grep -q running; then break; fi
        sleep 1
    done
    if v domstate "$domain" | grep -q running; then
        echo "-- FAILED: domain still running after domshutdown --mode agent"
        fail=1
    else
        echo "-- ok: domain stopped"
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "RESULT: PASS (AC16)"
else
    echo "RESULT: FAIL"
fi
exit "$fail"
