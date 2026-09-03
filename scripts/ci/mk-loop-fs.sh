#!/usr/bin/env bash
# Creates (or tears down) loop-mounted ext4 and xfs filesystems for the
# privileged tests (T5.2, AC2, AC17). Must run as root.
#
#   eval "$(scripts/ci/mk-loop-fs.sh setup)"    # prints export lines
#   scripts/ci/mk-loop-fs.sh teardown
#
# Exports QEMINGA_TEST_EXT4_MOUNT and, when mkfs.xfs exists,
# QEMINGA_TEST_XFS_MOUNT. The ext4 mountpoint is mode 0700 so the freeze
# path exercises CAP_DAC_READ_SEARCH (AC17, D7); a bind mount of it is
# created too so de-duplication is exercised (AC17).
set -euo pipefail

BASE="${QEMINGA_LOOP_BASE:-/mnt/qeminga-test}"
SIZE_MB="${QEMINGA_LOOP_SIZE_MB:-64}"
STATE="$BASE/.state"

setup() {
    mkdir -p "$BASE" "$STATE"
    for fs in ext4 xfs; do
        if [ "$fs" = xfs ] && ! command -v mkfs.xfs >/dev/null; then
            echo "# mkfs.xfs not found; skipping xfs" >&2
            continue
        fi
        img="$BASE/$fs.img"
        mnt="$BASE/$fs"
        rm -f "$img"
        truncate -s "${SIZE_MB}M" "$img"
        if [ "$fs" = ext4 ]; then mkfs.ext4 -q "$img"; else mkfs.xfs -q "$img"; fi
        loop="$(losetup --find --show "$img")"
        echo "$loop" > "$STATE/$fs.loop"
        mkdir -p "$mnt"
        chmod 0700 "$mnt"
        mount "$loop" "$mnt"
        chmod 0700 "$mnt"
        upper="$(echo "$fs" | tr '[:lower:]' '[:upper:]')"
        echo "export QEMINGA_TEST_${upper}_MOUNT=$mnt"
    done
    # A bind mount of the ext4 filesystem (same superblock, AC17).
    if [ -d "$BASE/ext4" ] && mountpoint -q "$BASE/ext4"; then
        mkdir -p "$BASE/ext4-bind"
        mount --bind "$BASE/ext4" "$BASE/ext4-bind"
        echo "export QEMINGA_TEST_EXT4_BIND=$BASE/ext4-bind"
    fi
}

teardown() {
    for m in "$BASE/ext4-bind" "$BASE/ext4" "$BASE/xfs"; do
        if mountpoint -q "$m" 2>/dev/null; then umount "$m" || umount -l "$m"; fi
    done
    for f in "$STATE"/*.loop; do
        [ -e "$f" ] || continue
        losetup -d "$(cat "$f")" 2>/dev/null || true
        rm -f "$f"
    done
    rm -rf "$BASE"
}

case "${1:-setup}" in
    setup) setup ;;
    teardown) teardown ;;
    *) echo "usage: $0 setup|teardown" >&2; exit 64 ;;
esac
