#!/usr/bin/env bash
# Enforces design §5.6: `unsafe` may appear only under src/kernel/, and every
# other source file must opt out with `#![forbid(unsafe_code)]` (the crate
# root uses `#![deny(unsafe_code)]` so that the kernel module can re-allow).
#
# Usage: scripts/check-unsafe.sh   (exit 0 = clean, 1 = violation)
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

# 1. No `unsafe` blocks/fns/impls/traits/extern outside src/kernel/.
while IFS= read -r file; do
    if grep -nE '\bunsafe[[:space:]]*(\{|fn\b|impl\b|trait\b|extern\b)' "$file" >/dev/null; then
        echo "error: unsafe code outside src/kernel/: $file" >&2
        grep -nE '\bunsafe[[:space:]]*(\{|fn\b|impl\b|trait\b|extern\b)' "$file" >&2
        status=1
    fi
done < <(find src -name '*.rs' -not -path 'src/kernel/*' | sort)

# 2. Every non-root, non-kernel module forbids unsafe_code; the crate root
#    (src/lib.rs) must deny it.
while IFS= read -r file; do
    case "$file" in
        src/lib.rs)
            if ! grep -qE '^#!\[deny\(unsafe_code\)\]' "$file"; then
                echo "error: $file must contain #![deny(unsafe_code)]" >&2
                status=1
            fi
            ;;
        *)
            if ! grep -qE '^#!\[forbid\(unsafe_code\)\]' "$file"; then
                echo "error: $file must contain #![forbid(unsafe_code)]" >&2
                status=1
            fi
            ;;
    esac
done < <(find src -name '*.rs' -not -path 'src/kernel/*' | sort)

# 3. Every unsafe block inside src/kernel/ must carry a SAFETY comment. Clippy's
#    `undocumented_unsafe_blocks` lint enforces this precisely; this is only a
#    coarse belt-and-braces check that the module is not empty of comments.
if [ -d src/kernel ]; then
    if grep -rlE '\bunsafe[[:space:]]*\{' src/kernel >/dev/null && \
       ! grep -rq 'SAFETY:' src/kernel; then
        echo "error: src/kernel/ contains unsafe blocks but no SAFETY: comments" >&2
        status=1
    fi
fi

if [ "$status" -eq 0 ]; then
    echo "ok: no unsafe code outside src/kernel/"
fi
exit "$status"
