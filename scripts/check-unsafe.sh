#!/usr/bin/env bash
# Enforces design §5.6: `unsafe` may appear only under src/kernel/, and every
# other Rust source file must opt out with `#![forbid(unsafe_code)]`. The
# crate root src/lib.rs uses `#![deny(unsafe_code)]` instead so that the
# kernel module can re-allow it.
#
# The compiler is the real enforcement: `forbid(unsafe_code)` rejects unsafe
# blocks, functions, impls, traits and `#[unsafe(...)]` attributes. This
# script makes sure the attribute is present everywhere it must be, covers
# crates the library's attribute does not reach (tests, benches, examples,
# build scripts, fuzz targets), and gives a fast, precise diagnostic before
# a compile.
#
# Usage: scripts/check-unsafe.sh   (exit 0 = clean, 1 = violation)
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

# Every Rust source root in the repository. Missing roots are fine; add new
# ones here when they appear.
mapfile -t files < <(
    find src tests benches examples fuzz build.rs \
        -name '*.rs' -not -path 'src/kernel/*' -not -path '*/target/*' \
        2>/dev/null | sort
)

# Remove `// ...` line comments (including `///` and `//!` doc comments) and
# single-line `/* ... */` block comments so prose about unsafe code is not
# reported as unsafe code.
strip_comments() {
    sed -e 's,//.*$,,' -e 's,/\*.*\*/,,g' "$1"
}

pattern='\bunsafe[[:space:]]*(\{|fn\b|impl\b|trait\b|extern\b)'

# 1. No unsafe blocks/fns/impls/traits/extern outside src/kernel/ (fast path;
#    the compiler check in step 2 is authoritative).
for file in "${files[@]}"; do
    if strip_comments "$file" | grep -nE "$pattern" >/dev/null; then
        echo "error: unsafe code outside src/kernel/: $file" >&2
        strip_comments "$file" | grep -nE "$pattern" | sed "s,^,  $file:," >&2
        status=1
    fi
done

# 2. Every non-kernel file carries the lint attribute the compiler enforces.
for file in "${files[@]}"; do
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
done

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
    echo "ok: no unsafe code outside src/kernel/ (${#files[@]} files checked)"
fi
exit "$status"
