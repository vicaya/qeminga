#!/usr/bin/env python3
"""Production-line coverage gate (T5.7).

`cargo llvm-cov` instruments every line of `src/`, including the inline
`#[cfg(test)] mod tests` blocks that hold this crate's unit tests and the
test doubles that are compiled unconditionally for the integration
suites (`src/kernel/fake.rs`); test code is nearly fully covered by
construction. This script drops the inline test blocks and the excluded
files from an LCOV report and reports the coverage of the remaining
**production lines**, which is the number the floor applies to.

    scripts/ci/coverage-gate.py LCOV [--floor PERCENT] [--exclude PATH]...
                               [--json OUT] [--markdown OUT] [--filtered OUT]

A file's inline test block is the top-level `#[cfg(test)]` attribute
immediately followed by `mod tests {`; it must run to the end of the file
(the layout every module here uses), otherwise the script fails rather
than guess. `--exclude` names a file (relative to `--root`) whose lines
count as test support: it is left out of the production figure and of
the filtered report, and still counted under "all instrumented lines".

The filtered report (`--filtered`) is a line and branch report: `DA` and
`BRDA` records carry a source line and are cut at the test block, while
function records (`FN`, `FNDA`, whose first field is an execution count,
not a line, and the `FNF`/`FNH`/`FNL`/`FNA` totals) are dropped
altogether rather than filtered by the wrong field. The `LF`/`LH` and
`BRF`/`BRH` totals are recomputed from the retained records (a branch
counts as hit when its taken count is a number above zero).

Exit status 1 when the production percentage is below the floor, 2 on a
layout or input problem.
"""
import argparse
import json
import re
import sys
from pathlib import Path

MARKER = re.compile(r"^#\[cfg\(test\)\]\s*$")


def test_block_start(path: Path) -> int | None:
    """1-based line of the `#[cfg(test)]` that opens the inline test module."""
    try:
        lines = path.read_text(encoding="utf-8").split("\n")
    except OSError:
        return None
    for i, line in enumerate(lines):
        if MARKER.match(line) and i + 1 < len(lines) and lines[i + 1].startswith("mod tests"):
            # The module must be the last top-level item: after `mod tests {`
            # every non-empty line is indented, except the closing brace.
            for j, rest in enumerate(lines[i + 2 :], start=i + 3):
                if rest and not rest[0].isspace() and rest.rstrip() != "}":
                    print(
                        f"coverage-gate: {path}:{j}: top-level code after the inline test module",
                        file=sys.stderr,
                    )
                    sys.exit(2)
            return i + 1
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("lcov")
    ap.add_argument("--floor", type=float, default=None)
    ap.add_argument("--json")
    ap.add_argument("--markdown")
    ap.add_argument("--filtered", help="write the LCOV without inline test lines")
    ap.add_argument("--root", default=".", help="repository root the LCOV paths are relative to")
    ap.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATH",
        help="test-support file (relative to --root) left out of the production figure",
    )
    args = ap.parse_args()

    root = Path(args.root).resolve()
    excluded = {(root / p).resolve() for p in args.exclude}
    excluded_seen = []
    all_found = all_hit = prod_found = prod_hit = 0
    per_file = []
    out_lines = []
    current = None
    cutoff = None
    skip_file = False
    file_found = file_hit = 0
    br_found = br_hit = 0
    for raw in Path(args.lcov).read_text(encoding="utf-8").splitlines():
        if raw.startswith("SF:"):
            p = Path(raw[3:])
            current = p if p.is_absolute() else root / p
            rel = current.relative_to(root) if str(current).startswith(str(root)) else current
            skip_file = current.resolve() in excluded
            if skip_file:
                excluded_seen.append(str(rel))
            cutoff = None if skip_file else test_block_start(current)
            file_found = file_hit = 0
            br_found = br_hit = 0
            if not skip_file:
                out_lines.append(raw)
            continue
        if raw.startswith("DA:"):
            line, hits = raw[3:].split(",")[:2]
            line = int(line)
            hit = int(hits) > 0
            all_found += 1
            all_hit += hit
            if skip_file or (cutoff is not None and line >= cutoff):
                continue
            prod_found += 1
            prod_hit += hit
            file_found += 1
            file_hit += hit
            out_lines.append(raw)
            continue
        if raw.startswith("BRDA:"):
            # BRDA:<line>,<block>,<branch>,<taken>: cut at the test block.
            fields = raw[5:].split(",")
            line = int(fields[0])
            if skip_file or (cutoff is not None and line >= cutoff):
                continue
            br_found += 1
            br_hit += fields[3].isdigit() and int(fields[3]) > 0
            out_lines.append(raw)
            continue
        if raw.startswith(("FN:", "FNDA:", "FNF:", "FNH:", "FNL:", "FNA:")):
            continue  # function records: not a line report, see the module docstring
        if raw.startswith(("LF:", "LH:", "BRF:", "BRH:")):
            continue  # recomputed below
        if raw == "end_of_record":
            if current is not None and not skip_file:
                per_file.append((str(rel), file_found, file_hit))
                if br_found:
                    out_lines.append(f"BRF:{br_found}")
                    out_lines.append(f"BRH:{br_hit}")
                out_lines.append(f"LF:{file_found}")
                out_lines.append(f"LH:{file_hit}")
                out_lines.append(raw)
            current = None
            skip_file = False
            continue
        if not skip_file:
            out_lines.append(raw)

    if all_found == 0:
        print("coverage-gate: no line records in the LCOV input", file=sys.stderr)
        sys.exit(2)
    pct = lambda h, f: (100.0 * h / f) if f else 0.0
    all_pct = pct(all_hit, all_found)
    prod_pct = pct(prod_hit, prod_found)
    summary = {
        "all_lines": {"found": all_found, "hit": all_hit, "percent": round(all_pct, 2)},
        "production_lines": {"found": prod_found, "hit": prod_hit, "percent": round(prod_pct, 2)},
        "floor_percent": args.floor,
        "passed": args.floor is None or prod_pct >= args.floor,
        "excluded": sorted(excluded_seen),
    }
    md = [
        "| Scope | Lines | Covered | Coverage |",
        "|---|---|---|---|",
        f"| Production lines (inline `mod tests` and test doubles excluded) | {prod_found} | {prod_hit} | **{prod_pct:.1f}%** |",
        f"| All instrumented lines | {all_found} | {all_hit} | {all_pct:.1f}% |",
    ]
    if args.floor is not None:
        md.append(f"| Floor (production lines) | | | {args.floor:g}% |")
    md.append("")
    if excluded_seen:
        md.append("Test-support files excluded from the production figure: " + ", ".join(f"`{p}`" for p in sorted(excluded_seen)))
        md.append("")
    md.append("<details><summary>Per file (production lines)</summary>")
    md.append("")
    md.append("| File | Lines | Coverage |")
    md.append("|---|---|---|")
    for name, found, hit in sorted(per_file):
        md.append(f"| `{name}` | {found} | {pct(hit, found):.1f}% |")
    md.append("")
    md.append("</details>")
    text = "\n".join(md) + "\n"
    print(text)
    if args.markdown:
        Path(args.markdown).write_text(text, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if args.filtered:
        Path(args.filtered).write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    if args.floor is not None and prod_pct < args.floor:
        print(f"coverage-gate: production-line coverage {prod_pct:.2f}% is below the floor {args.floor:g}%", file=sys.stderr)
        return 1
    print(f"coverage-gate: production-line coverage {prod_pct:.2f}%" + (f" (floor {args.floor:g}%)" if args.floor is not None else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
