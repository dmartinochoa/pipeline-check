"""Generate per-standard "check -> control" mapping markdown tables.

Reads the STANDARD object from each registered standard module, sorts
mappings by check_id, and writes a markdown table to stdout (or to the
output file specified with --out).

The generated table is intended to be injected into the matching doc
under docs/standards/ between the sentinel comments

    <!-- mappings:start -->
    <!-- mappings:end -->

Re-run after changes to a standard's mappings to keep the doc in sync.

Usage:
    python scripts/gen_standards_mappings.py <standard_name> [--out PATH]

Examples:
    python scripts/gen_standards_mappings.py slsa
    python scripts/gen_standards_mappings.py nist_ssdf --out -
"""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def render_table(standard_name: str) -> str:
    mod = importlib.import_module(
        f"pipeline_check.core.standards.data.{standard_name}"
    )
    standard = mod.STANDARD
    rows = sorted(standard.mappings.items(), key=lambda kv: kv[0])

    lines = [
        "| Check | Control(s) |",
        "|-------|------------|",
    ]
    for check_id, controls in rows:
        controls_str = " · ".join(f"`{c}`" for c in controls)
        lines.append(f"| `{check_id}` | {controls_str} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("standard", help="standard module name, e.g. slsa")
    parser.add_argument(
        "--out",
        default="-",
        help='output path; "-" writes to stdout (default)',
    )
    args = parser.parse_args()

    table = render_table(args.standard)
    if args.out == "-":
        sys.stdout.write(table)
    else:
        Path(args.out).write_text(table, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
