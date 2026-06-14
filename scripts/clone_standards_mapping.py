"""Clone an existing rule's standards mappings onto a new rule.

When a new rule mirrors an existing one (a cross-provider parity rule, a
new member of an established family), it should carry the *same* control
IDs in every standard the analog is mapped to. Doing that by hand means
opening each ``pipeline_check/core/standards/data/*.py`` file, finding the
analog's line, reading off that standard's control IDs, and inserting a
matching line for the new rule. This script does exactly that, per
standard, so the per-standard control sets are copied verbatim and nothing
is missed.

It clones ONLY the standards each analog is already mapped to: a rule that
maps to 10 standards yields 10 new entries, one that maps to 12 yields 12.
This preserves the deliberate "which standards does this kind of rule
belong in" decision the analog already encodes.

Usage::

    # Preview (default): print the line that would be added to each file.
    python scripts/clone_standards_mapping.py HARNESS-012 HARNESS-013 \\
        --comment "Harness secret echoed to step log"

    # Write the entries in place (each inserted right after the analog's
    # line so it stays grouped with its provider block).
    python scripts/clone_standards_mapping.py HARNESS-012 HARNESS-013 \\
        --comment "Harness secret echoed to step log" --apply

The new rule's own standards membership is still your call: pick an analog
whose mapping set matches the rule you're adding (the trust_remote_code
family maps to 12 standards, the model-pinning family to 8, the log-leak
family to 10, ...). After ``--apply``, run ``pytest tests/test_standards.py``
and regenerate the standards docs.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "pipeline_check" / "core" / "standards" / "data"

_RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-\d+$")


def _entry_re(rule_id: str) -> re.Pattern[str]:
    """Match a ``"<rule_id>": [<controls>],`` mapping line."""
    return re.compile(
        r'^(?P<indent>\s*)"(?P<id>' + re.escape(rule_id) + r')"\s*:\s*'
        r'(?P<controls>\[[^\]]*\])\s*,'
        r'(?P<trailing>.*)$'
    )


@dataclass
class Planned:
    """One planned insertion in one standards-data file."""

    path: Path
    after_line: int          # 1-based line number of the analog entry
    new_line: str            # the full line to insert (no trailing newline)
    controls: str            # the cloned ``[...]`` controls literal


def plan_clone(
    analog_id: str,
    new_id: str,
    comment: str,
    *,
    data_dir: Path = DATA_DIR,
) -> tuple[list[Planned], list[str]]:
    """Return (planned insertions, warnings) for cloning *analog_id*.

    For every ``data/*.py`` file that maps ``analog_id``, build a line that
    maps ``new_id`` to the same control literal. Files where ``analog_id``
    is absent are skipped (the analog isn't in that standard, so neither is
    the clone).
    """
    analog_re = _entry_re(analog_id)
    exists_re = _entry_re(new_id)
    planned: list[Planned] = []
    warnings: list[str] = []
    comment_suffix = f"  # {comment}" if comment else ""

    for path in sorted(data_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        analog_hits = [
            (i, m) for i, line in enumerate(lines)
            if (m := analog_re.match(line))
        ]
        if not analog_hits:
            continue
        if any(exists_re.match(line) for line in lines):
            warnings.append(
                f"{path.name}: {new_id} already mapped here; skipped."
            )
            continue
        if len(analog_hits) > 1:
            warnings.append(
                f"{path.name}: {analog_id} appears {len(analog_hits)} times; "
                f"cloning after the first."
            )
        idx, m = analog_hits[0]
        controls = m.group("controls")
        new_line = f'{m.group("indent")}"{new_id}":  {controls},{comment_suffix}'
        planned.append(Planned(
            path=path, after_line=idx + 1, new_line=new_line, controls=controls,
        ))
    return planned, warnings


def apply_plan(planned: list[Planned]) -> None:
    """Insert each planned line into its file (after the analog line)."""
    by_path: dict[Path, list[Planned]] = {}
    for p in planned:
        by_path.setdefault(p.path, []).append(p)
    for path, items in by_path.items():
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        # Insert from the bottom up so earlier indices stay valid.
        for item in sorted(items, key=lambda p: p.after_line, reverse=True):
            nl = "\n"
            # Match the newline style of the anchor line if possible.
            anchor = lines[item.after_line - 1]
            if anchor.endswith("\r\n"):
                nl = "\r\n"
            lines.insert(item.after_line, item.new_line + nl)
        path.write_text("".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("analog_id", help="rule whose mappings to clone (e.g. HARNESS-012)")
    parser.add_argument("new_id", help="new rule to map (e.g. HARNESS-013)")
    parser.add_argument(
        "--comment", default="",
        help="trailing ``# ...`` comment for each new entry",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="write the entries in place (default: print a dry run)",
    )
    args = parser.parse_args(argv)

    for label, value in (("analog_id", args.analog_id), ("new_id", args.new_id)):
        if not _RULE_ID_RE.match(value):
            parser.error(f"{label} {value!r} is not a PREFIX-NNN rule id")

    planned, warnings = plan_clone(
        args.analog_id, args.new_id, args.comment, data_dir=DATA_DIR,
    )
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not planned:
        print(
            f"No standard maps {args.analog_id}; nothing to clone.",
            file=sys.stderr,
        )
        return 1

    if args.apply:
        apply_plan(planned)
        print(
            f"Mapped {args.new_id} into {len(planned)} standard(s), cloned "
            f"from {args.analog_id}:"
        )
        for p in planned:
            print(f"  {p.path.name}: {p.controls}")
        print(
            "\nNext: pytest tests/test_standards.py, then regenerate the "
            "standards docs (python scripts/gen_standards_docs.py)."
        )
    else:
        print(
            f"# DRY RUN. {args.new_id} would be mapped into {len(planned)} "
            f"standard(s), cloned from {args.analog_id}.\n"
            f"# Pass --apply to write these entries.\n"
        )
        for p in planned:
            print(f"--- {p.path.name} (after line {p.after_line})")
            print(p.new_line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
