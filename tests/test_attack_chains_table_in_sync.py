"""Drift guard for the hand-edited chain table in ``docs/attack_chains.md``.

The catalog page carries two surfaces that name every registered
chain:

  * **Auto-generated detail block** between
    ``<!-- chain-catalog:start -->`` / ``<!-- chain-catalog:end -->``.
    ``scripts/gen_attack_chains_doc.py`` re-renders this from the
    live registry; ``tests/test_generated_docs_in_sync.py`` already
    fails when it drifts.
  * **Hand-edited summary table** above the catalog block (split
    into ``### Single-provider chains`` and ``### Cross-provider
    chains`` sections). The table is human-curated prose: the
    ``Providers`` and ``Triggering checks`` columns express the
    chain's intent in a way the generator's terse rendering
    doesn't. The cost is that contributors must remember to add a
    row when they add a chain.

The v1.3.0 cycle landed AC-028 and AC-029 without their table
rows, then the Argo CD pack landed without an AC-030 / AC-031
row. The drift went undetected for several PRs.

This test parses the table region (everything between the
``## Registered chains`` heading and the ``## How chains surface
in output`` heading) and asserts that every chain ID returned by
``chains.list_rules()`` appears as a leading-cell entry on a
table row, AND that no orphan IDs appear in the table that the
registry doesn't know about. The auto-generated detail block is
explicitly excluded so a registry chain isn't allowed to "count"
toward the table coverage just because the generator wrote a
detail card for it.
"""
from __future__ import annotations

import re
from pathlib import Path

from pipeline_check.core import chains as chains_pkg

REPO = Path(__file__).resolve().parent.parent
DOC_PATH = REPO / "docs" / "attack_chains.md"

# Leading-cell shape: ``| [`AC-031`](#ac-031) |`` or ``| [`XPC-010`](#xpc-010) |``.
# Anchored to ``^\|`` so it only matches the actual row-leading cell;
# inner-cell references to a chain id elsewhere in the same line don't
# pollute the count.
_ROW_LEADING_ID = re.compile(
    r"^\|\s*\[`((?:AC|XPC)-\d+)`\]",
    re.MULTILINE,
)


def _table_region() -> str:
    """Return the slice of attack_chains.md between the registered-chains
    heading and the chain-catalog generator block. Excludes both the
    intro narrative above the AC table and the auto-rendered detail
    cards below the XPC table."""
    text = DOC_PATH.read_text(encoding="utf-8")
    start_marker = "## Registered chains"
    end_marker = "## How chains surface in output"
    start = text.find(start_marker)
    end = text.find(end_marker)
    assert start != -1, (
        f"{DOC_PATH.relative_to(REPO)} no longer carries the "
        f"'{start_marker}' heading; update the table-sync test."
    )
    assert end != -1, (
        f"{DOC_PATH.relative_to(REPO)} no longer carries the "
        f"'{end_marker}' heading; update the table-sync test."
    )
    return text[start:end]


def _ids_in_table() -> set[str]:
    return set(_ROW_LEADING_ID.findall(_table_region()))


def _ids_in_registry() -> set[str]:
    return {rule.id for rule in chains_pkg.list_rules()}


def test_every_registered_chain_has_a_table_row() -> None:
    """A chain that ships in ``chains/rules/`` must also appear as a
    leading-cell entry in the hand-edited chain table.

    The fix when this fails is mechanical: add a table row for the
    missing chain id under the appropriate ``### Single-provider``
    or ``### Cross-provider`` section, then re-run
    ``python scripts/gen_attack_chains_doc.py`` so the detail card
    block stays in sync with the new row.
    """
    registry = _ids_in_registry()
    table = _ids_in_table()
    missing = sorted(registry - table)
    assert not missing, (
        f"docs/attack_chains.md: chain IDs in the registry are not "
        f"in the hand-edited table: {missing}. Add a row for each "
        f"under '### Single-provider chains' (AC-NNN) or '### "
        f"Cross-provider chains' (XPC-NNN), then re-run "
        f"`python scripts/gen_attack_chains_doc.py`."
    )


def test_no_orphan_chain_ids_in_table() -> None:
    """The reverse drift: the table names a chain id the registry
    doesn't know about. Usually a typo or a chain whose rule module
    was removed without the table row being deleted."""
    registry = _ids_in_registry()
    table = _ids_in_table()
    orphans = sorted(table - registry)
    assert not orphans, (
        f"docs/attack_chains.md: chain IDs in the table aren't in "
        f"the registry: {orphans}. Either delete the row(s) or "
        f"restore the rule module under "
        f"`pipeline_check/core/chains/rules/`."
    )
