"""Strong drift guard: every generated doc on disk must equal a
fresh render from the live registries.

The doc set under ``docs/providers/`` and ``docs/standards/`` is
produced by four scripts:

  - ``scripts/gen_provider_docs.py``        (provider reference pages)
  - ``scripts/gen_standards_docs.py``       (per-standard reference pages)
  - ``scripts/gen_attack_chains_doc.py``    (chain catalog in attack_chains.md)
  - ``scripts/link_standards_check_ids.py`` (mapping-table cell linking)

Drift sources the existing tests don't fully cover:

  - ``tests/test_doc_claims.py`` locks numerical claims (provider count,
    rule-range high IDs, comparison-matrix per-cell counts).
  - ``tests/test_rule_framework.py`` locks that every rule's id + title
    appears in the corresponding provider doc.

Neither catches changes to a rule's ``recommendation`` / ``docs_note``,
or to a standard's prose, or to formatting. This test does, by running
each generator in ``--check`` mode and asserting exit 0. A failure
maps 1:1 to "re-run the named generator and commit the result".

The four ``--check`` invocations are uniform: same script per
generator, same expected exit. Subprocess (over importing main())
keeps the test cheap-to-add and matches the precedent set by
``tests/test_attack_chains_doc.py``.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


# (script_path, fix_command_hint) — the hint is shown verbatim in the
# failure message so the contributor doesn't have to crack the test
# open to learn what to re-run.
_GENERATORS: list[tuple[str, str]] = [
    ("scripts/gen_provider_docs.py",
     "python scripts/gen_provider_docs.py"),
    ("scripts/gen_standards_docs.py",
     "python scripts/gen_standards_docs.py"),
    ("scripts/gen_attack_chains_doc.py",
     "python scripts/gen_attack_chains_doc.py"),
    ("scripts/link_standards_check_ids.py",
     "python scripts/link_standards_check_ids.py"),
]


@pytest.mark.parametrize(
    "script,fix_hint",
    _GENERATORS,
    ids=[Path(s).stem for s, _ in _GENERATORS],
)
def test_generated_doc_in_sync(script: str, fix_hint: str) -> None:
    """Run the generator with ``--check`` and require exit 0.

    Each generator's ``--check`` mode renders its targets in memory
    and compares against the on-disk file, exiting 1 (with a helpful
    line on stderr) when any byte differs. A failure here means a
    rule's prose, a standard's mapping, or a chain's metadata moved
    in source code without the matching doc being regenerated.
    """
    result = subprocess.run(
        [sys.executable, script, "--check"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"{script}: generated docs out of sync. "
        f"Re-run `{fix_hint}` and commit the result.\n"
        f"--- stdout ---\n{result.stdout}"
        f"--- stderr ---\n{result.stderr}"
    )
