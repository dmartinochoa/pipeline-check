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


# ──────────────────────────────────────────────────────────────────────
# Non-circular guard for the standards docs
# ──────────────────────────────────────────────────────────────────────
#
# ``test_generated_doc_in_sync`` above re-runs the generator and diffs
# its output against the on-disk doc, so a bug inside the generator
# matches both sides and the drift test stays green. The provider-doc
# side has ``test_rule_framework.py::test_generated_doc_references_every_rule``
# as a non-circular guard (it asserts each rule's id + title appears
# in the rendered output independently of the generator). This block
# is the equivalent guard for the standards docs.


def _registered_standards():
    """Return every Standard registered in the live package."""
    from pipeline_check.core.standards import resolve
    return resolve()


@pytest.mark.parametrize(
    "standard",
    _registered_standards(),
    ids=lambda s: s.name,
)
def test_standards_doc_references_every_control(standard) -> None:
    """Every control id (and title) in the live registry must appear
    verbatim in the rendered ``docs/standards/<name>.md``.

    Bypasses the generator entirely: reads the doc straight off disk
    and ``in``-checks each ``control_id`` + ``control_title``. If the
    standards registry grows a control, this test reds without
    re-running the generator, breaking the circularity that
    ``test_generated_doc_in_sync`` carries on its own.
    """
    doc_path = REPO / "docs" / "standards" / f"{standard.name}.md"
    assert doc_path.exists(), (
        f"{doc_path.relative_to(REPO)} missing — re-run "
        f"`python scripts/gen_standards_docs.py {standard.name}` "
        f"to generate it."
    )
    doc = doc_path.read_text(encoding="utf-8")
    for ctrl_id, ctrl_title in standard.controls.items():
        assert ctrl_id in doc, (
            f"control {ctrl_id} missing from "
            f"{doc_path.relative_to(REPO)} — did you regenerate the "
            f"standards docs after editing the registry?"
        )
        if ctrl_title:
            assert ctrl_title in doc, (
                f"control {ctrl_id}'s title is out of sync with the "
                f"generated doc. Regenerate with "
                f"gen_standards_docs.py."
            )
