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


# ──────────────────────────────────────────────────────────────────────
# _PROVIDER_PACKAGES coverage guard
# ──────────────────────────────────────────────────────────────────────
#
# ``gen_standards_docs.py`` carries a hand-curated ``_PROVIDER_PACKAGES``
# tuple that enumerates which provider rule packages feed the standards-
# doc rendering. A provider that adds a ``rules/`` package on disk but
# isn't appended here silently disappears from the standards docs:
# nothing crashes, the script still renders, the existing drift guards
# still pass, but the new provider's per-rule prose just doesn't appear.
# That's exactly the bug 8766da7 fixed (cloudformation / terraform /
# npm / pypi were missing).
#
# This guard walks ``pipeline_check/core/checks/<provider>/rules/`` and
# asserts each one has a matching entry in ``_PROVIDER_PACKAGES``. The
# import side-loads the script module without executing main(), so the
# tuple is read directly.


def _provider_packages_from_script() -> set[str]:
    """Return the set of package FQNs registered in ``_PROVIDER_PACKAGES``.

    Extracts via regex rather than importing the module, since
    ``gen_standards_docs.py`` defines a ``@dataclass`` at import time
    and loading it under a synthetic module name via
    ``importlib.util.spec_from_file_location`` confuses
    ``dataclasses.dataclass`` (it looks up the class's module in
    ``sys.modules`` and doesn't find it). The regex is anchored on
    the unique ``pipeline_check.core.checks.<X>.rules`` shape so it
    can't pick up unrelated strings.
    """
    import re

    text = (REPO / "scripts" / "gen_standards_docs.py").read_text(
        encoding="utf-8",
    )
    pattern = re.compile(
        r'"(pipeline_check\.core\.checks\.[A-Za-z_]+\.rules)"',
    )
    return set(pattern.findall(text))


def _provider_packages_on_disk() -> set[str]:
    """Return every package FQN that ships a ``rules/`` subdirectory."""
    checks_root = REPO / "pipeline_check" / "core" / "checks"
    found: set[str] = set()
    for rules_dir in checks_root.glob("*/rules"):
        if not rules_dir.is_dir():
            continue
        # Skip if the directory contains no rule modules (only ``__init__``
        # plus underscore-prefixed helpers).
        rule_files = [
            p for p in rules_dir.glob("*.py")
            if p.stem != "__init__" and not p.stem.startswith("_")
        ]
        if not rule_files:
            continue
        provider = rules_dir.parent.name
        found.add(f"pipeline_check.core.checks.{provider}.rules")
    return found


def test_gen_standards_docs_covers_every_provider_with_rules() -> None:
    """Every provider that ships a ``rules/`` package must appear in
    ``gen_standards_docs.py:_PROVIDER_PACKAGES``.

    Otherwise the provider's rule-based check modules silently drop
    out of the standards-doc rendering — the script still renders
    cleanly, the drift guard above still passes, but the per-rule
    prose simply doesn't appear. 8766da7 fixed exactly this gap for
    cloudformation / terraform / npm / pypi.
    """
    registered = _provider_packages_from_script()
    on_disk = _provider_packages_on_disk()
    missing = sorted(on_disk - registered)
    assert not missing, (
        "Provider(s) ship a rules/ package but aren't in "
        "scripts/gen_standards_docs.py:_PROVIDER_PACKAGES, so their "
        "rule-based check modules won't surface in the standards "
        f"docs: {missing}. Append the (slug, pkg_fqn, title) tuple "
        "for each missing provider."
    )
