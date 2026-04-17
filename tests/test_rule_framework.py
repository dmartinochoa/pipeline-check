"""Tests for the per-rule-module framework + the provider doc generator.

The GitHub provider was migrated to the
``pipeline_check/core/checks/github/rules/`` layout. These tests
lock in the invariants that make the pattern work:

  1. Every rule module under ``github/rules/`` exports a well-formed
     ``RULE`` and a callable ``check``.
  2. The rule registry is ordered so the doc generator emits
     rules in natural ``GHA-001 → GHA-012`` sequence.
  3. The orchestrator discovers every rule exactly once.
  4. The doc generator produces a deterministic markdown output
     that references every registered rule.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.checks.rule import Rule, discover_rules

RULES_FQN = "pipeline_check.core.checks.github.rules"


@pytest.fixture(scope="module")
def github_rules():
    return discover_rules(RULES_FQN)


# ──────────────────────────────────────────────────────────────────────
# Framework invariants
# ──────────────────────────────────────────────────────────────────────


def test_every_github_rule_has_metadata_and_check(github_rules):
    assert len(github_rules) == 29, (
        f"expected 29 GHA rules, got {len(github_rules)}. The "
        f"orchestrator iterates this registry directly, so a missing "
        f"entry silently drops a check from every scan."
    )
    for rule, check in github_rules:
        assert isinstance(rule, Rule)
        assert callable(check)
        assert rule.id.startswith("GHA-")
        assert rule.title.strip()
        assert rule.recommendation.strip(), f"{rule.id} must have a recommendation"
        assert rule.docs_note.strip(), f"{rule.id} must have a docs_note"


def test_rules_are_sorted_by_id(github_rules):
    """Discovery order drives both the orchestrator's finding order
    and the doc generator's section order. Lexical sort on module
    name gives natural ``GHA-001 → GHA-012`` sequence."""
    ids = [rule.id for rule, _ in github_rules]
    assert ids == sorted(ids), (
        f"rule registry is not sorted: {ids}. Rename modules so the "
        f"numeric suffix is zero-padded if needed."
    )


def test_rule_ids_are_unique(github_rules):
    ids = [rule.id for rule, _ in github_rules]
    assert len(ids) == len(set(ids)), f"duplicate rule IDs: {ids}"


# ──────────────────────────────────────────────────────────────────────
# Doc generator — rendering contract
# ──────────────────────────────────────────────────────────────────────


def test_generated_github_doc_references_every_rule(github_rules):
    """The provider reference doc is produced by
    ``scripts/gen_provider_docs.py`` from the same registry the
    orchestrator iterates. A rule that ships without appearing in
    the generated doc is almost always a sign the registry was
    mutated but the doc wasn't regenerated."""
    doc = (Path(__file__).resolve().parent.parent
           / "docs" / "providers" / "github.md").read_text(encoding="utf-8")
    for rule, _ in github_rules:
        assert rule.id in doc, (
            f"{rule.id} missing from docs/providers/github.md — did you "
            f"forget to run `python scripts/gen_provider_docs.py github` "
            f"after changing the rule?"
        )
        assert rule.title in doc, (
            f"{rule.id}'s title is out of sync with the generated doc. "
            f"Regenerate with gen_provider_docs.py."
        )


def test_generator_is_deterministic(github_rules, tmp_path, monkeypatch):
    """Running the generator twice produces byte-identical output.
    Non-determinism (dict iteration order, time stamps, random
    ordering) would cause spurious diffs in the doc commits."""
    # Import lazily so the script's REPO_ROOT path arithmetic works.
    import importlib
    gen = importlib.import_module("scripts.gen_provider_docs")
    title, rules_fqn, _, header = gen.SUPPORTED_PROVIDERS["github"]
    first = gen._render_provider(title, header, rules_fqn)
    second = gen._render_provider(title, header, rules_fqn)
    assert first == second


def test_discover_rules_skips_helpers_and_private_modules():
    """Modules prefixed with ``_`` (the shared regex/helper module)
    must NOT be picked up as rules. Otherwise the orchestrator would
    try to iterate a helper as a rule pair."""
    pairs = discover_rules(RULES_FQN)
    for rule, _ in pairs:
        assert not rule.id.startswith("_")


# ──────────────────────────────────────────────────────────────────────
# Migration invariant — ensure the orchestrator still wires correctly
# ──────────────────────────────────────────────────────────────────────


def test_orchestrator_runs_every_rule_once(tmp_path):
    """A minimal workflow scan should produce one finding per
    registered rule, proving the orchestrator doesn't silently drop
    rules or double-invoke any."""
    from pipeline_check.core.checks.github.base import GitHubContext
    from pipeline_check.core.checks.github.workflows import WorkflowChecks

    wf_path = tmp_path / "wf.yml"
    wf_path.write_text(
        "name: x\non: push\npermissions: { contents: read }\n"
        "jobs: { b: { runs-on: ubuntu-latest, steps: [{run: echo}] } }\n",
        encoding="utf-8",
    )
    ctx = GitHubContext.from_path(wf_path)
    findings = WorkflowChecks(ctx).run()
    ids = [f.check_id for f in findings]
    assert ids == sorted(ids)
    assert len(ids) == 29
    assert len(set(ids)) == 29
