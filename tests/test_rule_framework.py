"""Tests for the per-rule-module framework + the provider doc generator.

Every rule-pack provider (github, gitlab, bitbucket, azure, jenkins,
circleci, cloudbuild, kubernetes, buildkite, tekton, argo, dockerfile)
follows the same ``checks/<provider>/rules/<id>_<slug>.py`` layout.
These tests lock in the invariants that make the pattern work:

  1. Every rule module exports a well-formed ``RULE`` and a callable
     ``check``.
  2. The rule registry is ordered so the doc generator emits rules
     in natural sequence.
  3. Rule IDs are unique across the pack.
  4. The doc generator produces a deterministic markdown output that
     references every registered rule.
  5. The orchestrator discovers every rule exactly once (smoke-tested
     against GitHub Actions; the per-provider tests under
     ``tests/<provider>/`` cover the rest).

Adding a rule? Bump the matching entry in ``EXPECTED_RULE_COUNTS``.
The exact-equality assertion forces that update to be deliberate so
a rule that silently drops out of the registry can't slip past the
suite.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from pipeline_check.core.checks.rule import Rule, discover_rules

REPO_ROOT = Path(__file__).resolve().parent.parent

# Per-provider rule count. Bumped intentionally on every rule add /
# remove. ``test_rule_count_matches_expected`` enforces equality so
# both directions (regression + growth) require an explicit update.
EXPECTED_RULE_COUNTS: dict[str, int] = {
    "aws":            71,
    "terraform":      71,
    "cloudformation": 70,
    "github":         81,
    "gitlab":     37,
    "bitbucket":  31,
    "azure":      30,
    "jenkins":    35,
    "circleci":   31,
    "cloudbuild": 26,
    "kubernetes": 43,
    "helm":       10,
    "buildkite":  16,
    "tekton":     16,
    "argo":       16,
    "argocd":      9,
    "dockerfile": 30,
    "oci":        15,
    "drone":      11,
    "scm":        47,
    "npm":        10,
    "pypi":        7,
    "maven":       8,
}


def _gen():
    """Lazy-load the generator module — its sys.path arithmetic
    depends on REPO_ROOT layout, so import on first use."""
    return importlib.import_module("scripts.gen_provider_docs")


def _supported_providers() -> dict[str, tuple[str, str, Path, str]]:
    """``{name: (title, rules_fqn, doc_path, header)}`` for every
    provider the doc generator knows about."""
    return _gen().SUPPORTED_PROVIDERS


def _provider_ids() -> list[str]:
    return sorted(_supported_providers().keys())


@pytest.fixture(scope="module")
def rules_by_provider() -> dict[str, list[tuple[Rule, object]]]:
    """One discover_rules call per provider, cached across tests."""
    out: dict[str, list[tuple[Rule, object]]] = {}
    for name, (_title, fqn, _doc, _header) in _supported_providers().items():
        out[name] = discover_rules(fqn)
    return out


# ──────────────────────────────────────────────────────────────────────
# Framework invariants
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("provider", _provider_ids())
def test_every_rule_has_metadata_and_check(provider, rules_by_provider):
    rules = rules_by_provider[provider]
    for rule, check in rules:
        assert isinstance(rule, Rule)
        assert callable(check)
        assert rule.id, f"{provider}: rule has empty id"
        assert rule.title.strip(), f"{rule.id}: title is empty"
        assert rule.recommendation.strip(), (
            f"{rule.id}: must have a recommendation"
        )
        assert rule.docs_note.strip(), f"{rule.id}: must have a docs_note"


@pytest.mark.parametrize("provider", _provider_ids())
def test_rule_count_matches_expected(provider, rules_by_provider):
    """Equality, not floor — both adding and removing a rule must
    bump ``EXPECTED_RULE_COUNTS`` deliberately. Catches the case
    where a register() is silently dropped."""
    rules = rules_by_provider[provider]
    expected = EXPECTED_RULE_COUNTS.get(provider)
    assert expected is not None, (
        f"{provider}: missing entry in EXPECTED_RULE_COUNTS. Add the "
        f"current registry size."
    )
    assert len(rules) == expected, (
        f"{provider}: expected {expected} rules, got {len(rules)}. "
        f"The orchestrator iterates this registry directly, so a "
        f"missing entry silently drops a check from every scan. Bump "
        f"EXPECTED_RULE_COUNTS in this file when this is intentional."
    )


@pytest.mark.parametrize("provider", _provider_ids())
def test_rules_are_sorted_by_id(provider, rules_by_provider):
    """Discovery order drives both the orchestrator's finding order
    and the doc generator's section order. Lexical sort on module
    name gives natural sequence as long as the numeric suffix is
    zero-padded."""
    ids = [rule.id for rule, _ in rules_by_provider[provider]]
    assert ids == sorted(ids), (
        f"{provider}: rule registry is not sorted: {ids}. Rename "
        f"modules so the numeric suffix is zero-padded if needed."
    )


@pytest.mark.parametrize("provider", _provider_ids())
def test_rule_ids_are_unique(provider, rules_by_provider):
    ids = [rule.id for rule, _ in rules_by_provider[provider]]
    assert len(ids) == len(set(ids)), (
        f"{provider}: duplicate rule IDs: {ids}"
    )


@pytest.mark.parametrize("provider", _provider_ids())
def test_discover_rules_skips_helpers_and_private_modules(
    provider, rules_by_provider,
):
    """Modules prefixed with ``_`` (shared regex / helper modules)
    must NOT be picked up as rules. Otherwise the orchestrator would
    try to iterate a helper as a rule pair."""
    for rule, _ in rules_by_provider[provider]:
        assert not rule.id.startswith("_"), (
            f"{provider}: helper module slipped into the rule registry "
            f"as {rule.id!r}"
        )


# ──────────────────────────────────────────────────────────────────────
# Doc generator — rendering contract
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("provider", _provider_ids())
def test_generated_doc_references_every_rule(provider, rules_by_provider):
    """The provider reference doc is produced by
    ``scripts/gen_provider_docs.py`` from the same registry the
    orchestrator iterates. A rule that ships without appearing in
    the generated doc is almost always a sign the registry was
    mutated but the doc wasn't regenerated."""
    _title, _fqn, doc_path, _header = _supported_providers()[provider]
    doc = Path(doc_path).read_text(encoding="utf-8")
    for rule, _ in rules_by_provider[provider]:
        assert rule.id in doc, (
            f"{rule.id} missing from {Path(doc_path).name} — did you "
            f"forget to run `python scripts/gen_provider_docs.py "
            f"{provider}` after changing the rule?"
        )
        assert rule.title in doc, (
            f"{rule.id}'s title is out of sync with the generated doc. "
            f"Regenerate with gen_provider_docs.py."
        )


@pytest.mark.parametrize("provider", _provider_ids())
def test_generator_is_deterministic(provider):
    """Running the generator twice produces byte-identical output.
    Non-determinism (dict iteration order, timestamps, random
    ordering) would cause spurious diffs in the doc commits."""
    gen = _gen()
    title, rules_fqn, _doc, header = gen.SUPPORTED_PROVIDERS[provider]
    first = gen._render_provider(title, header, rules_fqn)
    second = gen._render_provider(title, header, rules_fqn)
    assert first == second


# ──────────────────────────────────────────────────────────────────────
# Migration invariant — orchestrator wiring smoke test
# ──────────────────────────────────────────────────────────────────────


def test_orchestrator_runs_every_rule_once(tmp_path):
    """A minimal workflow scan should produce one finding per
    registered rule, proving the orchestrator doesn't silently drop
    rules or double-invoke any. GitHub Actions stands in for the
    framework; per-provider tests under ``tests/<provider>/`` cover
    the rest."""
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
    expected = EXPECTED_RULE_COUNTS["github"]
    assert ids == sorted(ids)
    assert len(ids) == expected
    assert len(set(ids)) == expected
