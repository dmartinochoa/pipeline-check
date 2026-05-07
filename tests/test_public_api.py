"""Tests that lock the public Python API against accidental removal.

Anything in ``pipeline_check.__all__`` is part of the documented
import surface for library callers. Renaming or removing a name is a
semver-breaking change; this test fails when that happens so the
reviewer notices.

Adding a NEW name is fine — the test only enforces that the names
already present keep working.
"""
from __future__ import annotations

import inspect
import pathlib
import tempfile

import pytest

import pipeline_check

# ── Surface ──────────────────────────────────────────────────────────


# The set of names callers can import as ``from pipeline_check import X``.
# Bump only when intentionally removing or renaming. Adding a new name
# requires updating this set; the second test below reminds you.
EXPECTED_PUBLIC_NAMES: frozenset[str] = frozenset({
    # Core
    "Scanner",
    "ScanMetadata",
    # Findings + enums
    "Finding",
    "Location",
    "Severity",
    "Confidence",
    "ControlRef",
    "severity_rank",
    "confidence_rank",
    # Scoring
    "score",
    "ScoreResult",
    # Chains
    "Chain",
    "ChainRule",
    "evaluate_chains",
    "list_chain_rules",
    # Registry queries
    "available_providers",
    "available_standards",
    # Custom rule DSL
    "load_custom_rules",
    "LoadedCustomRules",
    "CustomRuleError",
    # Metadata
    "__version__",
})


def test_all_documented_names_are_importable():
    """Every name in ``__all__`` exists on the module and isn't ``None``."""
    for name in pipeline_check.__all__:
        assert hasattr(pipeline_check, name), (
            f"pipeline_check.__all__ lists {name!r} but it isn't on the module"
        )
        assert getattr(pipeline_check, name) is not None, (
            f"pipeline_check.{name} is None — re-export is broken"
        )


def test_public_surface_matches_expected_set():
    """``__all__`` matches the set this test locks in.

    Adding a new public name? Append it to ``EXPECTED_PUBLIC_NAMES``
    above. Removing one is a breaking change — bump the major version
    and document it in CHANGELOG.
    """
    actual = set(pipeline_check.__all__)
    missing = EXPECTED_PUBLIC_NAMES - actual
    extra = actual - EXPECTED_PUBLIC_NAMES
    assert not missing, (
        f"Public API regressed — these names dropped from __all__: "
        f"{sorted(missing)}. Removing them is a semver-breaking change."
    )
    assert not extra, (
        f"Public API grew — add these to EXPECTED_PUBLIC_NAMES in this "
        f"test: {sorted(extra)}"
    )


# ── Type identity ────────────────────────────────────────────────────


def test_scanner_is_a_class():
    assert inspect.isclass(pipeline_check.Scanner)


def test_finding_is_a_dataclass():
    # Finding is a dataclass — verify by checking for the marker attr.
    assert hasattr(pipeline_check.Finding, "__dataclass_fields__")


def test_severity_is_an_enum_with_canonical_levels():
    levels = {s.value for s in pipeline_check.Severity}
    assert levels == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_confidence_is_an_enum_with_canonical_levels():
    levels = {c.value for c in pipeline_check.Confidence}
    assert levels == {"HIGH", "MEDIUM", "LOW"}


def test_score_returns_scoreresult_shape():
    result = pipeline_check.score([])
    assert "score" in result and "grade" in result and "summary" in result


# ── Smoke test — the example in the docstring actually works ────────


def test_readme_example_runs_end_to_end():
    """The example from the module docstring should run without error
    and produce the expected output shape."""
    with tempfile.TemporaryDirectory() as td:
        wf = pathlib.Path(td) / "wf.yml"
        wf.write_text(
            "name: t\n"
            "on: push\n"
            "permissions: { contents: read }\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n",
            encoding="utf-8",
        )

        scanner = pipeline_check.Scanner(pipeline="github", gha_path=td)
        findings = scanner.run()
        assert all(isinstance(f, pipeline_check.Finding) for f in findings)

        critical = [
            f for f in findings
            if not f.passed and f.severity is pipeline_check.Severity.CRITICAL
        ]
        # GHA-001 (unpinned action) fires as HIGH on this fixture, not
        # CRITICAL — so the critical list is empty. The point is that
        # the comparison expression works without error.
        assert isinstance(critical, list)

        result = pipeline_check.score(findings)
        assert isinstance(result["score"], int)
        assert result["grade"] in {"A", "B", "C", "D"}


def test_chains_populated_after_run():
    """``Scanner.chains`` is the documented post-run accessor for
    attack-chain correlation. Make sure it's reachable from the public
    surface and starts empty before run()."""
    with tempfile.TemporaryDirectory() as td:
        pathlib.Path(td, "wf.yml").write_text(
            "on: push\njobs: { b: { runs-on: ubuntu-latest, "
            "steps: [{uses: actions/checkout@v4}] } }\n",
            encoding="utf-8",
        )
        scanner = pipeline_check.Scanner(pipeline="github", gha_path=td)
        assert scanner.chains == []
        scanner.run()
        # ``chains`` is now a list (possibly empty) of Chain objects.
        assert isinstance(scanner.chains, list)
        for c in scanner.chains:
            assert isinstance(c, pipeline_check.Chain)


def test_registry_queries_return_non_empty_lists():
    providers = pipeline_check.available_providers()
    standards = pipeline_check.available_standards()
    assert isinstance(providers, list) and providers
    assert isinstance(standards, list) and standards
    assert "github" in providers
    assert "owasp_cicd_top_10" in standards


def test_severity_and_confidence_rank_are_callable_and_ordered():
    s = pipeline_check.Severity
    assert pipeline_check.severity_rank(s.CRITICAL) > pipeline_check.severity_rank(s.LOW)
    c = pipeline_check.Confidence
    assert pipeline_check.confidence_rank(c.HIGH) > pipeline_check.confidence_rank(c.LOW)


# ── No internal modules leak through __all__ ────────────────────────


def test_public_names_dont_expose_internal_modules():
    """Catches accidental ``from .core import scanner`` style re-exports
    that would put internal modules on the public surface."""
    for name in pipeline_check.__all__:
        obj = getattr(pipeline_check, name)
        if inspect.ismodule(obj):
            pytest.fail(
                f"pipeline_check.{name} is a module — only specific "
                f"types and functions belong in the public surface."
            )
