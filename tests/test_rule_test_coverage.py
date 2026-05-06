"""Lock per-provider rule-test coverage against regression.

Each CI provider rule under ``pipeline_check/core/checks/<provider>/rules/``
should have at least one ``class Test<RULE_ID>...`` in some test file.
This module computes the current coverage and asserts it stays at or
above a per-provider floor. Adding a new rule without a corresponding
test class will dip the percentage and trip this guard.

The floors are deliberately set to the current state so this test
documents the gap rather than blocking a release. Push them upward
in subsequent PRs as the backfill continues.

AWS / Terraform / CloudFormation providers use a different test
shape (class-based checks with shared fixtures) and are out of scope
for this meta-test — their coverage is enforced by the per-service
test files under ``tests/aws/`` and ``tests/terraform/``.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from pipeline_check.core.checks.rule import discover_rules

REPO = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO / "tests"

# Provider package -> minimum acceptable test coverage (percent).
# Set to the floor as of v0.4.0; ratchet upward over time.
PROVIDERS_AND_FLOORS: dict[str, tuple[str, int]] = {
    "github":     ("pipeline_check.core.checks.github.rules",     75),
    "gitlab":     ("pipeline_check.core.checks.gitlab.rules",     70),
    "bitbucket":  ("pipeline_check.core.checks.bitbucket.rules",  65),
    "azure":      ("pipeline_check.core.checks.azure.rules",      65),
    "jenkins":    ("pipeline_check.core.checks.jenkins.rules",    70),
    "circleci":   ("pipeline_check.core.checks.circleci.rules",   70),
    "cloudbuild": ("pipeline_check.core.checks.cloudbuild.rules", 80),
    "dockerfile": ("pipeline_check.core.checks.dockerfile.rules", 65),
    "kubernetes": ("pipeline_check.core.checks.kubernetes.rules", 85),
}


def _read_all_test_text() -> str:
    """Concatenate every tracked ``test_*.py`` file under tests/.

    We scan the literal text rather than importing because:
      1. Importing every test module would actually run it.
      2. Class-name presence is a stable proxy for rule-coverage
         intent — if a class named ``TestGHA-001`` exists, the
         rule is "covered" for the purpose of this meta-test even
         if the class is currently empty.
    """
    out: list[str] = []
    for path in TESTS_DIR.rglob("test_*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            out.append(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
    return "\n".join(out)


def _covered_rule_ids(test_blob: str, rule_ids: set[str]) -> set[str]:
    """Subset of *rule_ids* that have at least one test class somewhere.

    Recognises both zero-padded (``TestGHA001``) and unpadded
    (``TestGHA1``) class-name forms — the convention is the padded one
    but a few legacy classes use the unpadded form.
    """
    matched: set[str] = set()
    for rid in rule_ids:
        prefix, num_str = rid.split("-")
        num = int(num_str)
        token_padded = f"Test{prefix}{num:03d}"
        if token_padded in test_blob:
            matched.add(rid)
            continue
        # Fallback: ``TestGHA1`` (no zero-pad).
        if re.search(rf"class\s+Test{re.escape(prefix)}{num}\b", test_blob):
            matched.add(rid)
    return matched


@pytest.mark.parametrize(
    "provider,fqn,floor",
    [(p, fqn, floor) for p, (fqn, floor) in PROVIDERS_AND_FLOORS.items()],
)
def test_per_rule_test_coverage_floor(provider: str, fqn: str, floor: int):
    """Each provider's rule-test coverage stays at or above its floor.

    A failure means either:
      a) a new rule was added without a ``Test<RULE_ID>`` test class
         (the dominant case), OR
      b) an existing test class was renamed without preserving the
         rule-id prefix (rename it back, or update the class
         convention).

    Bumping the floor in this file is fine as long as you actually
    backfilled tests; ratcheting it upward over time is how Track A
    progresses past the v0.4.0 baseline.
    """
    test_blob = _read_all_test_text()
    rules = discover_rules(fqn)
    rule_ids = {r.id for r, _ in rules}
    if not rule_ids:
        pytest.skip(f"{provider}: no rules discovered")
    matched = _covered_rule_ids(test_blob, rule_ids)
    pct = 100 * len(matched) / len(rule_ids)
    missing = sorted(rule_ids - matched)
    assert pct >= floor, (
        f"{provider}: rule-test coverage dropped to {pct:.0f}% "
        f"(floor: {floor}%, covered: {len(matched)}/{len(rule_ids)}). "
        f"Missing tests for: {', '.join(missing[:10])}"
        f"{'…' if len(missing) > 10 else ''}. "
        f"Either add a ``class Test<RULE_ID>...`` for the new rule, "
        f"or update the floor in this file once you've intentionally "
        f"backfilled past the gap."
    )


def test_at_least_half_of_ci_providers_cross_60_percent():
    """Forward-progress sanity: at least half of the CI/CD providers
    (i.e. excluding kubernetes/dockerfile/azure which have different
    test shapes) sit above 60% rule-test coverage.

    A failure here means the per-provider backfill has stalled across
    the catalog; pick a provider sitting at the floor and add tests
    for its uncovered rules until this passes again.
    """
    test_blob = _read_all_test_text()
    above_60 = 0
    ci_providers = {"github", "gitlab", "bitbucket", "jenkins", "circleci"}
    for provider in ci_providers:
        fqn = PROVIDERS_AND_FLOORS[provider][0]
        rules = discover_rules(fqn)
        rule_ids = {r.id for r, _ in rules}
        matched = _covered_rule_ids(test_blob, rule_ids)
        if 100 * len(matched) / max(1, len(rule_ids)) >= 60:
            above_60 += 1
    # All five major CI providers cross 60% as of this session.
    # Lifting this floor further requires backfilling more rules.
    assert above_60 >= 5, (
        f"Only {above_60}/5 CI providers cross 60% rule-test coverage. "
        f"Pick the provider closest to the threshold and backfill."
    )
