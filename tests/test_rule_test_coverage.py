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

import ast
import re
from pathlib import Path

import pytest

from pipeline_check.core.checks.rule import discover_rules

REPO = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO / "tests"

# Provider package -> minimum acceptable test coverage (percent).
# Set to the floor as of v0.4.0; ratchet upward over time.
PROVIDERS_AND_FLOORS: dict[str, tuple[str, int]] = {
    "github":     ("pipeline_check.core.checks.github.rules",     100),
    "gitlab":     ("pipeline_check.core.checks.gitlab.rules",     100),
    "bitbucket":  ("pipeline_check.core.checks.bitbucket.rules",  100),
    "azure":      ("pipeline_check.core.checks.azure.rules",      100),
    "jenkins":    ("pipeline_check.core.checks.jenkins.rules",    100),
    "circleci":   ("pipeline_check.core.checks.circleci.rules",   100),
    "cloudbuild": ("pipeline_check.core.checks.cloudbuild.rules", 100),
    "buildkite":  ("pipeline_check.core.checks.buildkite.rules",  100),
    "tekton":     ("pipeline_check.core.checks.tekton.rules",     100),
    "argo":       ("pipeline_check.core.checks.argo.rules",       100),
    "dockerfile": ("pipeline_check.core.checks.dockerfile.rules", 100),
    "kubernetes": ("pipeline_check.core.checks.kubernetes.rules", 100),
    "helm":       ("pipeline_check.core.checks.helm.rules",       100),
    "oci":        ("pipeline_check.core.checks.oci.rules",        100),
    "drone":      ("pipeline_check.core.checks.drone.rules",      100),
    "maven":      ("pipeline_check.core.checks.maven.rules",      100),
    "devenv":     ("pipeline_check.core.checks.devenv.rules",     100),
}


def _class_has_assertion(cls: ast.ClassDef) -> bool:
    """True when *cls* contains at least one real assertion.

    Recognizes a bare ``assert``, a ``pytest.raises`` / ``fail`` / ``warns``
    context or call, and ``unittest``-style ``self.assert*`` methods. An
    empty stub (a ``Test<ID>`` class whose methods only ``pass`` or build
    fixtures) has none of these, so it no longer counts as coverage.
    """
    for n in ast.walk(cls):
        if isinstance(n, ast.Assert):
            return True
        if isinstance(n, ast.Attribute) and (
            n.attr.startswith("assert") or n.attr in ("raises", "fail", "warns")
        ):
            return True
    return False


def _asserting_test_classes() -> dict[str, bool]:
    """``{Test-class name: has >= 1 assertion}`` across every tracked
    ``test_*.py``.

    We AST-parse rather than concatenate text so an empty ``Test<ID>``
    stub (which the old substring scan counted as covered) is recognized
    as the gap it is. Parsing is heavier than reading, so the result is
    cached in a module-scoped fixture and computed once.
    """
    out: dict[str, bool] = {}
    for path in TESTS_DIR.rglob("test_*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                out[node.name] = (
                    out.get(node.name, False) or _class_has_assertion(node)
                )
    return out


@pytest.fixture(scope="module")
def asserting_classes() -> dict[str, bool]:
    return _asserting_test_classes()


def _covered_rule_ids(
    class_assertions: dict[str, bool], rule_ids: set[str],
) -> set[str]:
    """Subset of *rule_ids* that have at least one ASSERTING test class.

    A rule is covered when some ``Test<RULE_ID>...`` class exists AND it
    carries a real assertion. Recognizes both the zero-padded
    (``TestGHA001``) and unpadded (``TestGHA1``) class-name forms; the
    ``(?!\\d)`` guard keeps ``GHA-001`` from matching a hypothetical
    ``TestGHA0012`` class.
    """
    asserting = [name for name, has in class_assertions.items() if has]
    matched: set[str] = set()
    for rid in rule_ids:
        prefix, num_str = rid.split("-")
        num = int(num_str)
        pat = re.compile(rf"^Test{re.escape(prefix)}0*{num}(?!\d)")
        if any(pat.match(name) for name in asserting):
            matched.add(rid)
    return matched


@pytest.mark.parametrize(
    "provider,fqn,floor",
    [(p, fqn, floor) for p, (fqn, floor) in PROVIDERS_AND_FLOORS.items()],
)
def test_per_rule_test_coverage_floor(
    provider: str, fqn: str, floor: int, asserting_classes: dict[str, bool],
):
    """Each provider's rule-test coverage stays at or above its floor.

    A failure means either:
      a) a new rule was added without a ``Test<RULE_ID>`` test class
         (the dominant case), OR
      b) an existing test class was renamed without preserving the
         rule-id prefix (rename it back, or update the class
         convention), OR
      c) a ``Test<RULE_ID>`` class exists but is an empty stub with no
         assertion (it no longer counts as coverage).

    Bumping the floor in this file is fine as long as you actually
    backfilled tests; ratcheting it upward over time is how Track A
    progresses past the v0.4.0 baseline.
    """
    rules = discover_rules(fqn)
    rule_ids = {r.id for r, _ in rules}
    if not rule_ids:
        pytest.skip(f"{provider}: no rules discovered")
    matched = _covered_rule_ids(asserting_classes, rule_ids)
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


def test_at_least_half_of_ci_providers_cross_60_percent(
    asserting_classes: dict[str, bool],
):
    """Forward-progress sanity: at least half of the CI/CD providers
    (i.e. excluding kubernetes/dockerfile/azure which have different
    test shapes) sit above 60% rule-test coverage.

    A failure here means the per-provider backfill has stalled across
    the catalog; pick a provider sitting at the floor and add tests
    for its uncovered rules until this passes again.
    """
    above_60 = 0
    ci_providers = {"github", "gitlab", "bitbucket", "jenkins", "circleci"}
    for provider in ci_providers:
        fqn = PROVIDERS_AND_FLOORS[provider][0]
        rules = discover_rules(fqn)
        rule_ids = {r.id for r, _ in rules}
        matched = _covered_rule_ids(asserting_classes, rule_ids)
        if 100 * len(matched) / max(1, len(rule_ids)) >= 60:
            above_60 += 1
    # All five major CI providers cross 60% as of this session.
    # Lifting this floor further requires backfilling more rules.
    assert above_60 >= 5, (
        f"Only {above_60}/5 CI providers cross 60% rule-test coverage. "
        f"Pick the provider closest to the threshold and backfill."
    )


class TestCoverageMechanics:
    """The strengthening itself: an empty stub must not pass for coverage,
    and the assertion detector recognizes the common assertion shapes."""

    def test_assertless_stub_is_not_coverage(self):
        # ``TestGHA001`` exists but carries no assertion -> not covered.
        classes = {"TestGHA001": False, "TestGHA002": True}
        assert _covered_rule_ids(classes, {"GHA-001", "GHA-002"}) == {"GHA-002"}

    def test_padded_and_unpadded_forms_match(self):
        classes = {"TestGHA001Curl": True, "TestGL3": True}
        covered = _covered_rule_ids(classes, {"GHA-001", "GL-003"})
        assert covered == {"GHA-001", "GL-003"}

    def test_number_boundary_avoids_false_match(self):
        # ``TestGHA0012`` must not count as coverage for GHA-001.
        classes = {"TestGHA0012": True}
        assert _covered_rule_ids(classes, {"GHA-001"}) == set()

    @pytest.mark.parametrize("body,expected", [
        ("def t(self): assert x == 1", True),
        ("def t(self):\n        with pytest.raises(ValueError): pass", True),
        ("def t(self): self.assertEqual(a, b)", True),
        ("def t(self): pytest.fail('nope')", True),
        ("def t(self): pass", False),
        ("def t(self):\n        wf = self._build()\n        run(wf)", False),
    ])
    def test_assertion_detection(self, body, expected):
        cls = ast.parse(f"class TestX:\n    {body}").body[0]
        assert _class_has_assertion(cls) is expected
