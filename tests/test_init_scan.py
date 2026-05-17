"""Tests for the smart-init flow: ``pipeline_check init`` runs a scan,
recommends a gate, writes a baseline, and prints a top-N summary.

The unit tests below pin the pure-function pieces (recommend_fail_on,
build_init_scan_result, _pick_top). The CLI end-to-end behavior lives
in tests/test_cli_ease_of_use.py and tests/test_cli_smart_init.py.
"""
from __future__ import annotations

import json

from pipeline_check.core import init_template
from pipeline_check.core.checks.base import (
    Finding,
    Location,
    Severity,
)
from pipeline_check.core.init_scan import (
    DEFAULT_BASELINE_PATH,
    TOP_FIX_COUNT,
    InitScanResult,
    _pick_top,
    build_init_scan_result,
)


def _f(
    check_id: str,
    severity: Severity,
    *,
    resource: str = "wf.yml",
    passed: bool = False,
    title: str = "t",
    locations: list[Location] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        resource=resource,
        description="d",
        recommendation="rec",
        passed=passed,
        locations=locations or [],
    )


class TestRecommendFailOn:
    def test_critical_failure_recommends_high(self):
        # A CRITICAL failure caps the gate at HIGH even on a low grade,
        # so the user baselines the criticals but a new HIGH still
        # blocks. Important: don't recommend CRITICAL itself, otherwise
        # baselined criticals pass and the user's gate is a no-op for
        # the very severity that prompted them to adopt the tool.
        assert init_template.recommend_fail_on("D", has_critical=True) is Severity.HIGH
        assert init_template.recommend_fail_on("A", has_critical=True) is Severity.HIGH

    def test_grade_a_b_recommends_medium(self):
        assert init_template.recommend_fail_on("A", has_critical=False) is Severity.MEDIUM
        assert init_template.recommend_fail_on("B", has_critical=False) is Severity.MEDIUM

    def test_grade_c_d_recommends_high(self):
        assert init_template.recommend_fail_on("C", has_critical=False) is Severity.HIGH
        assert init_template.recommend_fail_on("D", has_critical=False) is Severity.HIGH


class TestPickTop:
    def test_orders_by_severity_then_fixable_then_id(self):
        findings = [
            _f("GHA-005", Severity.LOW),
            _f("GHA-002", Severity.CRITICAL),
            _f("GHA-003", Severity.HIGH),  # has fixer
            _f("GHA-001", Severity.HIGH),  # no fixer
            _f("GHA-009", Severity.MEDIUM),
        ]
        top = _pick_top(findings, fixers={"GHA-003"})
        ids = [t.check_id for t in top]
        # CRITICAL first, then HIGH (fixable wins), then HIGH (no
        # fixer), then MEDIUM, then LOW.
        assert ids == ["GHA-002", "GHA-003", "GHA-001", "GHA-009", "GHA-005"]
        assert top[1].fixable is True
        assert top[2].fixable is False

    def test_dedupes_same_check_and_resource(self):
        # The same rule firing 50 times across one file shouldn't push
        # the rest of the top list off the screen.
        findings = [
            _f("GHA-001", Severity.HIGH, resource="wf.yml") for _ in range(20)
        ] + [
            _f("GHA-002", Severity.MEDIUM, resource="wf.yml"),
        ]
        top = _pick_top(findings, fixers=set())
        assert [t.check_id for t in top] == ["GHA-001", "GHA-002"]

    def test_dedupes_same_check_across_resources(self):
        # The same rule firing across many files (e.g. GHA-001 on every
        # workflow YAML) contributes one row, so unique rule types fill
        # the top-N instead of one offending rule crowding the others
        # out.
        findings = [
            _f("GHA-001", Severity.HIGH, resource=f"wf{i}.yml")
            for i in range(20)
        ] + [
            _f("GHA-002", Severity.MEDIUM, resource="wf.yml"),
        ]
        top = _pick_top(findings, fixers=set())
        assert [t.check_id for t in top] == ["GHA-001", "GHA-002"]

    def test_caps_at_top_fix_count(self):
        findings = [
            _f(f"GHA-{i:03d}", Severity.HIGH) for i in range(1, 20)
        ]
        # Each finding has a unique resource so dedup doesn't kick in.
        findings = [
            _f(f"GHA-{i:03d}", Severity.HIGH, resource=f"wf{i}.yml")
            for i in range(1, 20)
        ]
        top = _pick_top(findings, fixers=set())
        assert len(top) == TOP_FIX_COUNT


class TestBuildInitScanResult:
    def test_no_failures_does_not_baseline(self):
        findings = [_f("GHA-001", Severity.HIGH, passed=True)]
        result = build_init_scan_result(
            findings,
            detected_pipeline="github",
            tool_version="9.9.9",
            fixers=set(),
        )
        assert isinstance(result, InitScanResult)
        assert result.has_failures is False
        assert result.failing_findings == 0
        # Config still references the baseline path but as a comment so
        # the user can flip it on later.
        assert "# baseline: " in result.config_yaml
        # Fail-on tracks recommendation: clean scan = MEDIUM gate
        # (Grade A, no criticals).
        assert "fail_on: MEDIUM" in result.config_yaml

    def test_failures_get_baselined(self):
        findings = [
            _f("GHA-001", Severity.CRITICAL),
            _f("GHA-002", Severity.HIGH, passed=True),
            _f("GHA-003", Severity.MEDIUM),
        ]
        result = build_init_scan_result(
            findings,
            detected_pipeline="github",
            tool_version="9.9.9",
            fixers=set(),
        )
        assert result.has_failures is True
        assert result.failing_findings == 2
        # Critical present → recommend HIGH (not CRITICAL).
        assert result.recommended_fail_on is Severity.HIGH
        # Config has uncommented baseline line.
        assert f"baseline: {DEFAULT_BASELINE_PATH}" in result.config_yaml
        # Baseline JSON is well-formed with our findings.
        doc = json.loads(result.baseline_json)
        assert "findings" in doc
        failing_ids = {f["check_id"] for f in doc["findings"] if not f["passed"]}
        assert failing_ids == {"GHA-001", "GHA-003"}

    def test_pipeline_line_is_uncommented(self):
        result = build_init_scan_result(
            [],
            detected_pipeline="azure",
            tool_version="0.0.0",
            fixers=set(),
        )
        assert "\npipeline: azure\n" in result.config_yaml

    def test_top_field_populated(self):
        findings = [_f("GHA-001", Severity.HIGH), _f("GHA-002", Severity.LOW)]
        result = build_init_scan_result(
            findings,
            detected_pipeline="github",
            tool_version="0.0.0",
            fixers={"GHA-001"},
        )
        assert [t.check_id for t in result.top] == ["GHA-001", "GHA-002"]
        assert result.top[0].fixable is True
