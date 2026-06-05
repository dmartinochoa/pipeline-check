"""Tests for the shared reporter view (partition / counts / ordering)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.report_view import (
    ReportView,
    failure_sort_key,
    report_sort_key,
)


def _f(check_id="CB-001", passed=False, severity=Severity.HIGH):
    return Finding(
        check_id=check_id,
        title="t",
        severity=severity,
        resource="r",
        description="d",
        recommendation="rec",
        passed=passed,
    )


class TestSortKeys:
    def test_report_order_failures_before_passes(self):
        a = _f("CB-001", passed=True, severity=Severity.CRITICAL)
        b = _f("CB-002", passed=False, severity=Severity.LOW)
        ordered = sorted([a, b], key=report_sort_key)
        assert [f.check_id for f in ordered] == ["CB-002", "CB-001"]

    def test_report_order_severity_then_check_id(self):
        fs = [
            _f("CB-003", passed=False, severity=Severity.MEDIUM),
            _f("CB-001", passed=False, severity=Severity.CRITICAL),
            _f("CB-002", passed=False, severity=Severity.CRITICAL),
        ]
        ordered = sorted(fs, key=report_sort_key)
        # CRITICALs first, tie broken by check_id, then the MEDIUM.
        assert [f.check_id for f in ordered] == ["CB-001", "CB-002", "CB-003"]

    def test_failure_key_severity_desc_then_check_id(self):
        fs = [
            _f("CB-002", passed=False, severity=Severity.LOW),
            _f("CB-001", passed=False, severity=Severity.HIGH),
        ]
        ordered = sorted(fs, key=failure_sort_key)
        assert [f.check_id for f in ordered] == ["CB-001", "CB-002"]


class TestReportView:
    def test_partition_preserves_input_order(self):
        fs = [_f("CB-001", passed=False), _f("CB-002", passed=True),
              _f("CB-003", passed=False)]
        view = ReportView(fs)
        assert [f.check_id for f in view.failed] == ["CB-001", "CB-003"]
        assert [f.check_id for f in view.passed] == ["CB-002"]

    def test_counts(self):
        fs = [_f(passed=False), _f(passed=True), _f(passed=False)]
        view = ReportView(fs)
        assert view.total == 3
        assert view.failed_count == 2
        assert view.passed_count == 1

    def test_counts_empty(self):
        view = ReportView([])
        assert view.total == 0
        assert view.failed_count == 0
        assert view.passed_count == 0

    def test_ordered_puts_failures_first_then_passes(self):
        fs = [
            _f("CB-002", passed=True, severity=Severity.CRITICAL),
            _f("CB-001", passed=False, severity=Severity.LOW),
        ]
        ordered = ReportView(fs).ordered
        assert ordered[0].check_id == "CB-001"
        assert ordered[-1].check_id == "CB-002"
