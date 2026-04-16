"""Tests for the YAML ignore-file format + expiring suppressions."""
from __future__ import annotations

import datetime as dt

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.gate import (
    GateConfig,
    IgnoreRule,
    evaluate_gate,
    load_ignore_file,
)


def _f(check_id="GHA-001", resource="wf.yml") -> Finding:
    return Finding(
        check_id=check_id, title="t", severity=Severity.HIGH,
        resource=resource, description="", recommendation="", passed=False,
    )


def test_yaml_ignore_parses_structured_rules(tmp_path):
    p = tmp_path / "ignore.yml"
    p.write_text(
        "- check_id: GHA-001\n"
        "  resource: wf.yml\n"
        "  expires: 2099-01-01\n"
        "  reason: upstream action not yet SHA-tagged\n"
        "- check_id: gl-003\n"
    )
    rules = load_ignore_file(p)
    assert len(rules) == 2
    assert rules[0].check_id == "GHA-001"
    assert rules[0].resource == "wf.yml"
    assert rules[0].expires == dt.date(2099, 1, 1)
    assert rules[0].reason == "upstream action not yet SHA-tagged"
    assert rules[0].is_expired() is False
    # Second rule upper-cased, no expiry, no resource.
    assert rules[1].check_id == "GL-003"
    assert rules[1].resource is None
    assert rules[1].expires is None


def test_expired_rule_does_not_suppress(tmp_path):
    p = tmp_path / "ignore.yml"
    p.write_text(
        "- check_id: GHA-001\n"
        "  resource: wf.yml\n"
        "  expires: 2000-01-01\n"
    )
    rules = load_ignore_file(p)
    assert rules[0].is_expired() is True

    cfg = GateConfig(ignore_rules=rules, fail_on=Severity.HIGH)
    result = evaluate_gate([_f()], {"grade": "A"}, cfg)
    # The finding is NOT suppressed because the rule has expired.
    assert result.suppressed == []
    assert result.effective and not result.passed
    # The expired rule surfaces in the result so the UI can warn.
    assert result.expired_rules == rules


def test_non_expired_rule_still_suppresses(tmp_path):
    p = tmp_path / "ignore.yml"
    p.write_text(
        "- check_id: GHA-001\n"
        "  expires: 2099-12-31\n"
    )
    rules = load_ignore_file(p)
    cfg = GateConfig(ignore_rules=rules, fail_on=Severity.HIGH)
    result = evaluate_gate([_f()], {"grade": "A"}, cfg)
    assert len(result.suppressed) == 1
    assert result.passed
    assert result.expired_rules == []


def test_flat_format_still_works(tmp_path):
    p = tmp_path / ".pipelinecheckignore"
    p.write_text("GHA-001:wf.yml\n# comment\nGL-003\n")
    rules = load_ignore_file(p)
    assert [r.check_id for r in rules] == ["GHA-001", "GL-003"]
    # Flat rules never expire.
    assert all(r.expires is None for r in rules)
