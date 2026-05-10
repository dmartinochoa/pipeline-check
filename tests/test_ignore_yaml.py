"""Tests for the YAML ignore-file format + expiring suppressions."""
from __future__ import annotations

import datetime as dt

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.gate import (
    EXPIRY_WARNING_DAYS,
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


def test_days_until_expiry_handles_past_present_future():
    """``days_until_expiry`` returns the signed delta in days; None
    for rules without an ``expires`` date."""
    today = dt.date(2026, 5, 10)
    assert IgnoreRule(check_id="X", resource=None).days_until_expiry(today) is None
    future = IgnoreRule(
        check_id="X", resource=None, expires=dt.date(2026, 5, 24),
    )
    assert future.days_until_expiry(today) == 14
    same_day = IgnoreRule(
        check_id="X", resource=None, expires=dt.date(2026, 5, 10),
    )
    assert same_day.days_until_expiry(today) == 0
    past = IgnoreRule(
        check_id="X", resource=None, expires=dt.date(2026, 5, 1),
    )
    assert past.days_until_expiry(today) == -9


class TestExpiringSoonForewarning:
    """Suppressions inside the EXPIRY_WARNING_DAYS window still suppress
    but are surfaced under ``GateResult.expiring_soon`` so the operator
    revisits them before they fail the gate.

    Tests use ``today + timedelta`` rather than freezing the clock so
    they remain stable as time moves forward; the window is anchored to
    the same ``today`` that ``evaluate_gate`` reads.
    """

    def test_inside_window_lands_in_expiring_soon(self):
        rule = IgnoreRule(
            check_id="GHA-001", resource="wf.yml",
            expires=dt.date.today() + dt.timedelta(days=5),
        )
        cfg = GateConfig(ignore_rules=[rule], fail_on=Severity.HIGH)
        result = evaluate_gate([_f()], {"grade": "A"}, cfg)
        # Still suppresses (rule hasn't expired yet).
        assert result.suppressed and result.passed
        # And surfaces in the soon-to-expire bucket.
        assert result.expiring_soon == [rule]
        assert result.expired_rules == []

    def test_outside_window_omitted(self):
        rule = IgnoreRule(
            check_id="GHA-001", resource="wf.yml",
            expires=dt.date.today() + dt.timedelta(days=365),
        )
        cfg = GateConfig(ignore_rules=[rule], fail_on=Severity.HIGH)
        result = evaluate_gate([_f()], {"grade": "A"}, cfg)
        assert result.expiring_soon == []

    def test_expired_rule_not_in_expiring_soon(self):
        """An already-expired rule belongs in ``expired_rules``, not
        ``expiring_soon``; the two lists are disjoint."""
        rule = IgnoreRule(
            check_id="GHA-001", resource="wf.yml",
            expires=dt.date.today() - dt.timedelta(days=1),
        )
        cfg = GateConfig(ignore_rules=[rule], fail_on=Severity.HIGH)
        result = evaluate_gate([_f()], {"grade": "A"}, cfg)
        assert result.expired_rules == [rule]
        assert result.expiring_soon == []

    def test_window_boundary_inclusive(self):
        """A rule expiring exactly EXPIRY_WARNING_DAYS away is still
        warned about; one day past the window stays silent."""
        on_window = IgnoreRule(
            check_id="GHA-001", resource=None,
            expires=dt.date.today() + dt.timedelta(days=EXPIRY_WARNING_DAYS),
        )
        past_window = IgnoreRule(
            check_id="GHA-002", resource=None,
            expires=dt.date.today()
            + dt.timedelta(days=EXPIRY_WARNING_DAYS + 1),
        )
        cfg = GateConfig(
            ignore_rules=[on_window, past_window], fail_on=Severity.HIGH,
        )
        result = evaluate_gate([], {"grade": "A"}, cfg)
        assert result.expiring_soon == [on_window]


class TestExpiringSoonCLISurface:
    """The CLI's ``_emit_gate_summary`` renders ``expiring_soon`` rules
    as a ``[gate] ignore rule expires in N days on YYYY-MM-DD: ...``
    forewarning so the operator sees them in the same scan output as
    everything else gated."""

    def _evaluate_with_expiring(self, days: int):
        from pipeline_check.cli import _emit_gate_summary

        rule = IgnoreRule(
            check_id="GHA-001", resource="wf.yml",
            expires=dt.date.today() + dt.timedelta(days=days),
        )
        cfg = GateConfig(ignore_rules=[rule], fail_on=Severity.HIGH)
        gate = evaluate_gate([_f()], {"grade": "A"}, cfg)
        return gate, _emit_gate_summary

    def test_renders_warning_line(self, capsys):
        gate, emit = self._evaluate_with_expiring(days=5)
        emit(gate)
        err = capsys.readouterr().err
        assert "ignore rule expires in 5 days" in err
        assert "GHA-001:wf.yml" in err
        assert "still suppressing" in err

    def test_renders_today_for_zero_days(self, capsys):
        gate, emit = self._evaluate_with_expiring(days=0)
        emit(gate)
        err = capsys.readouterr().err
        assert "ignore rule expires today" in err

    def test_renders_singular_day_for_one_day(self, capsys):
        gate, emit = self._evaluate_with_expiring(days=1)
        emit(gate)
        err = capsys.readouterr().err
        # Singular noun, not "1 days".
        assert "expires in 1 day on" in err
        assert "1 days" not in err


def test_yaml_duplicate_key_rejected(tmp_path, capsys):
    """A YAML ignore rule with a duplicated field (typo or copy-paste
    mistake) must not silently drop half the user's intent. Loader
    raises, load_ignore_file surfaces the error to stderr and returns
    an empty list."""
    p = tmp_path / ".pipeline-check-ignore.yml"
    p.write_text(
        "- check_id: GHA-001\n"
        "  resource: a.yml\n"
        "  resource: b.yml\n"
    )
    rules = load_ignore_file(p)
    captured = capsys.readouterr()
    assert "duplicate key" in captured.err
    assert rules == []
