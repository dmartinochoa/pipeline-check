"""Tests for ``--config-strict`` and ``--warn-expiring-suppressions``.

Two small CLI/DX knobs:

* ``--config-strict`` promotes an unknown config-file key from the default
  warn-and-drop to a hard error before a real scan, so a typo (a gate key
  written at the top level instead of under ``gate:``) fails fast.
* ``--warn-expiring-suppressions`` makes the (previously hardcoded 14-day,
  always-on) soon-to-expire forewarning window configurable and
  disable-able. Parsing lives in ``gate.parse_expiry_window``; the window
  is consumed via ``GateConfig.expiry_warning_days``.
"""
from __future__ import annotations

import datetime as _dt

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.gate import (
    EXPIRY_WARNING_DAYS,
    GateConfig,
    IgnoreRule,
    evaluate_gate,
    parse_expiry_window,
)
from pipeline_check.core.scorer import ScoreResult


# ── parse_expiry_window ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("14", 14),
        ("7d", 7),
        ("  30  ", 30),
        ("7D", 7),
        ("0", None),
        ("0d", None),
        ("off", None),
        ("none", None),
        ("never", None),
        ("no", None),
        ("OFF", None),
    ],
)
def test_parse_expiry_window_accepts(raw, expected):
    assert parse_expiry_window(raw) == expected


@pytest.mark.parametrize("raw", ["-1", "-3d", "abc", "3x", "", "d"])
def test_parse_expiry_window_rejects(raw):
    with pytest.raises(ValueError):
        parse_expiry_window(raw)


def test_default_window_constant_matches_gateconfig_default():
    assert GateConfig().expiry_warning_days == EXPIRY_WARNING_DAYS


# ── evaluate_gate: expiry window plumbing ────────────────────────────


def _score(grade: str = "A") -> ScoreResult:
    return {"grade": grade, "score": 95, "counts": {}, "total": 0}


def _ignore_in(days: int) -> IgnoreRule:
    when = _dt.date.today() + _dt.timedelta(days=days)
    return IgnoreRule(check_id="GHA-001", resource=None, expires=when)


def test_expiring_soon_respects_custom_window():
    rule = _ignore_in(5)
    # Window 7 catches a rule 5 days out...
    res = evaluate_gate(
        [], _score(), GateConfig(ignore_rules=[rule], expiry_warning_days=7),
    )
    assert rule in res.expiring_soon
    # ...window 3 does not.
    res = evaluate_gate(
        [], _score(), GateConfig(ignore_rules=[rule], expiry_warning_days=3),
    )
    assert res.expiring_soon == []


def test_expiry_window_none_disables_forewarning_but_not_expired():
    soon = _ignore_in(5)
    past = _ignore_in(-2)
    res = evaluate_gate(
        [],
        _score(),
        GateConfig(ignore_rules=[soon, past], expiry_warning_days=None),
    )
    assert res.expiring_soon == []
    # Already-expired rules are still reported regardless of the window.
    assert past in res.expired_rules


def test_default_gateconfig_uses_two_week_window():
    in10 = _ignore_in(10)
    in20 = _ignore_in(20)
    res = evaluate_gate([], _score(), GateConfig(ignore_rules=[in10, in20]))
    assert in10 in res.expiring_soon       # within 14 days
    assert in20 not in res.expiring_soon   # beyond 14 days


# ── CLI: --config-strict ─────────────────────────────────────────────


def test_config_strict_clean_config_scans(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".pipeline-check.yml").write_text("pipeline: github\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n"
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--config-strict", "--output", "json"],
    )
    # Clean config: --config-strict is a no-op and the scan runs.
    assert result.exit_code in (0, 1), result.output


def test_config_strict_unknown_key_aborts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # ``fail_on`` belongs under ``gate:``; at the top level it's unknown.
    (tmp_path / ".pipeline-check.yml").write_text(
        "pipeline: github\nfail_on: HIGH\n"
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--config-strict", "--output", "json"],
    )
    assert result.exit_code == 2
    assert "fail_on" in result.output
    assert "--config-strict" in result.output


def test_unknown_key_without_strict_still_scans(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".pipeline-check.yml").write_text(
        "pipeline: github\nfail_on: HIGH\n"
    )
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n"
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--output", "json"],
    )
    # Backward compatible: an unknown key is dropped with a warning, not
    # fatal, when --config-strict is absent.
    assert result.exit_code in (0, 1), result.output


# ── CLI: --warn-expiring-suppressions value parsing ──────────────────


def test_warn_expiring_bad_value_is_usage_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n"
    )
    result = CliRunner().invoke(
        scan,
        ["--pipeline", "github", "--warn-expiring-suppressions", "bogus"],
    )
    assert result.exit_code == 2
    assert "warn-expiring-suppressions" in result.output
