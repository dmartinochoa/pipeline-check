"""Tests closing the coverage gaps flagged during review.

Each test here targets a specific uncovered branch identified by the
previous ``--cov-report=term-missing`` run. Keeping them in one file
makes it obvious what's being guarded against: the coverage floor
itself (90% via --cov-fail-under) stops them from silently
evaporating.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from pipeline_check.core import diff as diff_mod
from pipeline_check.core import gate as gate_mod


# ────────────────────────────────────────────────────────────────────────
# diff.py — cover both subprocess code paths without mocking them away.
# ────────────────────────────────────────────────────────────────────────

def test_changed_files_against_non_git_directory(tmp_path):
    """``changed_files`` must return None (not raise, not wrong-path)
    when invoked outside a git checkout. Exercises the real subprocess
    path — no mock — so a regression in how we shell out surfaces."""
    result = diff_mod.changed_files("nonexistent-ref", cwd=tmp_path)
    assert result is None


def test_git_show_against_non_git_directory(tmp_path):
    """Same as above but for the ``git show`` wrapper used by
    ``--baseline-from-git``."""
    result = diff_mod.git_show("origin/main", "baseline.json", cwd=tmp_path)
    assert result is None


# ────────────────────────────────────────────────────────────────────────
# gate.py — the YAML-ignore error branches.
# ────────────────────────────────────────────────────────────────────────

def test_yaml_ignore_malformed_yaml_warns(tmp_path, capsys):
    p = tmp_path / "ignore.yml"
    p.write_text("- {invalid yaml here\n")  # unterminated flow mapping
    rules = gate_mod.load_ignore_file(p)
    captured = capsys.readouterr()
    assert rules == []
    assert "could not parse" in captured.err, (
        "malformed YAML must be surfaced to stderr, not silently swallowed"
    )


def test_yaml_ignore_non_list_top_level_warns(tmp_path, capsys):
    p = tmp_path / "ignore.yml"
    p.write_text("not_a_list: true\n")
    rules = gate_mod.load_ignore_file(p)
    captured = capsys.readouterr()
    assert rules == []
    assert "top-level list" in captured.err


def test_yaml_ignore_skips_non_dict_entries(tmp_path):
    """List entries that aren't dicts (e.g. a stray string) are
    skipped silently so a mis-formatted entry can't block the rest."""
    p = tmp_path / "ignore.yml"
    p.write_text(
        "- check_id: GHA-001\n"
        "- \"just a string\"\n"
        "- check_id: GL-003\n"
    )
    rules = gate_mod.load_ignore_file(p)
    assert [r.check_id for r in rules] == ["GHA-001", "GL-003"]


# ────────────────────────────────────────────────────────────────────────
# sarif_reporter.py — _best_effort_line sad paths.
# ────────────────────────────────────────────────────────────────────────

def test_best_effort_line_returns_none_for_non_file_resource():
    from pipeline_check.core.sarif_reporter import _best_effort_line
    from pipeline_check.core.checks.base import Finding, Severity
    f = Finding(
        check_id="CB-001", title="t", severity=Severity.HIGH,
        resource="arn:aws:codebuild:us-east-1:111:project/app",
        description="", recommendation="", passed=False,
    )
    assert _best_effort_line(f) is None


def test_best_effort_line_returns_none_when_no_pattern_matches(tmp_path):
    from pipeline_check.core.sarif_reporter import _best_effort_line
    from pipeline_check.core.checks.base import Finding, Severity
    # A file with no signature the pattern catalogue knows about.
    wf = tmp_path / "ci.yml"
    wf.write_text("name: ci\non: push\njobs: {}\n")
    f = Finding(
        check_id="GHA-004", title="t", severity=Severity.MEDIUM,  # no pattern registered
        resource=str(wf), description="", recommendation="", passed=False,
    )
    assert _best_effort_line(f) is None


def test_best_effort_line_skips_oversize_file(tmp_path):
    """Files larger than the 256KB cap are skipped to keep SARIF
    generation bounded regardless of pathological inputs."""
    from pipeline_check.core.sarif_reporter import _best_effort_line
    from pipeline_check.core.checks.base import Finding, Severity
    big = tmp_path / "big.yml"
    big.write_text("# pad\n" * (300 * 1024 // 6))  # ~300KB
    f = Finding(
        check_id="GHA-008", title="t", severity=Severity.CRITICAL,
        resource=str(big), description="", recommendation="", passed=False,
    )
    assert _best_effort_line(f) is None


def test_best_effort_line_finds_gha008_secret(tmp_path):
    """Happy path for the secret-scanner line lookup."""
    from pipeline_check.core.sarif_reporter import _best_effort_line
    from pipeline_check.core.checks.base import Finding, Severity
    wf = tmp_path / "ci.yml"
    wf.write_text("jobs:\n  b:\n    env:\n      KEY: AKIAIOSFODNN7EXAMPLE\n")
    f = Finding(
        check_id="GHA-008", title="t", severity=Severity.CRITICAL,
        resource=str(wf), description="", recommendation="", passed=False,
    )
    assert _best_effort_line(f) == 4


# ────────────────────────────────────────────────────────────────────────
# lambda_handler.py — fan-out error branch.
# ────────────────────────────────────────────────────────────────────────

def test_fanout_records_per_scan_error_and_forces_worst_grade(monkeypatch):
    from pipeline_check import lambda_handler as lh

    call_count = {"n": 0}

    def _fake_handler(event, ctx):
        if "regions" in event or "providers" in event:
            return lh._fan_out(
                regions=event.get("regions", []),
                providers=event.get("providers", []),
            )
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {
                "statusCode": 200, "grade": "A", "score": 95,
                "total_findings": 0, "critical_failures": 0,
                "report_s3_key": None, "report_s3_status": "unconfigured",
            }
        raise RuntimeError("synthetic mid-scan crash")

    monkeypatch.setattr(lh, "handler", _fake_handler)

    result = lh._fan_out(regions=["us-east-1", "eu-west-1"], providers=["aws"])
    assert result["statusCode"] == 200
    # One successful scan + one error entry.
    assert len(result["scans"]) == 2
    errs = [s for s in result["scans"] if "error" in s]
    assert len(errs) == 1
    assert "synthetic mid-scan crash" in errs[0]["error"]
    # A crashed scan forces the aggregate worst grade to D so downstream
    # consumers don't mistake a partial failure for an A.
    assert result["worst_grade"] == "D"


# ────────────────────────────────────────────────────────────────────────
# HTML reporter — empty-findings edge case.
# ────────────────────────────────────────────────────────────────────────

def test_html_report_renders_with_no_findings():
    from pipeline_check.core.html_reporter import report_html
    html = report_html([], {"grade": "A", "score": 100, "summary": {}})
    # Dropdowns should still exist (JS guards count == 0 already).
    assert 'id="f-sev"' in html
    assert 'id="f-count"' in html
    # No data rows present. ``data-check-id`` appears as a CSS
    # selector in the inlined JS, so check for a row attribute instead.
    assert 'data-severity="' not in html
