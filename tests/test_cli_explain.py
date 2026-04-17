"""Tests for the ``pipeline_check --explain CHECK_ID`` subcommand."""
from __future__ import annotations

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.rule import Rule
from pipeline_check.core.explain import (
    _build_index,
    _suggest,
    available_ids,
    render,
)


# ─── Renderer — rule-based check ───────────────────────────────────────────


def test_explain_rule_based_check_renders_all_sections():
    body, code = render("GHA-024")
    assert code == 0
    # Header with severity + confidence
    assert "GHA-024" in body
    assert "HIGH confidence" in body  # GHA-024 not in demotion list
    # Standards block
    assert "owasp_cicd_top_10" in body
    # Docs note section
    assert "[What it checks]" in body
    # Fix section
    assert "[How to fix]" in body


def test_explain_rule_based_check_shows_known_fp_when_present():
    body, code = render("GHA-016")
    assert code == 0
    assert "LOW confidence" in body  # demoted
    assert "[Known false-positive modes]" in body
    # The curl-pipe known_fp mentions vendor installers.
    assert "installer" in body.lower()


def test_explain_rule_without_known_fp_omits_section():
    body, code = render("GHA-024")
    assert code == 0
    # GHA-024 has no known_fp — the section should be absent.
    assert "[Known false-positive modes]" not in body


# ─── Renderer — AWS rule-based check (post-migration) ─────────────────────
#
# Every AWS check is now a rule module under ``aws/rules/``; the
# class-based fallback path is exercised by terraform/cloudformation
# modules whose IDs don't overlap with an AWS rule. No such IDs currently
# exist in the repo — if any reappear, add a dedicated test here.


def test_explain_cb001_renders_full_rule_sections():
    body, code = render("CB-001")
    assert code == 0
    assert "CB-001" in body
    assert "CRITICAL" in body
    # Rule-based rendering includes the docs note and fix sections.
    assert "[What it checks]" in body
    assert "[How to fix]" in body


def test_explain_iam002_shows_standards():
    body, code = render("IAM-002")
    assert code == 0
    assert "IAM-002" in body
    assert "owasp_cicd_top_10" in body


# ─── Renderer — unknown check ID ───────────────────────────────────────────


def test_explain_unknown_id_exits_3_with_suggestions():
    body, code = render("GHA-999")
    assert code == 3
    assert "Unknown check ID" in body
    assert "Did you mean" in body
    # Should suggest same-prefix IDs
    assert "GHA-" in body


def test_explain_unknown_id_case_insensitive():
    body, code = render("gha-024")
    assert code == 0
    assert "GHA-024" in body


def test_suggest_prefix_match():
    ids = ["GHA-001", "GHA-002", "CB-001", "IAM-001"]
    # prefix match wins
    assert _suggest("GHA-999", ids)[:2] == ["GHA-001", "GHA-002"]


def test_suggest_fallback_substring():
    ids = ["GHA-001", "CB-001", "IAM-001"]
    # No same-prefix match for XYZ — substring "001" returns the IDs.
    assert _suggest("001", ids) == ids


# ─── CLI integration ───────────────────────────────────────────────────────


def test_cli_explain_exit_zero_for_known_id():
    result = CliRunner().invoke(scan, ["--explain", "GHA-024"])
    assert result.exit_code == 0
    assert "GHA-024" in result.output
    assert "[How to fix]" in result.output


def test_cli_explain_exit_three_for_unknown_id():
    result = CliRunner().invoke(scan, ["--explain", "XYZ-999"])
    assert result.exit_code == 3
    assert "Unknown check ID" in result.output


def test_cli_explain_class_based_id_works():
    result = CliRunner().invoke(scan, ["--explain", "CB-001"])
    assert result.exit_code == 0
    assert "CB-001" in result.output


# ─── Rule dataclass gained known_fp ────────────────────────────────────────


def test_rule_dataclass_has_known_fp_field_defaulting_to_empty_tuple():
    from pipeline_check.core.checks.base import Severity
    r = Rule(id="X-001", title="t", severity=Severity.LOW)
    assert r.known_fp == ()


def test_rule_dataclass_known_fp_roundtrip():
    from pipeline_check.core.checks.base import Severity
    r = Rule(
        id="X-001",
        title="t",
        severity=Severity.LOW,
        known_fp=("mode A", "mode B"),
    )
    assert r.known_fp == ("mode A", "mode B")


# ─── Index coverage ────────────────────────────────────────────────────────


def test_available_ids_includes_rule_based_and_class_based():
    ids = set(available_ids())
    # Rule-based
    assert "GHA-024" in ids
    # Class-based (AWS core)
    assert "CB-001" in ids
    assert "IAM-001" in ids


def test_build_index_is_cached_across_calls():
    first = _build_index()
    second = _build_index()
    assert first is second  # Same object — memoised.


# ─── Manual integration ────────────────────────────────────────────────────


def test_man_topic_explain_listed():
    from pipeline_check.core import manual

    assert "explain" in manual.topics()
    body = manual.render("explain")
    assert "TOPIC: explain" in body
    assert "--explain" in body
