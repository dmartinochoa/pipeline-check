"""``--inline-explain`` across the non-terminal reporters.

The flag used to affect only the terminal reporter. These tests pin
the wiring into SARIF (rule ``help``), JUnit (``<failure>`` body),
markdown (collapsible section), and Code Quality (issue
``description``), plus the shared ``inline_exploit`` gate. JSON and
HTML carry ``exploit_example`` unconditionally and are not gated.
"""
from __future__ import annotations

import json

from pipeline_check.core.checks.base import Finding, Severity, inline_exploit
from pipeline_check.core.codequality_reporter import report_codequality
from pipeline_check.core.junit_reporter import report_junit
from pipeline_check.core.markdown_reporter import report_markdown
from pipeline_check.core.sarif_reporter import report_sarif
from pipeline_check.core.scorer import score

_EXPLOIT = "attacker moves the v4 tag to a malicious commit and gets RCE"


def _finding(exploit: str | None = _EXPLOIT, *, passed: bool = False) -> Finding:
    return Finding(
        check_id="GHA-001",
        title="Unpinned action",
        severity=Severity.HIGH,
        resource=".github/workflows/ci.yml",
        description="action is not pinned to a SHA",
        recommendation="pin to a commit SHA",
        passed=passed,
        exploit_example=exploit,
    )


# ── shared gate ─────────────────────────────────────────────────────


def test_gate_off_returns_none():
    assert inline_exploit(_finding(), inline_explain=False) is None


def test_gate_on_returns_rstripped_exploit():
    f = _finding(_EXPLOIT + "\n\n")
    assert inline_exploit(f, inline_explain=True) == _EXPLOIT


def test_gate_on_without_example_returns_none():
    assert inline_exploit(_finding(None), inline_explain=True) is None


# ── SARIF ───────────────────────────────────────────────────────────


def _sarif_rule(text: str) -> dict:
    payload = json.loads(text)
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    return next(r for r in rules if r["id"] == "GHA-001")


def test_sarif_off_keeps_exploit_out_of_help():
    findings = [_finding()]
    rule = _sarif_rule(report_sarif(findings, score(findings)))
    assert _EXPLOIT not in rule["help"]["text"]
    assert _EXPLOIT not in rule["help"]["markdown"]


def test_sarif_on_adds_exploit_to_help_text_and_markdown():
    findings = [_finding()]
    rule = _sarif_rule(
        report_sarif(findings, score(findings), inline_explain=True)
    )
    assert _EXPLOIT in rule["help"]["text"]
    assert _EXPLOIT in rule["help"]["markdown"]
    assert "Proof of exploit" in rule["help"]["markdown"]


# ── JUnit ───────────────────────────────────────────────────────────


def test_junit_off_keeps_exploit_out_of_failure_body():
    findings = [_finding()]
    assert _EXPLOIT not in report_junit(findings, score(findings))


def test_junit_on_adds_exploit_to_failure_body():
    findings = [_finding()]
    out = report_junit(findings, score(findings), inline_explain=True)
    assert "Proof of exploit:" in out
    assert _EXPLOIT in out


# ── markdown ────────────────────────────────────────────────────────


def test_markdown_off_has_no_proof_section():
    findings = [_finding()]
    out = report_markdown(findings, score(findings))
    assert "Proof of exploit" not in out
    assert _EXPLOIT not in out


def test_markdown_on_adds_collapsible_proof_section():
    findings = [_finding()]
    out = report_markdown(findings, score(findings), inline_explain=True)
    assert "<summary>Proof of exploit (1)</summary>" in out
    assert _EXPLOIT in out
    # The failures table itself stays a five-column grid.
    assert "| Severity | Check | Title | Resource | Controls |" in out


def test_markdown_on_without_example_emits_no_section():
    findings = [_finding(None)]
    out = report_markdown(findings, score(findings), inline_explain=True)
    assert "Proof of exploit" not in out


# ── Code Quality ────────────────────────────────────────────────────


def test_codequality_off_keeps_exploit_out_of_description():
    findings = [_finding()]
    issues = json.loads(report_codequality(findings))
    assert all(_EXPLOIT not in i["description"] for i in issues)


def test_codequality_on_adds_exploit_to_description():
    findings = [_finding()]
    issues = json.loads(report_codequality(findings, inline_explain=True))
    assert issues
    assert all("Proof of exploit:" in i["description"] for i in issues)
    assert all(_EXPLOIT in i["description"] for i in issues)


def test_codequality_fingerprint_stable_across_inline_explain():
    """Enriching the description must not churn dismissed MR threads:
    the fingerprint is over (check_id, path, line) only."""
    findings = [_finding()]
    off = json.loads(report_codequality(findings))
    on = json.loads(report_codequality(findings, inline_explain=True))
    assert [i["fingerprint"] for i in off] == [i["fingerprint"] for i in on]
