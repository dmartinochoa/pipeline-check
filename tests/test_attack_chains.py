"""Tests for the attack-chain detection engine and the rules under
``pipeline_check.core.chains``."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import chains as chains_pkg
from pipeline_check.core.chains.base import (
    Chain,
    ChainRule,
    failing,
    group_by_resource,
    has_failing,
    min_confidence,
)
from pipeline_check.core.checks.base import Confidence, Finding, Severity
from pipeline_check.core.gate import GateConfig, evaluate_gate


# ── Synthetic finding factory ─────────────────────────────────────────


def _f(
    check_id: str,
    resource: str,
    *,
    passed: bool = False,
    confidence: Confidence = Confidence.HIGH,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"{check_id} title",
        severity=severity,
        resource=resource,
        description="",
        recommendation="",
        passed=passed,
        confidence=confidence,
    )


# ── base.py helpers ──────────────────────────────────────────────────


class TestHelpers:
    def test_failing_filters_by_check_id_and_passed_flag(self):
        a = _f("X-1", "r1")
        b = _f("X-2", "r1")
        c = _f("X-1", "r2", passed=True)
        d = _f("X-3", "r1")
        out = failing([a, b, c, d], "X-1", "X-2")
        assert a in out and b in out
        assert c not in out  # passed
        assert d not in out  # different check_id

    def test_has_failing_simple(self):
        assert has_failing([_f("A", "r")], "A") is True
        assert has_failing([_f("A", "r", passed=True)], "A") is False
        assert has_failing([_f("A", "r")], "B") is False

    def test_group_by_resource_keeps_only_complete_groups(self):
        """A resource with only one of the required check IDs is dropped."""
        full = [_f("A", "r1"), _f("B", "r1")]   # both
        partial = [_f("A", "r2")]                # only A
        groups = group_by_resource(full + partial, ["A", "B"])
        assert "r1" in groups
        assert "r2" not in groups
        assert set(groups["r1"]) == {"A", "B"}

    def test_group_by_resource_ignores_passed(self):
        groups = group_by_resource(
            [_f("A", "r1", passed=True), _f("B", "r1")],
            ["A", "B"],
        )
        assert groups == {}

    def test_min_confidence_returns_lowest(self):
        a = _f("A", "r", confidence=Confidence.HIGH)
        b = _f("B", "r", confidence=Confidence.LOW)
        c = _f("C", "r", confidence=Confidence.MEDIUM)
        assert min_confidence([a, b, c]) is Confidence.LOW

    def test_min_confidence_empty_list_defaults_high(self):
        # Defensive: an empty list shouldn't crash callers; HIGH is the
        # sensible default since "no evidence" can't lower confidence.
        assert min_confidence([]) is Confidence.HIGH


# ── Engine ──────────────────────────────────────────────────────────


class TestEngine:
    def test_list_rules_discovers_all_eight_chains(self):
        rule_ids = {r.id for r in chains_pkg.list_rules()}
        # Lock the current set so additions are an explicit decision.
        assert rule_ids == {
            "AC-001", "AC-002", "AC-003", "AC-004",
            "AC-005", "AC-006", "AC-007", "AC-008",
        }

    def test_evaluate_empty_findings_returns_empty(self):
        assert chains_pkg.evaluate([]) == []

    def test_evaluate_filters_by_enabled(self):
        # Even with matching findings, an empty enabled set yields nothing.
        wf = ".github/workflows/x.yml"
        findings = [_f("GHA-002", wf), _f("GHA-005", wf)]
        assert chains_pkg.evaluate(findings, enabled=set()) == []
        # And the same findings DO produce AC-001 when AC-001 is enabled.
        out = chains_pkg.evaluate(findings, enabled={"AC-001"})
        assert [c.chain_id for c in out] == ["AC-001"]

    def test_evaluate_results_sorted_by_chain_id(self):
        wf = ".github/workflows/x.yml"
        findings = [
            _f("GHA-001", wf), _f("GHA-002", wf), _f("GHA-005", wf),
        ]
        out = chains_pkg.evaluate(findings)
        # AC-001 (GHA-002 + GHA-005) and AC-003 (GHA-001 + GHA-005)
        # both fire — must come back in deterministic ID order.
        ids = [c.chain_id for c in out]
        assert ids == sorted(ids)

    def test_chain_to_dict_round_trip_is_json_serialisable(self):
        wf = ".github/workflows/x.yml"
        findings = [_f("GHA-002", wf), _f("GHA-005", wf)]
        chain = chains_pkg.evaluate(findings)[0]
        # to_dict must round-trip through json without failing.
        json.dumps(chain.to_dict())
        d = chain.to_dict()
        assert d["chain_id"] == "AC-001"
        assert d["severity"] == "CRITICAL"
        assert "T1078.004" in d["mitre_attack"]
        assert d["triggering_check_ids"] == ["GHA-002", "GHA-005"]


# ── Per-chain positive / negative ────────────────────────────────────


class TestChainAC001:
    """AC-001 — Fork-PR Credential Theft."""

    def test_fires_when_both_legs_on_same_workflow(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-005", wf)])
        assert any(c.chain_id == "AC-001" for c in out)
        ac1 = next(c for c in out if c.chain_id == "AC-001")
        assert ac1.severity is Severity.CRITICAL
        assert ac1.resources == [wf]
        assert "T1078.004" in ac1.mitre_attack

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-002", ".github/workflows/a.yml"),
            _f("GHA-005", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-001" for c in out)

    def test_does_not_fire_when_one_leg_passed(self):
        wf = ".github/workflows/x.yml"
        out = chains_pkg.evaluate([
            _f("GHA-002", wf, passed=True), _f("GHA-005", wf),
        ])
        assert not any(c.chain_id == "AC-001" for c in out)

    def test_confidence_inherits_minimum(self):
        wf = ".github/workflows/x.yml"
        out = chains_pkg.evaluate([
            _f("GHA-002", wf, confidence=Confidence.HIGH),
            _f("GHA-005", wf, confidence=Confidence.LOW),
        ])
        ac1 = next(c for c in out if c.chain_id == "AC-001")
        assert ac1.confidence is Confidence.LOW


class TestChainAC005:
    """AC-005 — cross-provider; resources may differ between legs."""

    def test_fires_across_providers(self):
        out = chains_pkg.evaluate([
            _f("GHA-006", ".github/workflows/build.yml"),
            _f("CP-001", "arn:aws:codepipeline:us-east-1:1:pipeline/x"),
        ])
        assert any(c.chain_id == "AC-005" for c in out)

    def test_does_not_fire_without_deploy_leg(self):
        out = chains_pkg.evaluate([_f("GHA-006", ".github/workflows/build.yml")])
        assert not any(c.chain_id == "AC-005" for c in out)

    def test_does_not_fire_without_build_leg(self):
        out = chains_pkg.evaluate([_f("CP-001", "arn:aws:codepipeline:.../x")])
        assert not any(c.chain_id == "AC-005" for c in out)


class TestChainAC002:
    """AC-002 — Script Injection to Unprotected Deploy."""

    def test_fires_when_both_legs_on_same_workflow(self):
        wf = ".github/workflows/deploy.yml"
        out = chains_pkg.evaluate([_f("GHA-003", wf), _f("GHA-014", wf)])
        ac2 = [c for c in out if c.chain_id == "AC-002"]
        assert len(ac2) == 1
        assert ac2[0].severity is Severity.CRITICAL
        assert "T1190" in ac2[0].mitre_attack

    def test_does_not_fire_when_legs_on_different_workflows(self):
        out = chains_pkg.evaluate([
            _f("GHA-003", ".github/workflows/a.yml"),
            _f("GHA-014", ".github/workflows/b.yml"),
        ])
        assert not any(c.chain_id == "AC-002" for c in out)


class TestChainAC004:
    """AC-004 — Self-Hosted Runner Persistent Foothold."""

    def test_fires_with_pull_request_target_and_non_ephemeral_runner(self):
        wf = ".github/workflows/ci.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-012", wf)])
        ac4 = [c for c in out if c.chain_id == "AC-004"]
        assert len(ac4) == 1
        assert "T1543" in ac4[0].mitre_attack


class TestChainAC006:
    """AC-006 — Cache Poisoning via Untrusted Trigger."""

    def test_fires_with_pull_request_target_and_cache_key_issue(self):
        wf = ".github/workflows/build.yml"
        out = chains_pkg.evaluate([_f("GHA-002", wf), _f("GHA-011", wf)])
        ac6 = [c for c in out if c.chain_id == "AC-006"]
        assert len(ac6) == 1
        assert ac6[0].severity is Severity.HIGH


class TestChainAC008:
    """AC-008 — Dependency Confusion Window."""

    def test_fires_with_no_lockfile_and_integrity_bypass(self):
        wf = ".github/workflows/release.yml"
        out = chains_pkg.evaluate([_f("GHA-021", wf), _f("GHA-029", wf)])
        ac8 = [c for c in out if c.chain_id == "AC-008"]
        assert len(ac8) == 1
        assert "T1195.001" in ac8[0].mitre_attack


class TestChainAC007:
    """AC-007 — IAM PrivEsc via CodeBuild (AWS-specific, multi-resource)."""

    def test_fires_with_cb002_plus_iam002(self):
        out = chains_pkg.evaluate([
            _f("CB-002", "arn:aws:codebuild:.../proj"),
            _f("IAM-002", "arn:aws:iam::1:role/build"),
        ])
        ac7 = [c for c in out if c.chain_id == "AC-007"]
        assert len(ac7) == 1
        assert ac7[0].severity is Severity.CRITICAL

    def test_fires_with_cb002_plus_iam004(self):
        out = chains_pkg.evaluate([
            _f("CB-002", "arn:aws:codebuild:.../proj"),
            _f("IAM-004", "arn:aws:iam::1:role/build"),
        ])
        assert any(c.chain_id == "AC-007" for c in out)

    def test_does_not_fire_without_iam_leg(self):
        out = chains_pkg.evaluate([_f("CB-002", "arn:aws:codebuild:.../proj")])
        assert not any(c.chain_id == "AC-007" for c in out)


# ── Gate integration ─────────────────────────────────────────────────


class TestGate:
    def _chain(self, chain_id="AC-001"):
        # Build a Chain object directly without re-evaluating; keeps the
        # gate test independent of rule predicates.
        f = _f("GHA-002", ".github/workflows/x.yml")
        return Chain(
            chain_id=chain_id, title="t", severity=Severity.CRITICAL,
            confidence=Confidence.HIGH, summary="", narrative="",
            mitre_attack=[], kill_chain_phase="", triggering_check_ids=[],
            triggering_findings=[f], resources=["x"], references=[],
            recommendation="",
        )

    def test_fail_on_any_chain_trips(self):
        cfg = GateConfig(fail_on_any_chain=True)
        result = evaluate_gate(
            [], {"grade": "A"}, cfg, chains=[self._chain()],
        )
        assert result.passed is False
        assert result.tripped_chains
        assert any("--fail-on-any-chain" in r for r in result.reasons)

    def test_fail_on_chain_specific_id_trips(self):
        cfg = GateConfig(fail_on_chains={"AC-001"})
        result = evaluate_gate(
            [], {"grade": "A"}, cfg,
            chains=[self._chain("AC-001"), self._chain("AC-008")],
        )
        assert result.passed is False
        # Only the named chain is in tripped_chains.
        assert {c.chain_id for c in result.tripped_chains} == {"AC-001"}

    def test_chain_gate_passes_when_no_chains(self):
        cfg = GateConfig(fail_on_any_chain=True)
        result = evaluate_gate([], {"grade": "A"}, cfg, chains=[])
        assert result.passed is True


# ── CLI ──────────────────────────────────────────────────────────────


class TestCLI:
    def test_list_chains_prints_all_ids(self):
        result = CliRunner().invoke(scan, ["--list-chains"])
        assert result.exit_code == 0
        for cid in ("AC-001", "AC-005", "AC-008"):
            assert cid in result.output

    def test_explain_chain_prints_summary(self):
        result = CliRunner().invoke(scan, ["--explain-chain", "AC-001"])
        assert result.exit_code == 0
        assert "AC-001" in result.output
        assert "Fork-PR" in result.output
        assert "MITRE ATT&CK" in result.output

    def test_explain_chain_unknown_id_exits_3_with_suggestion(self):
        result = CliRunner().invoke(scan, ["--explain-chain", "AC-999"])
        assert result.exit_code == 3

    def test_no_chains_in_json_output_when_disabled(self, tmp_path, monkeypatch):
        # Create a fixture workflow that triggers AC-001 — pull_request_target
        # checking out PR head + AWS keys in env.
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text(
            "name: ci\n"
            "on: pull_request_target\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
            "      AWS_SECRET_ACCESS_KEY: notarealsecret/notarealsecret/notarealsecret\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        monkeypatch.chdir(tmp_path)

        def _json_from_output(text: str) -> dict:
            # CliRunner merges stderr/stdout; the CLI emits ``[auto]``
            # and ``[scan]`` status lines to stderr before the JSON
            # body. Carve out the JSON object starting at the first
            # ``{`` and ending at the matching ``}``.
            i = text.index("{")
            return json.loads(text[i:])

        # With chains enabled (default): JSON should include a chains key.
        result = CliRunner().invoke(scan, ["-p", "github", "-o", "json"])
        payload = _json_from_output(result.output)
        assert "chains" in payload
        # With --no-chains: chains key omitted.
        result = CliRunner().invoke(
            scan, ["-p", "github", "-o", "json", "--no-chains"],
        )
        payload = _json_from_output(result.output)
        assert "chains" not in payload
