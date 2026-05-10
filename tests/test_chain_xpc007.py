"""XPC-007 cross-provider chain tests.

Same shape as the XPC-001..006 modules. Exercises every branch of
the ``match()`` function for the SCM-005 + GHA-001 (unpinned-actions
+ Dependabot-off) composite.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc007_unpinned_actions_no_remediation as r,
)
from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Severity,
)


def _failing(check_id: str, resource: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check_id=check_id,
        title="synthetic",
        severity=severity,
        resource=resource,
        description="synthetic test fixture",
        recommendation="",
        passed=False,
        confidence=Confidence.HIGH,
    )


def _passing(check_id: str, resource: str) -> Finding:
    return Finding(
        check_id=check_id,
        title="synthetic",
        severity=Severity.HIGH,
        resource=resource,
        description="synthetic test fixture",
        recommendation="",
        passed=True,
        confidence=Confidence.HIGH,
    )


class TestXPC007:
    def test_fires_on_combined_scm005_gha001(self) -> None:
        findings = [
            _failing("SCM-005", "github:org/repo",
                     severity=Severity.MEDIUM),
            _failing("GHA-001", ".github/workflows/ci.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-007"
        assert c.severity == Severity.HIGH
        assert "github:org/repo" in c.resources
        assert ".github/workflows/ci.yml" in c.resources
        assert "SCM-005" in c.triggering_check_ids
        assert "GHA-001" in c.triggering_check_ids
        # Narrative cites the canonical real-world incident.
        assert "tj-actions" in c.narrative.lower()

    def test_silent_when_only_scm_fires(self) -> None:
        findings = [
            _failing("SCM-005", "github:org/repo"),
            _passing("GHA-001", ".github/workflows/ci.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_gha_fires(self) -> None:
        findings = [
            _passing("SCM-005", "github:org/repo"),
            _failing("GHA-001", ".github/workflows/ci.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("SCM-005", "github:org/repo"),
            _passing("GHA-001", ".github/workflows/ci.yml"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            _failing("SCM-005", "github:org/repo-a"),
            _failing("SCM-005", "github:org/repo-b"),
            _failing("GHA-001", ".github/workflows/ci.yml"),
            _failing("GHA-001", ".github/workflows/release.yml"),
            _failing("GHA-001", ".github/workflows/deploy.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_engine_dispatch_picks_up_xpc007(self) -> None:
        findings = [
            _failing("SCM-005", "github:org/repo"),
            _failing("GHA-001", ".github/workflows/ci.yml"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-007" in ids

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        findings = [
            Finding(
                check_id="SCM-005", title="x", severity=Severity.MEDIUM,
                resource="github:org/repo", description="",
                recommendation="", passed=False,
                confidence=Confidence.LOW,
            ),
            Finding(
                check_id="GHA-001", title="x", severity=Severity.HIGH,
                resource=".github/workflows/ci.yml", description="",
                recommendation="", passed=False,
                confidence=Confidence.HIGH,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.LOW
