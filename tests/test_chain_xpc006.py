"""XPC-006 cross-provider chain tests.

Same shape as the XPC-001..005 modules. Exercises every branch of
the ``match()`` function for the SCM-002 + GHA-002 (unreviewed
fork-PR privilege escalation) composite.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc006_unreviewed_fork_pr_privilege_escalation as r,
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


class TestXPC006:
    def test_fires_on_combined_scm002_gha002(self) -> None:
        findings = [
            _failing("SCM-002", "github:org/repo"),
            _failing("GHA-002", ".github/workflows/triage.yml",
                     severity=Severity.CRITICAL),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-006"
        # Composite carries CRITICAL — matches GHA-002's severity
        # rather than SCM-002's HIGH (the chain rule asserts the
        # combined risk is at least as severe as the worst leg).
        assert c.severity == Severity.CRITICAL
        assert "github:org/repo" in c.resources
        assert ".github/workflows/triage.yml" in c.resources
        assert "SCM-002" in c.triggering_check_ids
        assert "GHA-002" in c.triggering_check_ids
        # Narrative spells out the single-identity-introduction
        # framing the chain is built around.
        assert "single insider" in c.narrative.lower() or \
               "single identity" in c.narrative.lower() or \
               "compromised maintainer" in c.narrative.lower()

    def test_silent_when_only_scm_fires(self) -> None:
        findings = [
            _failing("SCM-002", "github:org/repo"),
            _passing("GHA-002", ".github/workflows/triage.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_gha_fires(self) -> None:
        findings = [
            _passing("SCM-002", "github:org/repo"),
            _failing("GHA-002", ".github/workflows/triage.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("SCM-002", "github:org/repo"),
            _passing("GHA-002", ".github/workflows/triage.yml"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            _failing("SCM-002", "github:org/repo-a"),
            _failing("SCM-002", "github:org/repo-b"),
            _failing("GHA-002", ".github/workflows/triage.yml"),
            _failing("GHA-002", ".github/workflows/labeler.yml"),
            _failing("GHA-002", ".github/workflows/comment-bot.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_engine_dispatch_picks_up_xpc006(self) -> None:
        findings = [
            _failing("SCM-002", "github:org/repo"),
            _failing("GHA-002", ".github/workflows/triage.yml"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-006" in ids

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        findings = [
            Finding(
                check_id="SCM-002", title="x", severity=Severity.HIGH,
                resource="github:org/repo", description="",
                recommendation="", passed=False,
                confidence=Confidence.MEDIUM,
            ),
            Finding(
                check_id="GHA-002", title="x", severity=Severity.CRITICAL,
                resource=".github/workflows/triage.yml", description="",
                recommendation="", passed=False,
                confidence=Confidence.HIGH,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        # MEDIUM (the weaker of the two legs) propagates.
        assert chains[0].confidence == Confidence.MEDIUM
