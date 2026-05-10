"""XPC-008 cross-provider chain tests.

Same shape as the XPC-001..007 modules. Exercises every branch of
the ``match()`` function for the SCM-001/007 + DF-001
(unreviewed-source + mutable-runtime-image) composite.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc008_unreviewed_source_mutable_runtime as r,
)
from pipeline_check.core.checks.base import (
    Confidence,
    Finding,
    Severity,
)


def _failing(check_id: str, resource: str) -> Finding:
    return Finding(
        check_id=check_id,
        title="synthetic",
        severity=Severity.HIGH,
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


class TestXPC008:
    def test_fires_on_scm001_plus_df001(self) -> None:
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-008"
        assert c.severity == Severity.HIGH
        assert "github:org/repo" in c.resources
        assert "Dockerfile" in c.resources
        assert "SCM-001" in c.triggering_check_ids
        assert "DF-001" in c.triggering_check_ids
        # Narrative names the no-protection branch.
        assert "no branch protection rule" in c.narrative

    def test_fires_on_scm007_plus_df001(self) -> None:
        """SCM-007 (force-push allowed) is the alternative SCM leg."""
        findings = [
            _failing("SCM-007", "github:org/repo"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert "SCM-007" in c.triggering_check_ids
        assert "force-pushes" in c.narrative

    def test_fires_when_both_scm_legs_present(self) -> None:
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _failing("SCM-007", "github:org/repo"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 2
        triggers = {tuple(sorted(c.triggering_check_ids)) for c in chains}
        assert ("DF-001", "SCM-001") in triggers
        assert ("DF-001", "SCM-007") in triggers

    def test_silent_when_only_scm_fires(self) -> None:
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _passing("DF-001", "Dockerfile"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_df_fires(self) -> None:
        findings = [
            _passing("SCM-001", "github:org/repo"),
            _failing("DF-001", "Dockerfile"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("SCM-001", "github:org/repo"),
            _passing("DF-001", "Dockerfile"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three Dockerfiles -> six pairs.
        findings = [
            _failing("SCM-001", "github:org/repo-a"),
            _failing("SCM-001", "github:org/repo-b"),
            _failing("DF-001", "api/Dockerfile"),
            _failing("DF-001", "worker/Dockerfile"),
            _failing("DF-001", "cron/Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_engine_dispatch_picks_up_xpc008(self) -> None:
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-008" in ids

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        findings = [
            Finding(
                check_id="SCM-001", title="x", severity=Severity.HIGH,
                resource="github:org/repo", description="",
                recommendation="", passed=False,
                confidence=Confidence.MEDIUM,
            ),
            Finding(
                check_id="DF-001", title="x", severity=Severity.HIGH,
                resource="Dockerfile", description="",
                recommendation="", passed=False,
                confidence=Confidence.HIGH,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.MEDIUM
