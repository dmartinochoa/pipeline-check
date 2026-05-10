"""XPC-004 cross-provider chain tests.

Same shape as the XPC-001 / XPC-002 / XPC-003 modules. Exercises
every branch of the chain rule's ``match()`` so the SCM + GHA
composite stays predictable across registry refactors.

XPC-004's SCM leg accepts either ``SCM-001`` (no protection rule)
or ``SCM-007`` (rule exists but force-pushes allowed) — both signal
"anyone with write access can land arbitrary code on the default
branch." The tests cover each leg path independently.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc004_token_leak_unprotected_branch as r,
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


class TestXPC004:
    def test_fires_on_scm001_plus_gha019(self) -> None:
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _failing("GHA-019", ".github/workflows/release.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-004"
        assert c.severity == Severity.CRITICAL
        assert "github:org/repo" in c.resources
        assert ".github/workflows/release.yml" in c.resources
        assert "SCM-001" in c.triggering_check_ids
        assert "GHA-019" in c.triggering_check_ids
        # Narrative reflects the no-protection-rule branch.
        assert "no branch protection rule" in c.narrative

    def test_fires_on_scm007_plus_gha019(self) -> None:
        """SCM-007 (force-push allowed) is the alternative SCM leg —
        same chain, different SCM rule satisfies the governance side."""
        findings = [
            _failing("SCM-007", "github:org/repo"),
            _failing("GHA-019", ".github/workflows/release.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert "SCM-007" in c.triggering_check_ids
        assert "force-pushes" in c.narrative

    def test_fires_when_both_scm_legs_present(self) -> None:
        """Both SCM-001 and SCM-007 failing on the same repo plus a
        single GHA-019 should produce two composites (one per SCM
        leg) so the operator sees both governance vectors."""
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _failing("SCM-007", "github:org/repo"),
            _failing("GHA-019", ".github/workflows/release.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 2
        triggers = {tuple(sorted(c.triggering_check_ids)) for c in chains}
        assert ("GHA-019", "SCM-001") in triggers
        assert ("GHA-019", "SCM-007") in triggers

    def test_silent_when_only_scm_fires(self) -> None:
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _passing("GHA-019", ".github/workflows/release.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_gha_fires(self) -> None:
        findings = [
            _passing("SCM-001", "github:org/repo"),
            _failing("GHA-019", ".github/workflows/release.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("SCM-001", "github:org/repo"),
            _passing("GHA-019", ".github/workflows/release.yml"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            _failing("SCM-001", "github:org/repo-a"),
            _failing("SCM-001", "github:org/repo-b"),
            _failing("GHA-019", ".github/workflows/build.yml"),
            _failing("GHA-019", ".github/workflows/release.yml"),
            _failing("GHA-019", ".github/workflows/deploy.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_engine_dispatch_picks_up_xpc004(self) -> None:
        findings = [
            _failing("SCM-001", "github:org/repo"),
            _failing("GHA-019", ".github/workflows/release.yml"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-004" in ids

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        findings = [
            Finding(
                check_id="SCM-001", title="x", severity=Severity.HIGH,
                resource="github:org/repo", description="",
                recommendation="", passed=False,
                confidence=Confidence.HIGH,
            ),
            Finding(
                check_id="GHA-019", title="x", severity=Severity.HIGH,
                resource=".github/workflows/release.yml", description="",
                recommendation="", passed=False,
                confidence=Confidence.MEDIUM,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.MEDIUM
