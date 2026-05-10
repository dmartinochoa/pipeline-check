"""XPC-005 cross-provider chain tests.

Same shape as the XPC-001..004 modules. Exercises every branch of
the chain rule's ``match()`` so the SCM-source-side + GHA-artifact-
side composite stays predictable across registry refactors.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc005_unsigned_source_to_unsigned_artifact as r,
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
        severity=Severity.MEDIUM,
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
        severity=Severity.MEDIUM,
        resource=resource,
        description="synthetic test fixture",
        recommendation="",
        passed=True,
        confidence=Confidence.HIGH,
    )


class TestXPC005:
    def test_fires_on_combined_scm006_gha006(self) -> None:
        findings = [
            _failing("SCM-006", "github:org/repo"),
            _failing("GHA-006", ".github/workflows/release.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-005"
        assert c.severity == Severity.HIGH
        assert "github:org/repo" in c.resources
        assert ".github/workflows/release.yml" in c.resources
        assert "SCM-006" in c.triggering_check_ids
        assert "GHA-006" in c.triggering_check_ids
        # Narrative spells out the end-to-end provenance gap.
        assert "chain of custody" in c.narrative.lower()
        assert "slsa" in c.narrative.lower()

    def test_silent_when_only_scm_fires(self) -> None:
        findings = [
            _failing("SCM-006", "github:org/repo"),
            _passing("GHA-006", ".github/workflows/release.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_gha_fires(self) -> None:
        findings = [
            _passing("SCM-006", "github:org/repo"),
            _failing("GHA-006", ".github/workflows/release.yml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("SCM-006", "github:org/repo"),
            _passing("GHA-006", ".github/workflows/release.yml"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        # Two SCM repos + three offending workflows -> six pairs.
        findings = [
            _failing("SCM-006", "github:org/repo-a"),
            _failing("SCM-006", "github:org/repo-b"),
            _failing("GHA-006", ".github/workflows/build.yml"),
            _failing("GHA-006", ".github/workflows/release.yml"),
            _failing("GHA-006", ".github/workflows/deploy.yml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_engine_dispatch_picks_up_xpc005(self) -> None:
        findings = [
            _failing("SCM-006", "github:org/repo"),
            _failing("GHA-006", ".github/workflows/release.yml"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-005" in ids

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        findings = [
            Finding(
                check_id="SCM-006", title="x", severity=Severity.MEDIUM,
                resource="github:org/repo", description="",
                recommendation="", passed=False,
                confidence=Confidence.LOW,
            ),
            Finding(
                check_id="GHA-006", title="x", severity=Severity.MEDIUM,
                resource=".github/workflows/release.yml", description="",
                recommendation="", passed=False,
                confidence=Confidence.HIGH,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        # LOW (the weaker of the two legs) propagates.
        assert chains[0].confidence == Confidence.LOW
