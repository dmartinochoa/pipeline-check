"""XPC-002 cross-provider chain tests.

Same shape as the XPC-001 test module: a synthetic findings list
exercises every branch of the chain rule's ``match()`` so the
composite path stays predictable across registry refactors.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc002_floating_tag_continuity as r,
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


class TestXPC002:
    def test_fires_on_combined_df_k8s_failures(self) -> None:
        findings = [
            _failing("DF-001", "Dockerfile"),
            _failing("K8S-001", "deploy.yaml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-002"
        assert c.severity == Severity.HIGH
        assert "Dockerfile" in c.resources
        assert "deploy.yaml" in c.resources
        assert "DF-001" in c.triggering_check_ids
        assert "K8S-001" in c.triggering_check_ids

    def test_silent_when_only_dockerfile_fires(self) -> None:
        findings = [
            _failing("DF-001", "Dockerfile"),
            _passing("K8S-001", "deploy.yaml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_k8s_fires(self) -> None:
        findings = [
            _passing("DF-001", "Dockerfile"),
            _failing("K8S-001", "deploy.yaml"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("DF-001", "Dockerfile"),
            _passing("K8S-001", "deploy.yaml"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        # Two Dockerfiles + three manifests -> six pairs.
        findings = [
            _failing("DF-001", "api/Dockerfile"),
            _failing("DF-001", "worker/Dockerfile"),
            _failing("K8S-001", "k8s/api.yaml"),
            _failing("K8S-001", "k8s/worker.yaml"),
            _failing("K8S-001", "k8s/cron.yaml"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 6

    def test_engine_dispatch_picks_up_xpc002(self) -> None:
        findings = [
            _failing("DF-001", "Dockerfile"),
            _failing("K8S-001", "deploy.yaml"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-002" in ids

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        findings = [
            Finding(
                check_id="DF-001", title="x", severity=Severity.HIGH,
                resource="Dockerfile", description="", recommendation="",
                passed=False, confidence=Confidence.MEDIUM,
            ),
            Finding(
                check_id="K8S-001", title="x", severity=Severity.HIGH,
                resource="deploy.yaml", description="", recommendation="",
                passed=False, confidence=Confidence.HIGH,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        # MEDIUM (the weaker of the two legs) propagates.
        assert chains[0].confidence == Confidence.MEDIUM
