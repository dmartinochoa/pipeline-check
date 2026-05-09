"""XPC-003 cross-provider chain tests.

Same shape as the XPC-001 / XPC-002 modules: a synthetic findings
list exercises every branch of the chain rule's ``match()``.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc003_unverified_helm_release as r,
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


class TestXPC003:
    def test_fires_on_combined_helm_oci_failures(self) -> None:
        findings = [
            _failing("HELM-002", "charts/api/Chart.lock"),
            _failing("OCI-002", "image.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-003"
        assert c.severity == Severity.HIGH
        assert "charts/api/Chart.lock" in c.resources
        assert "image.json" in c.resources
        assert "HELM-002" in c.triggering_check_ids
        assert "OCI-002" in c.triggering_check_ids

    def test_silent_when_only_helm_fires(self) -> None:
        findings = [
            _failing("HELM-002", "Chart.lock"),
            _passing("OCI-002", "img.json"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_oci_fires(self) -> None:
        findings = [
            _passing("HELM-002", "Chart.lock"),
            _failing("OCI-002", "img.json"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("HELM-002", "Chart.lock"),
            _passing("OCI-002", "img.json"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        findings = [
            _failing("HELM-002", "charts/api/Chart.lock"),
            _failing("HELM-002", "charts/worker/Chart.lock"),
            _failing("OCI-002", "img-amd64.json"),
            _failing("OCI-002", "img-arm64.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 4
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert len(pairs) == 4

    def test_engine_dispatch_picks_up_xpc003(self) -> None:
        findings = [
            _failing("HELM-002", "Chart.lock"),
            _failing("OCI-002", "img.json"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-003" in ids

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        findings = [
            Finding(
                check_id="HELM-002", title="x", severity=Severity.HIGH,
                resource="Chart.lock", description="", recommendation="",
                passed=False, confidence=Confidence.LOW,
            ),
            Finding(
                check_id="OCI-002", title="x", severity=Severity.HIGH,
                resource="img.json", description="", recommendation="",
                passed=False, confidence=Confidence.HIGH,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.LOW
