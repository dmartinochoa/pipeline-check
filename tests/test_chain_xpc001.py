"""XPC-001 cross-provider chain tests.

Synthesises a mixed findings set with GHA-006 and OCI-002 failures
and asserts the chain engine emits the composite XPC-001 chain.
The single-provider tests verify it stays silent when only one of
the two providers is in the run.
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc001_deploy_without_provenance as r,
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


class TestXPC001:
    def test_fires_on_combined_gha_oci_failures(self) -> None:
        findings = [
            _failing("GHA-006", ".github/workflows/release.yml"),
            _failing("OCI-002", "image.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        chain = chains[0]
        assert chain.chain_id == "XPC-001"
        assert chain.severity == Severity.HIGH
        assert ".github/workflows/release.yml" in chain.resources
        assert "image.json" in chain.resources
        assert "GHA-006" in chain.triggering_check_ids
        assert "OCI-002" in chain.triggering_check_ids

    def test_silent_when_only_gha_fires(self) -> None:
        findings = [
            _failing("GHA-006", ".github/workflows/release.yml"),
            _passing("OCI-002", "image.json"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_oci_fires(self) -> None:
        findings = [
            _passing("GHA-006", ".github/workflows/release.yml"),
            _failing("OCI-002", "image.json"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        findings = [
            _passing("GHA-006", ".github/workflows/release.yml"),
            _passing("OCI-002", "image.json"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_combination(self) -> None:
        # Two failing workflows + two failing manifests -> four
        # composite chains (one per cross-product entry).
        findings = [
            _failing("GHA-006", ".github/workflows/release.yml"),
            _failing("GHA-006", ".github/workflows/build.yml"),
            _failing("OCI-002", "image-amd64.json"),
            _failing("OCI-002", "image-arm64.json"),
        ]
        chains = r.match(findings)
        assert len(chains) == 4
        pairs = {tuple(sorted(c.resources)) for c in chains}
        assert pairs == {
            (".github/workflows/build.yml", "image-amd64.json"),
            (".github/workflows/build.yml", "image-arm64.json"),
            (".github/workflows/release.yml", "image-amd64.json"),
            (".github/workflows/release.yml", "image-arm64.json"),
        }

    def test_engine_finds_chain_via_dispatch(self) -> None:
        # Wire-up smoke test: the chain engine's discovery picks up
        # XPC-001 along with the AC-* chains.
        findings = [
            _failing("GHA-006", "wf.yml"),
            _failing("OCI-002", "img.json"),
        ]
        chains = evaluate(findings)
        xpc = [c for c in chains if c.chain_id == "XPC-001"]
        assert len(xpc) == 1

    def test_confidence_inherits_from_weakest_finding(self) -> None:
        # min_confidence semantics: a HIGH + LOW pair yields LOW.
        findings = [
            Finding(
                check_id="GHA-006", title="x", severity=Severity.HIGH,
                resource="wf.yml", description="", recommendation="",
                passed=False, confidence=Confidence.HIGH,
            ),
            Finding(
                check_id="OCI-002", title="x", severity=Severity.HIGH,
                resource="img.json", description="", recommendation="",
                passed=False, confidence=Confidence.LOW,
            ),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        assert chains[0].confidence == Confidence.LOW
