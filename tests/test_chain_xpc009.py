"""XPC-009 cross-tool chain tests.

First chain that fires on an ingested SARIF finding (from
``--ingest``) + a native pipeline-check finding. Exercises the
prefix-matched ingest leg (``INGEST-trivy-CVE-*`` etc.) plus the
exact-match native leg (``DF-001``).
"""
from __future__ import annotations

from pipeline_check.core.chains.engine import evaluate
from pipeline_check.core.chains.rules import (
    xpc009_ingested_cve_plus_floating_image as r,
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
        confidence=Confidence.MEDIUM,
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


class TestXPC009:
    def test_fires_on_trivy_cve_plus_df001(self) -> None:
        findings = [
            _failing("INGEST-trivy-CVE-2024-12345", "alpine:3.18"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        c = chains[0]
        assert c.chain_id == "XPC-009"
        assert c.severity == Severity.HIGH
        # Narrative names the source tool slug pulled from the check_id.
        assert "trivy" in c.narrative
        assert "Dockerfile" in c.resources

    def test_fires_on_grype_cve_prefix(self) -> None:
        """Different scanner, same CVE shape — still fires."""
        findings = [
            _failing("INGEST-grype-CVE-2023-99999", "myapp:latest"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        assert "grype" in chains[0].narrative

    def test_fires_on_trivy_avd_prefix(self) -> None:
        """Trivy's Aqua Vulnerability DB IDs (``AVD-*``) also count
        as CVE-shaped."""
        findings = [
            _failing("INGEST-trivy-AVD-AWS-0028", "infra/main.tf"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1

    def test_fires_on_snyk_prefix(self) -> None:
        findings = [
            _failing("INGEST-snyk-SNYK-PYTHON-CRYPTOGRAPHY-1234", "app/"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 1
        assert "snyk" in chains[0].narrative

    def test_silent_when_only_cve_fires(self) -> None:
        findings = [
            _failing("INGEST-trivy-CVE-2024-12345", "alpine:3.18"),
            _passing("DF-001", "Dockerfile"),
        ]
        assert r.match(findings) == []

    def test_silent_when_only_df_fires(self) -> None:
        findings = [
            _passing("INGEST-trivy-CVE-2024-12345", "alpine:3.18"),
            _failing("DF-001", "Dockerfile"),
        ]
        assert r.match(findings) == []

    def test_silent_when_neither_fires(self) -> None:
        assert r.match([]) == []

    def test_non_cve_ingest_does_not_trigger(self) -> None:
        """An ingested finding that isn't CVE-shaped (e.g., a
        generic Trivy misconfiguration finding without the AVD or
        CVE prefix) should not satisfy the CVE leg."""
        findings = [
            _failing("INGEST-trivy-some-misconfig", "alpine:3.18"),
            _failing("DF-001", "Dockerfile"),
        ]
        assert r.match(findings) == []

    def test_emits_one_chain_per_pair(self) -> None:
        # 3 CVEs + 2 Dockerfiles -> 6 pairs.
        findings = [
            _failing("INGEST-trivy-CVE-2024-1", "alpine:3.18"),
            _failing("INGEST-trivy-CVE-2024-2", "alpine:3.18"),
            _failing("INGEST-grype-CVE-2024-3", "myapp:latest"),
            _failing("DF-001", "api/Dockerfile"),
            _failing("DF-001", "worker/Dockerfile"),
        ]
        chains = r.match(findings)
        assert len(chains) == 6

    def test_engine_dispatch_picks_up_xpc009(self) -> None:
        findings = [
            _failing("INGEST-trivy-CVE-2024-12345", "alpine:3.18"),
            _failing("DF-001", "Dockerfile"),
        ]
        chains = evaluate(findings)
        ids = {c.chain_id for c in chains}
        assert "XPC-009" in ids


# ── failing_prefix helper coverage ────────────────────────────────


class TestFailingPrefixHelper:
    def test_matches_prefix(self):
        from pipeline_check.core.chains.base import failing_prefix
        f = _failing("INGEST-trivy-CVE-2024-1", "x")
        assert failing_prefix([f], "INGEST-trivy-") == [f]

    def test_skips_passing(self):
        from pipeline_check.core.chains.base import failing_prefix
        f = _passing("INGEST-trivy-CVE-2024-1", "x")
        assert failing_prefix([f], "INGEST-trivy-") == []

    def test_supports_multiple_prefixes(self):
        from pipeline_check.core.chains.base import failing_prefix
        a = _failing("INGEST-trivy-CVE-1", "x")
        b = _failing("INGEST-grype-CVE-1", "x")
        c = _failing("DF-001", "x")
        result = failing_prefix(
            [a, b, c], "INGEST-trivy-", "INGEST-grype-",
        )
        # ``Finding`` is slots=True and not hashable; compare by id
        # rather than via set membership.
        assert [id(f) for f in result] == [id(a), id(b)]

    def test_no_match_returns_empty(self):
        from pipeline_check.core.chains.base import failing_prefix
        f = _failing("DF-001", "x")
        assert failing_prefix([f], "INGEST-") == []
