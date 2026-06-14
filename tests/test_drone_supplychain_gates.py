"""Unit tests for the Drone supply-chain hygiene gates (DR-019..022)."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.drone.base import Pipeline
from pipeline_check.core.checks.drone.rules import (
    dr019_signing as r19,
)
from pipeline_check.core.checks.drone.rules import (
    dr020_sbom as r20,
)
from pipeline_check.core.checks.drone.rules import (
    dr021_slsa_provenance as r21,
)
from pipeline_check.core.checks.drone.rules import (
    dr022_vuln_scanning as r22,
)

_DIGEST = "@sha256:" + "0" * 64


def _pipeline(**data: Any) -> Pipeline:
    body: dict[str, Any] = {"kind": "pipeline", "type": "docker", "name": "default"}
    body.update(data)
    return Pipeline(path=".drone.yml", doc_index=0, data=body)


def _build(*extra: str) -> Pipeline:
    return _pipeline(steps=[
        {"name": "build", "image": f"plugins/docker{_DIGEST}",
         "commands": ["docker build -t app .", "docker push app", *extra]},
    ])


class TestDR019Signing:
    def test_metadata(self):
        assert r19.RULE.id == "DR-019"
        assert r19.RULE.severity is Severity.MEDIUM

    def test_fails_on_build_without_signing(self):
        assert not r19.check(_build()).passed

    def test_passes_with_cosign(self):
        assert r19.check(_build("cosign sign --yes app")).passed

    def test_passes_on_lint_only_pipeline(self):
        p = _pipeline(steps=[{"name": "lint", "image": f"alpine{_DIGEST}",
                              "commands": ["npm run lint"]}])
        assert r19.check(p).passed  # no artifacts -> not applicable


class TestDR020Sbom:
    def test_fails_on_build_without_sbom(self):
        assert not r20.check(_build()).passed

    def test_passes_with_syft(self):
        assert r20.check(_build("syft app -o cyclonedx-json")).passed


class TestDR021Provenance:
    def test_fails_on_build_without_provenance(self):
        assert not r21.check(_build()).passed

    def test_passes_with_attestation(self):
        assert r21.check(_build("cosign attest --predicate slsa.json app")).passed


class TestDR022VulnScanning:
    def test_fails_without_scanner(self):
        assert not r22.check(_build()).passed

    def test_passes_with_trivy(self):
        assert r22.check(_build("trivy image app")).passed
