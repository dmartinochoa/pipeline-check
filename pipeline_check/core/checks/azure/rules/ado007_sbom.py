"""ADO-007 — pipeline should produce an SBOM."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_sbom
from ...rule import Rule

RULE = Rule(
    id="ADO-007",
    title="SBOM not produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SBOM",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add an SBOM step — `microsoft/sbom-tool`, `syft . -o "
        "cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM "
        "as a pipeline artifact so downstream consumers can ingest it."
    ),
    docs_note=(
        "Without an SBOM, downstream consumers can't audit the "
        "dependency set shipped in the artifact."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_sbom(doc)
    desc = (
        "Pipeline produces an SBOM (CycloneDX / syft / Microsoft sbom-tool)."
        if passed else
        "Pipeline does not produce a software bill of materials (SBOM)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
