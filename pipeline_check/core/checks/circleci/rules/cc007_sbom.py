"""CC-007 — Pipeline should produce an SBOM."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_sbom, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="CC-007",
    title="SBOM not produced (no CycloneDX/syft/Trivy-SBOM step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SBOM",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add an SBOM generation step — `syft . -o cyclonedx-json`, "
        "Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. "
        "Attach the SBOM to the build artifacts so consumers can ingest "
        "it into their vulnerability management pipeline."
    ),
    docs_note=(
        "Without an SBOM, downstream consumers cannot audit the exact "
        "set of dependencies shipped in the artifact, delaying "
        "vulnerability response when a transitive dep is disclosed. "
        "The check recognises CycloneDX, syft, Anchore SBOM action, "
        "spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM "
        "mode."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_sbom(doc)
    if not passed and not produces_artifacts(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        "Pipeline produces an SBOM (CycloneDX / syft / Trivy-SBOM)."
        if passed else
        "Pipeline does not produce a software bill of materials (SBOM). "
        "Without an SBOM, downstream consumers cannot audit the exact "
        "set of dependencies shipped in the artifact, delaying "
        "vulnerability response when a transitive dep is disclosed."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
