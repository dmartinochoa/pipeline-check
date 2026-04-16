"""BB-007 — pipeline should produce an SBOM."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_sbom
from ...rule import Rule

RULE = Rule(
    id="BB-007",
    title="SBOM not produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SBOM",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add an SBOM step — `syft . -o cyclonedx-json`, Trivy with "
        "`--format cyclonedx`, or Microsoft's `sbom-tool`. Attach "
        "the SBOM as a build artifact."
    ),
    docs_note=(
        "Without an SBOM, downstream consumers can't audit the "
        "dependency set shipped in the artifact. Passes when "
        "CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_sbom(doc)
    desc = (
        "Pipeline produces an SBOM (CycloneDX / syft / Trivy-SBOM)."
        if passed else
        "Pipeline does not produce a software bill of materials "
        "(SBOM). Without an SBOM, downstream consumers cannot audit "
        "the exact set of dependencies shipped in the artifact."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
