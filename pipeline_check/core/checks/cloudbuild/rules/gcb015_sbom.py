"""GCB-015 — Pipeline should produce a software bill of materials.

Reuses the cross-provider ``has_sbom`` helper so the tool catalogue
(syft / CycloneDX / spdx-sbom-generator / Microsoft sbom-tool /
Trivy-SBOM) stays in sync with GHA-007 / GL-007 / BB-007 / ADO-007 /
CC-007 / JF-007. Silent-pass when the pipeline does not appear to
produce artifacts (no top-level ``images:``, no ``docker push`` /
``gcloud run deploy`` / ``kubectl apply`` in any step).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_sbom, produces_artifacts
from ...rule import Rule

RULE = Rule(
    id="GCB-015",
    title="SBOM not produced (no CycloneDX / syft / Trivy-SBOM step)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-SBOM",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add an SBOM generation step — ``syft <image> -o cyclonedx-json``, "
        "``trivy image --format cyclonedx`` — and publish the resulting "
        "document alongside the image (typically via a cosign attestation "
        "so the SBOM travels with the artifact)."
    ),
    docs_note=(
        "Complements GCB-009 (signing) and GCB-008 (vuln scanning). "
        "Without an SBOM, downstream consumers cannot audit the exact "
        "dependency set shipped in a Cloud Build image, delaying "
        "vulnerability response when a transitive dep is disclosed. "
        "Pairs naturally with ``cosign attest --type cyclonedx`` in a "
        "follow-up step."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    produces = produces_artifacts(doc) or bool(doc.get("images"))
    passed = has_sbom(doc)
    if not passed and not produces:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No artifact production detected — check not applicable.",
            recommendation=RULE.recommendation, passed=True,
        )
    desc = (
        "Pipeline produces an SBOM (syft / CycloneDX / Trivy-SBOM / "
        "sbom-tool / spdx-sbom-generator)."
        if passed else
        "Pipeline does not produce a software bill of materials. "
        "Without an SBOM, downstream consumers cannot audit the exact "
        "set of dependencies shipped in the artifact."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
