"""ECR-001 — ECR repository has imageScanningConfiguration.scanOnPush disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-001",
    title="Image scanning on push not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-1104",),
    recommendation=(
        "Enable imageScanningConfiguration.scanOnPush on the repository. "
        "Consider also enabling Amazon Inspector continuous scanning for "
        "ongoing CVE detection against images already in the registry."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.ecr_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        enabled = (repo.get("imageScanningConfiguration") or {}).get("scanOnPush", False)
        if enabled:
            desc = "Image scanning on push is enabled."
        else:
            desc = (
                "Image scanning on push is disabled. Vulnerabilities in base images "
                "or dependencies will not be detected when images are pushed, allowing "
                "unvetted images to propagate through the pipeline."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=bool(enabled),
        ))
    return findings
