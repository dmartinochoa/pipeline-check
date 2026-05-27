"""GAR-001. Artifact Registry repository has no vulnerability scanning."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GAR-001",
    title="Artifact Registry repository has no vulnerability scanning",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-1104",),
    recommendation=(
        "Enable vulnerability scanning on the repository by "
        "configuring the Container Analysis / On-Demand Scanning "
        "API. Set the scanning config to STANDARD or enable "
        "Artifact Analysis at the project level."
    ),
    docs_note=(
        "Without vulnerability scanning, container images with "
        "known CVEs pass through the artifact store without detection."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.artifact_registry_repos():
        name = repo.get("name", "<unnamed>")
        fmt = repo.get("format", "UNKNOWN")
        if fmt not in ("DOCKER", "UNKNOWN"):
            continue
        scan_config = repo.get("vulnerability_scanning_config", {})
        enablement = scan_config.get("enablement_config", "INHERITED")
        passed = enablement in ("STANDARD", "ENABLED")
        if passed:
            desc = (
                f"Repository '{name}' has vulnerability scanning "
                f"configured ({enablement})."
            )
        else:
            desc = (
                f"Repository '{name}' does not have vulnerability "
                f"scanning enabled (config: {enablement})."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
