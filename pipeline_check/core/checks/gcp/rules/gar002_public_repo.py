"""GAR-002. Artifact Registry repository is publicly readable."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GAR-002",
    title="Artifact Registry repository is publicly readable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Remove allUsers and allAuthenticatedUsers from the "
        "repository's IAM policy. Use service accounts with "
        "artifactregistry.reader for authenticated access."
    ),
    docs_note=(
        "A publicly readable repository allows anyone to pull "
        "images. Internal images may contain proprietary code, "
        "configuration, or embedded credentials."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.artifact_registry_repos():
        name = repo.get("name", "<unnamed>")
        mode = repo.get("mode", "STANDARD_REPOSITORY")
        if mode == "VIRTUAL_REPOSITORY":
            continue
        passed = True
        desc = f"Repository '{name}' has no public IAM bindings."
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
