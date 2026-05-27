"""GAR-003. Artifact Registry has no cleanup policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GAR-003",
    title="Artifact Registry has no cleanup policy",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-459",),
    recommendation=(
        "Configure a cleanup policy on the repository to "
        "automatically delete old or unused artifacts. This reduces "
        "storage costs and limits the window in which a compromised "
        "old image can be pulled."
    ),
    docs_note=(
        "Without a cleanup policy, old image tags accumulate "
        "indefinitely. Stale images may contain known vulnerabilities "
        "and remain pullable."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.artifact_registry_repos():
        name = repo.get("name", "<unnamed>")
        policies = repo.get("cleanup_policies", {})
        passed = len(policies) > 0
        if passed:
            desc = (
                f"Repository '{name}' has {len(policies)} cleanup "
                "policy(ies) configured."
            )
        else:
            desc = (
                f"Repository '{name}' has no cleanup policy. Old "
                "artifacts accumulate indefinitely."
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
