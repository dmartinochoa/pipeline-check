"""ECR-004 — ECR repository has no lifecycle policy for stale/untagged images."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-004",
    title="No lifecycle policy configured",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a lifecycle policy that expires untagged images after a short "
        "period (e.g. 7 days) and limits the number of tagged images retained, "
        "reducing exposure to images with known CVEs."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("ecr")
    for repo in catalog.ecr_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        try:
            client.get_lifecycle_policy(repositoryName=name)
            passed = True
            desc = "A lifecycle policy is configured on the repository."
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "LifecyclePolicyNotFoundException":
                passed = False
                desc = (
                    "No lifecycle policy is configured. Without automated cleanup, "
                    "old and potentially vulnerable images accumulate indefinitely, "
                    "increasing storage costs and the attack surface for older tags."
                )
            else:
                passed = False
                desc = f"Could not retrieve lifecycle policy: {exc}"
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
