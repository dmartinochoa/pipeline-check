"""ECR-002 — ECR repository has mutable image tags."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-002",
    title="Image tags are mutable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-494",),
    recommendation=(
        "Set imageTagMutability=IMMUTABLE on the repository. Reference images "
        "by digest (sha256:...) in deployment manifests for strongest "
        "immutability guarantees."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.ecr_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        mutability = repo.get("imageTagMutability", "MUTABLE")
        passed = mutability == "IMMUTABLE"
        if passed:
            desc = "Image tags are immutable — pushed tags cannot be overwritten."
        else:
            desc = (
                "Image tag mutability is MUTABLE. Any principal with ecr:PutImage "
                "can silently overwrite a tag (e.g. :latest or a semver tag), "
                "allowing a malicious or accidental image swap to affect deployments "
                "that pull by tag without verifying a digest."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
