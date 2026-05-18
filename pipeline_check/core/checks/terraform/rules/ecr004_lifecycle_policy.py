"""ECR-004 (Terraform). No ECR lifecycle policy configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..ecr import _ecr004_lifecycle_policy

RULE = Rule(
    id="ECR-004",
    title="No lifecycle policy configured",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-400",),
    recommendation=(
        "Attach an ``aws_ecr_lifecycle_policy`` that expires untagged "
        "and old tagged images. Both bounded image age and bounded "
        "image count are reasonable starting points; pick what matches "
        "your release cadence."
    ),
    docs_note=(
        "Looks for an ``aws_ecr_lifecycle_policy`` joined by "
        "``repository`` for each ``aws_ecr_repository``. Without a "
        "lifecycle policy, images and untagged digests accumulate "
        "indefinitely — old vulnerable images stay deployable and "
        "storage costs creep."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    lifecycles: set[str] = set()
    for r in ctx.resources("aws_ecr_lifecycle_policy"):
        repo = r.values.get("repository")
        if repo:
            lifecycles.add(repo)
    findings: list[Finding] = []
    for r in ctx.resources("aws_ecr_repository"):
        name = r.values.get("name") or r.name
        findings.append(_ecr004_lifecycle_policy(name in lifecycles, name))
    return findings
