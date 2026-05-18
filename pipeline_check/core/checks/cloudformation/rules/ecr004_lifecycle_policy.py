"""ECR-004 (CloudFormation). ECR repository has no lifecycle policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..ecr import _ecr004_lifecycle_policy

RULE = Rule(
    id="ECR-004",
    title="No lifecycle policy configured",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-400",),
    recommendation=(
        "Configure ``LifecyclePolicy.LifecyclePolicyText`` with rules "
        "that expire untagged and old tagged images. Bounded image "
        "age and bounded image count are reasonable starting points."
    ),
    docs_note=(
        "Reads ``AWS::ECR::Repository.Properties.LifecyclePolicy``. "
        "Without one, images and untagged digests accumulate "
        "indefinitely — old vulnerable images stay deployable."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::ECR::Repository"):
        name = as_str(r.properties.get("RepositoryName")) or r.logical_id
        findings.append(_ecr004_lifecycle_policy(r.properties, name))
    return findings
