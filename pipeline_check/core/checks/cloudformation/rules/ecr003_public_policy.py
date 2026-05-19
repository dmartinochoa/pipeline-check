"""ECR-003 (CloudFormation). ECR repository policy allows wildcard."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..ecr import _ecr003_public_policy

RULE = Rule(
    id="ECR-003",
    title="Repository policy allows public access",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Drop any ``Statement`` with ``Effect: Allow`` plus "
        "``Principal: \"*\"`` (or ``Principal.AWS: \"*\"`` / "
        "``Principal.Service: \"*\"``). Use specific account IDs."
    ),
    docs_note=(
        "Parses ``AWS::ECR::Repository.Properties.RepositoryPolicyText`` "
        "(or the standalone resource if used). Flags any ``Allow`` "
        "statement that names a wildcard principal — wildcard there "
        "lets every AWS account in the world pull the image."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::ECR::Repository"):
        name = as_str(r.properties.get("RepositoryName")) or r.logical_id
        findings.append(_ecr003_public_policy(r.properties, name))
    return findings
