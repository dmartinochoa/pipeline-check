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
    exploit_example=(
        "# Vulnerable: ECR repository policy with ``Principal:\n"
        "# '*'``. Anyone on the internet can pull images and\n"
        "# enumerate internal app names + base-image versions.\n"
        "Resources:\n"
        "  Repo:\n"
        "    Type: AWS::ECR::Repository\n"
        "    Properties:\n"
        "      RepositoryName: myapp\n"
        "      RepositoryPolicyText:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal: '*'\n"
        "            Action: [ecr:BatchGetImage, ecr:GetDownloadUrlForLayer]\n"
        "\n"
        "# Safe: scope the principal to a specific account rather\n"
        "# than a wildcard. Use ECR Public for truly public images.\n"
        "Resources:\n"
        "  Repo:\n"
        "    Type: AWS::ECR::Repository\n"
        "    Properties:\n"
        "      RepositoryName: myapp\n"
        "      RepositoryPolicyText:\n"
        "        Version: '2012-10-17'\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            Principal:\n"
        "              AWS: arn:aws:iam::123456789012:root\n"
        "            Action: [ecr:BatchGetImage, ecr:GetDownloadUrlForLayer]"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::ECR::Repository"):
        name = as_str(r.properties.get("RepositoryName")) or r.logical_id
        findings.append(_ecr003_public_policy(r.properties, name))
    return findings
