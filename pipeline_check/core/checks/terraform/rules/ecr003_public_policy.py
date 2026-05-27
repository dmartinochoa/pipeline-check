"""ECR-003 (Terraform). ECR repository policy allows public access."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..ecr import _ecr003_public_policy

RULE = Rule(
    id="ECR-003",
    title="Repository policy allows public access",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Drop any ``Statement`` with ``Effect = \"Allow\"`` plus "
        "``Principal = \"*\"`` (or ``Principal.AWS = \"*\"`` / "
        "``Principal.Service = \"*\"``). Use specific account IDs and "
        "lock cross-account access to a known set."
    ),
    docs_note=(
        "Parses ``aws_ecr_repository_policy.policy`` JSON joined to the "
        "repo by ``repository``. Flags any ``Allow`` statement that "
        "names a wildcard principal — a wildcard there lets every AWS "
        "account in the world pull the image."
    ),
    exploit_example=(
        "# Vulnerable: wildcard principal lets any AWS account\n"
        "# pull container images from this private ECR repo.\n"
        'resource "aws_ecr_repository_policy" "open" {\n'
        "  repository = aws_ecr_repository.app.name\n"
        "  policy     = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        "# Safe: scope to a specific account.\n"
        'resource "aws_ecr_repository_policy" "scoped" {\n'
        "  repository = aws_ecr_repository.app.name\n"
        "  policy     = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "arn:aws:iam::123456789012:root" }\n'
        '      Action    = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]\n'
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    policies: dict[str, str] = {}
    for r in ctx.resources("aws_ecr_repository_policy"):
        repo = r.values.get("repository")
        if repo:
            policies[repo] = r.values.get("policy", "") or ""
    findings: list[Finding] = []
    for r in ctx.resources("aws_ecr_repository"):
        name = r.values.get("name") or r.name
        findings.append(_ecr003_public_policy(policies.get(name), name))
    return findings
