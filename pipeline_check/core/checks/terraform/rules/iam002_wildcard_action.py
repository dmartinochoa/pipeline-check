"""IAM-002 (Terraform). CI/CD role policy has Action: '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..iam import _iam002_wildcard_action
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-002",
    title="CI/CD role has wildcard Action in attached policy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Enumerate the specific IAM actions the role needs and drop "
        "``Action = \"*\"`` (or ``Action = [\"*\"]``) entirely. Tools "
        "like Access Analyzer or CloudTrail-based policy generation "
        "can suggest the minimum set."
    ),
    docs_note=(
        "Walks every policy document attached to a CI/CD role: inline "
        "``aws_iam_role_policy``, inline blocks on the role itself, "
        "customer-managed ``aws_iam_policy`` joined through "
        "``aws_iam_role_policy_attachment``. Fires when any ``Allow`` "
        "statement names ``\"*\"`` in ``Action``."
    ),
    exploit_example=(
        "# Vulnerable: inline policy grants Action: * on all\n"
        "# resources. The CI role can do anything in the account.\n"
        'resource "aws_iam_role_policy" "broad" {\n'
        "  role   = aws_iam_role.ci.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "*"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        "# Safe: scope to the specific actions needed.\n"
        'resource "aws_iam_role_policy" "scoped" {\n'
        "  role   = aws_iam_role.ci.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = ["s3:GetObject", "ecr:GetDownloadUrlForLayer"]\n'
        '      Resource = "arn:aws:s3:::my-artifacts/*"\n'
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _iam002_wildcard_action(docs, role.values.get("name") or role.name)
        for role, _, docs in cicd_role_view(ctx)
    ]
