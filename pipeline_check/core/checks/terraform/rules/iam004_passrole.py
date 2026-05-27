"""IAM-004 (Terraform). CI/CD role policy allows iam:PassRole on '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..iam import _iam004_passrole_wildcard
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-004",
    title="CI/CD role can PassRole to any role",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Scope ``iam:PassRole`` to the specific role ARNs the pipeline "
        "must hand off to (CodeDeploy task role, ECS task role, …). "
        "Add an ``iam:PassedToService`` condition so the role can only "
        "be passed to the service that actually consumes it."
    ),
    docs_note=(
        "Inspects every policy reachable from a CI/CD role. Fires on "
        "any ``Allow`` statement granting ``iam:PassRole`` (or "
        "``iam:*`` / ``*``) with ``Resource = \"*\"``. PassRole on a "
        "wildcard resource is one of the canonical privilege-escalation "
        "primitives in AWS."
    ),
    exploit_example=(
        "# Vulnerable: CI role can pass any role to any service,\n"
        "# enabling privilege escalation to admin.\n"
        'resource "aws_iam_role_policy" "passrole" {\n'
        "  role   = aws_iam_role.ci.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:PassRole"\n'
        '      Resource = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        "# Safe: scope PassRole to the specific target role.\n"
        'resource "aws_iam_role_policy" "passrole" {\n'
        "  role   = aws_iam_role.ci.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect   = "Allow"\n'
        '      Action   = "iam:PassRole"\n'
        '      Resource = aws_iam_role.ecs_task.arn\n'
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _iam004_passrole_wildcard(docs, role.values.get("name") or role.name)
        for role, _, docs in cicd_role_view(ctx)
    ]
