"""PBAC-005 (Terraform). Pipeline stage roles all equal the pipeline role."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase3 import _pbac005_cp005_cp007

RULE = Rule(
    id="PBAC-005",
    title="Pipeline action roles all equal the pipeline-level role",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-250",),
    recommendation=(
        "Assign a least-privilege ``role_arn`` to every ``stage[*]."
        "action[*]`` that needs cross-account or cross-service "
        "permissions, instead of falling back to the "
        "``aws_codepipeline.role_arn``."
    ),
    docs_note=(
        "Compares each ``stage[*].action[*].role_arn`` against the "
        "pipeline's top-level ``role_arn``. When all action-level "
        "values are empty or identical to the pipeline role, every "
        "stage runs with the same blast-radius — a compromise in any "
        "one action reaches the others' resources."
    ),
    exploit_example=(
        "# Vulnerable: both pipeline stages share one IAM role.\n"
        "# A compromised build stage inherits the deploy stage's\n"
        "# production-write permissions.\n"
        'resource "aws_codepipeline" "release" {\n'
        "  stage {\n"
        '    name = "Build"\n'
        "    action {\n"
        "      role_arn = aws_iam_role.shared.arn\n"
        "    }\n"
        "  }\n"
        "  stage {\n"
        '    name = "Deploy"\n'
        "    action {\n"
        "      role_arn = aws_iam_role.shared.arn\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: use separate roles per stage.\n"
        'resource "aws_codepipeline" "release" {\n'
        "  stage {\n"
        '    name = "Build"\n'
        "    action { role_arn = aws_iam_role.build.arn }\n"
        "  }\n"
        "  stage {\n"
        '    name = "Deploy"\n'
        "    action { role_arn = aws_iam_role.deploy.arn }\n"
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        f for f in _pbac005_cp005_cp007(ctx) if f.check_id == "PBAC-005"
    ]
