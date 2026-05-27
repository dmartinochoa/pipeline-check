"""IAM-001 (Terraform). CI/CD role has AdministratorAccess attached."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..iam import _iam001_admin_access
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-001",
    title="CI/CD role has AdministratorAccess policy attached",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-269",),
    recommendation=(
        "Replace ``AdministratorAccess`` with least-privilege policies "
        "that grant only the specific actions and resources the build "
        "actually needs. Pair with IAM-003 (permissions boundary) so a "
        "future policy edit can't quietly re-broaden the role."
    ),
    docs_note=(
        "Considers a role CI/CD-scoped when its ``assume_role_policy`` "
        "trusts ``codebuild.amazonaws.com``, "
        "``codepipeline.amazonaws.com``, or "
        "``codedeploy.amazonaws.com``. Reads ``managed_policy_arns`` "
        "plus every ``aws_iam_role_policy_attachment.policy_arn`` "
        "joined to the role, fires when "
        "``arn:aws:iam::aws:policy/AdministratorAccess`` appears."
    ),
    exploit_example=(
        "# Vulnerable: the CI role carries AdministratorAccess.\n"
        "# A compromised build step can create IAM users, delete\n"
        "# S3 buckets, or pivot to any service in the account.\n"
        'resource "aws_iam_role" "ci" {\n'
        '  name               = "codebuild-ci"\n'
        "  assume_role_policy = data.aws_iam_policy_document.cb_trust.json\n"
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n'
        "}\n"
        "\n"
        "# Safe: scope to only the actions the build needs.\n"
        'resource "aws_iam_role" "ci" {\n'
        '  name               = "codebuild-ci"\n'
        "  assume_role_policy = data.aws_iam_policy_document.cb_trust.json\n"
        "  managed_policy_arns = [\n"
        '    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",\n'
        '    "arn:aws:iam::aws:policy/AmazonECRFullAccess",\n'
        "  ]\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _iam001_admin_access(arns, role.values.get("name") or role.name)
        for role, arns, _ in cicd_role_view(ctx)
    ]
