"""IAM-005 (Terraform). CI/CD role trust policy missing sts:ExternalId."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..iam import _iam005_external_trust
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-005",
    title="CI/CD role trust policy missing sts:ExternalId",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-441",),
    recommendation=(
        "Add a ``Condition`` block with ``StringEquals.sts:ExternalId`` "
        "to every trust-policy statement that allows an external AWS "
        "account to assume the role. Generate a high-entropy "
        "ExternalId once and store it in the relying party's "
        "configuration."
    ),
    docs_note=(
        "Parses ``aws_iam_role.assume_role_policy``. Walks every "
        "``Allow`` statement whose ``Principal.AWS`` is an external "
        "account, and fires when no ``Condition`` on the statement "
        "carries ``sts:ExternalId``. Without it the role is vulnerable "
        "to the confused-deputy pattern."
    ),
    exploit_example=(
        "# Vulnerable: CI role trusts an external AWS account.\n"
        "# That account's administrators can assume your CI role.\n"
        'data "aws_iam_policy_document" "trust" {\n'
        "  statement {\n"
        '    actions = ["sts:AssumeRole"]\n'
        "    principals {\n"
        '      type        = "AWS"\n'
        '      identifiers = ["arn:aws:iam::999888777666:root"]\n'
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: trust only same-account service principals.\n"
        'data "aws_iam_policy_document" "trust" {\n'
        "  statement {\n"
        '    actions = ["sts:AssumeRole"]\n'
        "    principals {\n"
        '      type        = "Service"\n'
        '      identifiers = ["codebuild.amazonaws.com"]\n'
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _iam005_external_trust(
            role.values, role.values.get("name") or role.name
        )
        for role, _, _ in cicd_role_view(ctx)
    ]
