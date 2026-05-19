"""IAM-005 (CloudFormation). CI/CD role trust missing sts:ExternalId."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..iam import _iam005_external_trust
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-005",
    title="CI/CD role trust policy missing sts:ExternalId",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-441",),
    recommendation=(
        "Add a ``Condition`` block with "
        "``StringEquals.sts:ExternalId`` to every trust-policy "
        "statement that allows an external AWS account to assume "
        "the role. Generate a high-entropy ExternalId once and "
        "store it in the relying party's configuration."
    ),
    docs_note=(
        "Parses ``AssumeRolePolicyDocument``. Walks every ``Allow`` "
        "statement whose ``Principal.AWS`` is an external account, "
        "and fires when no ``Condition`` carries ``sts:ExternalId``. "
        "Without it, the role is vulnerable to the confused-deputy "
        "pattern."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam005_external_trust(
            role.properties,
            as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, _, _ in cicd_role_view(ctx)
    ]
