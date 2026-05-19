"""IAM-003 (CloudFormation). CI/CD role has no PermissionsBoundary."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..iam import _iam003_permission_boundary
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-003",
    title="CI/CD role has no permission boundary",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``PermissionsBoundary`` on every CI/CD role to a "
        "managed policy ARN (or ``{ Ref: <ManagedPolicy> }``). "
        "Boundaries cap effective permissions even if an admin "
        "later attaches a broader policy."
    ),
    docs_note=(
        "Reads ``AWS::IAM::Role.Properties.PermissionsBoundary``. "
        "Without a boundary, every additive policy attached to the "
        "role takes immediate effect — there's no second layer "
        "constraining the maximum reach."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam003_permission_boundary(
            role.properties,
            as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, _, _ in cicd_role_view(ctx)
    ]
