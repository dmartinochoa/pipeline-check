"""IAM-003 (Terraform). CI/CD role has no permissions_boundary."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..iam import _iam003_permission_boundary
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-003",
    title="CI/CD role has no permission boundary",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Attach a permissions boundary policy via "
        "``permissions_boundary = aws_iam_policy.cicd_boundary.arn``. "
        "Boundaries cap the effective permissions of the role even if "
        "an admin later attaches a broader policy."
    ),
    docs_note=(
        "Reads ``aws_iam_role.permissions_boundary`` on every "
        "CI/CD-scoped role. Without a boundary, every additive policy "
        "attached to the role takes immediate effect — there's no "
        "second layer constraining the maximum reach."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _iam003_permission_boundary(
            role.values, role.values.get("name") or role.name
        )
        for role, _, _ in cicd_role_view(ctx)
    ]
