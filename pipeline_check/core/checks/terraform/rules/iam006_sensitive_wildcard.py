"""IAM-006 (Terraform). Sensitive actions granted with wildcard Resource."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..iam import _iam006_wildcard_resource
from ._iam_context import cicd_role_view

RULE = Rule(
    id="IAM-006",
    title="Sensitive actions granted with wildcard Resource",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Scope ``Resource`` to specific ARNs (bucket ARNs, key ARNs, "
        "secret ARNs, role ARNs). Reserve ``Resource = \"*\"`` for "
        "actions that genuinely require it (e.g. ``ec2:Describe*``, "
        "``cloudwatch:DescribeAlarms``)."
    ),
    docs_note=(
        "Inspects every policy reachable from a CI/CD role. Fires on "
        "any ``Allow`` statement pairing a sensitive service action "
        "(``s3:*``, ``kms:*``, ``secretsmanager:*``, ``ssm:*``, "
        "``iam:*``, ``sts:*``, ``dynamodb:*``, ``lambda:*``, "
        "``ec2:*``) with ``Resource = \"*\"``. A compromised build "
        "with these reaches into prod data, secrets, and IAM in one "
        "step."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _iam006_wildcard_resource(docs, role.values.get("name") or role.name)
        for role, _, docs in cicd_role_view(ctx)
    ]
