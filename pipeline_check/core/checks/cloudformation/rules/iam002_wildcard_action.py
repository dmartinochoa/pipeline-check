"""IAM-002 (CloudFormation). CI/CD role policy has Action: '*'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
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
        "``Action: \"*\"`` entirely. Access Analyzer or "
        "CloudTrail-based policy generation can suggest a minimum set."
    ),
    docs_note=(
        "Walks every policy document attached to a CI/CD role: "
        "inline ``Role.Policies`` plus the resolved "
        "``AWS::IAM::ManagedPolicy`` referenced via "
        "``ManagedPolicyArns: { Ref: … }``. Fires when any "
        "``Allow`` statement names ``\"*\"`` in ``Action``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _iam002_wildcard_action(
            docs, as_str(role.properties.get("RoleName")) or role.logical_id,
        )
        for role, _, docs in cicd_role_view(ctx)
    ]
