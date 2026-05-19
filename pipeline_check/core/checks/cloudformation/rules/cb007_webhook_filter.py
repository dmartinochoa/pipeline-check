"""CB-007 (CloudFormation). CodeBuild webhook has no FilterGroups."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..codebuild import _cb007_webhook_filter

RULE = Rule(
    id="CB-007",
    title="CodeBuild webhook has no filter_group",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-732",),
    recommendation=(
        "Define ``Triggers.FilterGroups`` entries that restrict "
        "triggers to specific branches, actors, and event types. At "
        "minimum include an ``ACTOR_ACCOUNT_ID`` filter to keep "
        "fork PRs from triggering builds."
    ),
    docs_note=(
        "Unlike Terraform (where webhooks are a separate resource), "
        "CFN models the webhook as a property of "
        "``AWS::CodeBuild::Project.Triggers``. Reads "
        "``Triggers.{Webhook,FilterGroups}`` and fires when a "
        "webhook is enabled with no filter groups."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb007_webhook_filter(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
