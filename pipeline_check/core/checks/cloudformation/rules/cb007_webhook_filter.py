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
    exploit_example=(
        "# Vulnerable: a CodeBuild webhook with no FilterGroups.\n"
        "Resources:\n"
        "  CIProject:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Source:\n"
        "        Type: GITHUB\n"
        "      Triggers:\n"
        "        Webhook: true\n"
        "\n"
        "# Attack: Webhook: true with no FilterGroups builds on every\n"
        "# event, including pull requests from forks of a public repo.\n"
        "# The fork PR's buildspec and scripts run in CodeBuild with the\n"
        "# project's IAM role, so anyone on the internet executes in\n"
        "# your build account (poisoned-pipeline execution).\n"
        "\n"
        "# Safe: restrict triggers to a trusted branch and actor.\n"
        "      Triggers:\n"
        "        Webhook: true\n"
        "        FilterGroups:\n"
        "          - - Type: HEAD_REF\n"
        "              Pattern: ^refs/heads/main$\n"
        "            - Type: ACTOR_ACCOUNT_ID\n"
        "              Pattern: ^123456789012$"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb007_webhook_filter(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
