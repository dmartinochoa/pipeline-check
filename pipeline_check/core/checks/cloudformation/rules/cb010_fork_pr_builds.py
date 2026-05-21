"""CB-010 (CloudFormation). CodeBuild webhook allows fork-PR builds."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _codebuild

RULE = Rule(
    id="CB-010",
    title="CodeBuild webhook allows fork-PR builds without actor filtering",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-863",),
    recommendation=(
        "Add an ``ACTOR_ACCOUNT_ID`` filter to every "
        "``Triggers.FilterGroups`` entry whose ``EVENT`` filter "
        "covers a ``PULL_REQUEST_*`` event. Without it, a fork-PR "
        "build runs with the project's service role."
    ),
    docs_note=(
        "Reads ``Triggers.FilterGroups[*]``. For each group that "
        "covers a ``PULL_REQUEST_*`` event, fires when no sibling "
        "``ACTOR_ACCOUNT_ID`` filter constrains the PR author."
    ),
    exploit_example=(
        "# Vulnerable: ``Triggers.FilterGroups`` accepts\n"
        "# ``PULL_REQUEST_CREATED`` / ``PULL_REQUEST_UPDATED``\n"
        "# events with no ``ACTOR_ACCOUNT_ID`` filter. A fork PR\n"
        "# triggers the build with the project's role.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Triggers:\n"
        "        Webhook: true\n"
        "        FilterGroups:\n"
        "          - - Type: EVENT\n"
        "              Pattern: PULL_REQUEST_CREATED\n"
        "\n"
        "# Safe: add an ``ACTOR_ACCOUNT_ID`` filter restricting\n"
        "# to internal accounts. Fork PRs no longer trigger.\n"
        "Resources:\n"
        "  Build:\n"
        "    Type: AWS::CodeBuild::Project\n"
        "    Properties:\n"
        "      Triggers:\n"
        "        Webhook: true\n"
        "        FilterGroups:\n"
        "          - - Type: EVENT\n"
        "              Pattern: PULL_REQUEST_CREATED\n"
        "            - Type: ACTOR_ACCOUNT_ID\n"
        "              Pattern: '12345678|23456789'"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codebuild(ctx) if f.check_id == "CB-010"]
