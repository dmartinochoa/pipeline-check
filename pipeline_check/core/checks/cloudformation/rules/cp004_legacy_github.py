"""CP-004 (CloudFormation). Pipeline uses legacy ThirdParty/GitHub source."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codepipeline import _cp004_legacy_github

RULE = Rule(
    id="CP-004",
    title="Legacy ThirdParty/GitHub source action (OAuth token)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Switch the source action to "
        "``ActionTypeId.Owner: AWS`` + "
        "``ActionTypeId.Provider: CodeStarSourceConnection`` and "
        "point ``Configuration.ConnectionArn`` at an "
        "``AWS::CodeStarConnections::Connection``."
    ),
    docs_note=(
        "Fires on ``Stages[*].Actions[*]`` whose "
        "``ActionTypeId.Owner == \"ThirdParty\"`` AND "
        "``ActionTypeId.Provider == \"GitHub\"``. The v1 GitHub "
        "action stores a long-lived OAuth token literally in the "
        "pipeline configuration."
    ),
    exploit_example=(
        "# Vulnerable: a CodePipeline source action of type\n"
        "# ``ThirdParty/GitHub`` (v1). The OAuth token lives on\n"
        "# the action config indefinitely, never rotates, and\n"
        "# isn't revocable from the AWS side.\n"
        "Resources:\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      Stages:\n"
        "        - Name: Source\n"
        "          Actions:\n"
        "            - ActionTypeId:\n"
        "                Category: Source\n"
        "                Owner: ThirdParty\n"
        "                Provider: GitHub\n"
        "                Version: '1'\n"
        "              Configuration:\n"
        "                OAuthToken: ghp_long_lived_pat_abc...\n"
        "\n"
        "# Safe: ``Owner: AWS`` with ``Provider:\n"
        "# CodeStarSourceConnection``. The action references a\n"
        "# CodeConnections ARN; the GitHub user can revoke the\n"
        "# connection and AWS refreshes the underlying token.\n"
        "Resources:\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      Stages:\n"
        "        - Name: Source\n"
        "          Actions:\n"
        "            - ActionTypeId:\n"
        "                Category: Source\n"
        "                Owner: AWS\n"
        "                Provider: CodeStarSourceConnection\n"
        "                Version: '1'\n"
        "              Configuration:\n"
        "                ConnectionArn: !Ref GitHubConnection\n"
        "                FullRepositoryId: myorg/myrepo\n"
        "                BranchName: main"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::CodePipeline::Pipeline"):
        name = as_str(r.properties.get("Name")) or r.logical_id
        stages = r.properties.get("Stages") or []
        findings.append(_cp004_legacy_github(stages, name))
    return findings
