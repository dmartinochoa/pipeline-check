"""CP-001 (CloudFormation). No approval before deploy in pipeline stages."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codepipeline import _cp001_approval_before_deploy

RULE = Rule(
    id="CP-001",
    title="No approval action before deploy stages",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-862",),
    recommendation=(
        "Add a ``Manual`` approval action to a stage that precedes "
        "every ``Deploy``-category action. Pipelines that "
        "auto-promote to production trust every prior stage's "
        "findings absolutely."
    ),
    docs_note=(
        "Walks ``AWS::CodePipeline::Pipeline."
        "Stages[*].Actions[*].ActionTypeId.Category``. Fires when "
        "any ``Deploy`` action is reachable from the source without "
        "an intervening ``Approval`` action upstream."
    ),
    exploit_example=(
        "# Vulnerable: a CodePipeline goes Source -> Build ->\n"
        "# Deploy with no manual approval. Every commit reaches\n"
        "# production; a compromised source branch ships straight.\n"
        "Resources:\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      Stages:\n"
        "        - Name: Source\n"
        "          Actions: [{ ActionTypeId: { Category: Source, ... } }]\n"
        "        - Name: Build\n"
        "          Actions: [{ ActionTypeId: { Category: Build, ... } }]\n"
        "        - Name: Deploy\n"
        "          Actions: [{ ActionTypeId: { Category: Deploy, ... } }]\n"
        "\n"
        "# Safe: add a manual approval stage between Build and\n"
        "# Deploy. A reviewer approves each release; an SNS\n"
        "# topic notifies the approver group.\n"
        "Resources:\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      Stages:\n"
        "        - Name: Source\n"
        "          Actions: [...]\n"
        "        - Name: Build\n"
        "          Actions: [...]\n"
        "        - Name: Approve\n"
        "          Actions:\n"
        "            - Name: manual-approval\n"
        "              ActionTypeId:\n"
        "                Category: Approval\n"
        "                Owner: AWS\n"
        "                Provider: Manual\n"
        "                Version: '1'\n"
        "        - Name: Deploy\n"
        "          Actions: [...]"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::CodePipeline::Pipeline"):
        name = as_str(r.properties.get("Name")) or r.logical_id
        stages = r.properties.get("Stages") or []
        findings.append(_cp001_approval_before_deploy(stages, name))
    return findings
