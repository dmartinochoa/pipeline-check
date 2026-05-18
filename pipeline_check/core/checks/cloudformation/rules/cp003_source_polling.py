"""CP-003 (CloudFormation). Pipeline source action uses polling."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext, as_str
from ..codepipeline import _cp003_source_polling

RULE = Rule(
    id="CP-003",
    title="Source stage using polling instead of event-driven trigger",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-1188",),
    recommendation=(
        "Set ``Configuration.PollForSourceChanges: false`` on every "
        "``Source`` action and create an EventBridge rule (or "
        "CodeStar connection) to drive change detection on commit."
    ),
    docs_note=(
        "Reads ``Stages[*].Actions[*]`` where "
        "``ActionTypeId.Category == \"Source\"`` and "
        "``Configuration.PollForSourceChanges`` is the string "
        "``\"true\"``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("AWS::CodePipeline::Pipeline"):
        name = as_str(r.properties.get("Name")) or r.logical_id
        stages = r.properties.get("Stages") or []
        findings.append(_cp003_source_polling(stages, name))
    return findings
