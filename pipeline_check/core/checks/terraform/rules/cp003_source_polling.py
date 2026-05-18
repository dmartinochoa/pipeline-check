"""CP-003 (Terraform). Pipeline source action uses polling, not events."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codepipeline import _cp003_source_polling

RULE = Rule(
    id="CP-003",
    title="Source stage using polling instead of event-driven trigger",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-1188",),
    recommendation=(
        "Set ``configuration.PollForSourceChanges = \"false\"`` on every "
        "``Source`` action and create an EventBridge rule (or "
        "``aws_codestarconnections_connection``) to drive change "
        "detection on commit."
    ),
    docs_note=(
        "Reads ``stage[*].action[*]`` where ``category = \"Source\"``. "
        "Fires when ``configuration.PollForSourceChanges`` is the "
        "literal string ``\"true\"`` — polling forces a 60s minimum "
        "trigger lag and bypasses the audit trail an EventBridge rule "
        "would leave."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_codepipeline"):
        name = r.values.get("name") or r.name
        stages = r.values.get("stage", []) or []
        findings.append(_cp003_source_polling(stages, name))
    return findings
