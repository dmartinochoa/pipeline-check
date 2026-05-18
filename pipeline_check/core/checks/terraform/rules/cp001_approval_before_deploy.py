"""CP-001 (Terraform). No approval before deploy in pipeline stages."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codepipeline import _cp001_approval_before_deploy

RULE = Rule(
    id="CP-001",
    title="No approval action before deploy stages",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-862",),
    recommendation=(
        "Add a ``Manual`` approval action to a stage that precedes every "
        "``Deploy``-category action. Pipelines that auto-promote to "
        "production trust every prior stage's findings absolutely."
    ),
    docs_note=(
        "Walks ``aws_codepipeline.stage[*].action[*].category``. Fires "
        "when any ``Deploy`` action is reachable from the source without "
        "an intervening ``Approval`` action upstream of it."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    findings: list[Finding] = []
    for r in ctx.resources("aws_codepipeline"):
        name = r.values.get("name") or r.name
        stages = r.values.get("stage", []) or []
        findings.append(_cp001_approval_before_deploy(stages, name))
    return findings
