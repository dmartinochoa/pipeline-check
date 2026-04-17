"""CP-001 — CodePipeline Deploy stage reachable without a preceding Approval."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CP-001",
    title="No approval action before deploy stages",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-284",),
    recommendation=(
        "Add a Manual approval action to a stage that precedes every Deploy "
        "stage that targets a production or sensitive environment."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        name = pipeline.get("name", "<unnamed>")
        stages = pipeline.get("stages", []) or []
        approval_seen = False
        deploy_without_approval = False
        for stage in stages:
            for action in stage.get("actions", []) or []:
                category = action.get("actionTypeId", {}).get("category", "")
                if category == "Approval":
                    approval_seen = True
                if category == "Deploy" and not approval_seen:
                    deploy_without_approval = True
        passed = not deploy_without_approval
        if passed:
            desc = "At least one manual approval action exists before all deploy stages."
        else:
            desc = (
                "One or more Deploy stages are reachable without a preceding Manual "
                "approval action. This allows any code change to reach production "
                "automatically without human review, violating flow control principles."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
