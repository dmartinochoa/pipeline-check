"""CP-005 — CodePipeline production deploy stage missing manual approval."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CP-005",
    title="Production Deploy stage has no preceding ManualApproval",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-284",),
    recommendation=(
        "Add a ``Manual`` approval action immediately before any stage "
        "whose name contains ``prod`` / ``production``. CP-001 covers "
        "the generic case; this rule specifically looks at production-"
        "tagged stages where the blast radius of an unreviewed deploy "
        "is largest."
    ),
)

_PROD_TOKENS = ("prod", "production", "live")


def _stage_is_production(stage: dict) -> bool:
    name = (stage.get("name") or "").lower()
    if any(tok in name for tok in _PROD_TOKENS):
        return True
    for action in stage.get("actions", []) or []:
        action_name = (action.get("name") or "").lower()
        if any(tok in action_name for tok in _PROD_TOKENS):
            return True
    return False


def _has_approval(stage: dict) -> bool:
    for action in stage.get("actions", []) or []:
        at = action.get("actionTypeId") or {}
        if at.get("category") == "Approval" and at.get("provider") == "Manual":
            return True
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        name = pipeline.get("name", "<unnamed>")
        stages = pipeline.get("stages", []) or []
        missing: list[str] = []
        for idx, stage in enumerate(stages):
            if not _stage_is_production(stage):
                continue
            # Is there an Approval action earlier in the same or prior stage?
            prior_approval = any(_has_approval(s) for s in stages[:idx])
            if not prior_approval and not _has_approval(stage):
                missing.append(stage.get("name", f"stage[{idx}]"))
        if not missing:
            continue
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name,
            description=(
                f"Pipeline '{name}' production stage(s) {missing} have no "
                "preceding ManualApproval."
            ),
            recommendation=RULE.recommendation, passed=False,
        ))
    return findings
