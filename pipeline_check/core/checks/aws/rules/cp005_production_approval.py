"""CP-005. CodePipeline production deploy stage missing manual approval."""
from __future__ import annotations

import re
from typing import Any

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
    docs_note=(
        "The complement to CP-001: this rule fires only on stages "
        "whose name contains ``prod`` / ``production`` / ``live``. "
        "Even teams that intentionally skip approvals for dev / "
        "staging deploys usually want a human in the loop for a "
        "production-tagged target."
    ),
)

_PROD_TOKENS = frozenset({"prod", "production", "live"})
# Split a name into lowercased words across camelCase, kebab-case, and
# snake_case so token matching is whole-word: "ProdDeploy" / "deploy-prod"
# / "deploy_prod" match "prod", but "Delivery" / "Product" / "reproduce"
# (substring-only matches) do not.
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def _name_matches_prod(text: str) -> bool:
    words = {w.lower() for w in _WORD_RE.findall(text or "")}
    return bool(_PROD_TOKENS & words)


def _stage_is_production(stage: dict[str, Any]) -> bool:
    if _name_matches_prod(stage.get("name") or ""):
        return True
    for action in stage.get("actions", []) or []:
        if _name_matches_prod(action.get("name") or ""):
            return True
    return False


def _has_approval(stage: dict[str, Any]) -> bool:
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
