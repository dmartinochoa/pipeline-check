"""PBAC-005 — CodePipeline stage action roles match the pipeline role."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="PBAC-005",
    title="CodePipeline stage action roles mirror the pipeline role",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-862",),
    recommendation=(
        "Give each stage action (Source, Build, Deploy) its own "
        "narrowly-scoped IAM role via ``roleArn`` on the action "
        "declaration. Sharing the pipeline-level role means a compromise "
        "of one action (e.g. a build) gains the permissions the deploy "
        "stage also needs."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        name = pipeline.get("name", "<unnamed>")
        pipeline_role = pipeline.get("roleArn", "")
        stages = pipeline.get("stages", []) or []
        overrides = 0
        total_actions = 0
        for stage in stages:
            for action in stage.get("actions", []) or []:
                total_actions += 1
                action_role = action.get("roleArn", "")
                if action_role and action_role != pipeline_role:
                    overrides += 1
        if total_actions == 0:
            continue
        passed = overrides > 0
        desc = (
            f"Pipeline '{name}' has {overrides}/{total_actions} actions with a "
            "scoped roleArn."
            if passed else
            f"Pipeline '{name}' runs every action ({total_actions}) with "
            "the pipeline-level role — no per-stage separation of privilege."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
