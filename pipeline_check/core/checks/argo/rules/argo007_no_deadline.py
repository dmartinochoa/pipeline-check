"""ARGO-007 — Workflow lacks ``activeDeadlineSeconds``."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, workflow_spec

RULE = Rule(
    id="ARGO-007",
    title="Argo workflow has no activeDeadlineSeconds",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-400",),
    recommendation=(
        "Set ``spec.activeDeadlineSeconds`` (or "
        "``spec.workflowSpec.activeDeadlineSeconds`` on a "
        "``CronWorkflow``) so a hung step can't pin the workflow "
        "controller's reconcile cycle indefinitely. Pick a value "
        "generous enough for the slowest legitimate run "
        "(e.g. 3600 for a typical pipeline, 21600 for ML training). "
        "Per-template ``activeDeadlineSeconds`` is also accepted as "
        "evidence of intent."
    ),
    docs_note=(
        "Applies to ``Workflow``, ``CronWorkflow``, "
        "``WorkflowTemplate``, and ``ClusterWorkflowTemplate``. The "
        "field can sit at the workflow level or on individual "
        "templates."
    ),
)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        spec = workflow_spec(doc)
        if not spec:
            continue
        if spec.get("activeDeadlineSeconds") is not None:
            continue
        templates = spec.get("templates")
        per_template = False
        if isinstance(templates, list):
            for t in templates:
                if isinstance(t, dict) and t.get("activeDeadlineSeconds") is not None:
                    per_template = True
                    break
        if per_template:
            continue
        offenders.append(f"{doc.kind}/{doc.name}")
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every workflow declares an activeDeadlineSeconds."
        if passed else
        f"{len(offenders)} workflow(s) without activeDeadlineSeconds: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A hung step otherwise "
        f"holds the workflow until the controller defaults expire."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
