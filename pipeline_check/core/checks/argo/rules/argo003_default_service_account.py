"""ARGO-003. Workflow spec must set a non-default ``serviceAccountName``."""
from __future__ import annotations

from typing import Any

from ..._primitives.anchors import k8s_sa
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from ..base import ArgoContext, workflow_spec

RULE = Rule(
    id="ARGO-003",
    title="Argo workflow uses the default ServiceAccount",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-IAM",),
    cwe=("CWE-250", "CWE-732"),
    recommendation=(
        "Set ``spec.serviceAccountName`` (or "
        "``spec.workflowSpec.serviceAccountName`` for CronWorkflow) "
        "to a least-privilege ServiceAccount that carries only the "
        "secrets and RBAC the workflow needs. Falling back to the "
        "namespace's ``default`` SA grants access to whatever "
        "cluster-admin or wildcard role someone later binds to "
        "``default``, a privilege-escalation surface that should "
        "never be load-bearing for workflow pods."
    ),
    docs_note=(
        "Applies to ``Workflow`` and ``CronWorkflow``. "
        "``WorkflowTemplate`` / ``ClusterWorkflowTemplate`` are "
        "exempt because the SA is set on the run that references "
        "them. An explicit ``serviceAccountName: default`` is "
        "treated the same as omission."
    ),
)


def _missing_or_default(spec: dict[str, Any]) -> bool:
    sa = spec.get("serviceAccountName")
    if sa is None:
        return True
    if isinstance(sa, str) and sa.strip().lower() in {"", "default"}:
        return True
    return False


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    # ResourceAnchor phase 1: emit one k8s_sa anchor per
    # ``(namespace, default)`` pair the offending workflow runs as.
    # AC-021 intersects this with K8S-029's default-SA-binding anchors
    # to confirm the workflow's default SA actually has a binding in
    # the same namespace. Order-preserving dict de-dupes the
    # (namespace, default) pair when multiple workflows in one
    # namespace all omit serviceAccountName.
    anchor_set: dict[str, ResourceAnchor] = {}
    for doc in ctx.docs:
        if doc.kind not in ("Workflow", "CronWorkflow"):
            continue
        examined += 1
        spec = workflow_spec(doc)
        if _missing_or_default(spec):
            offenders.append(f"{doc.kind}/{doc.name}")
            built = k8s_sa(doc.namespace or None, "default")
            if built is not None:
                anchor_set[built.identity] = built
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Workflow / CronWorkflow documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every Workflow sets a non-default serviceAccountName."
        if passed else
        f"{len(offenders)} workflow(s) use the default SA: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Bind a least-privilege "
        f"SA created for this workflow."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=tuple(anchor_set.values()),
    )
