"""TKN-007 — ``TaskRun`` / ``PipelineRun`` runs as the default ServiceAccount."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TektonContext

RULE = Rule(
    id="TKN-007",
    title="Tekton run uses the default ServiceAccount",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-IAM",),
    cwe=("CWE-250", "CWE-732"),
    recommendation=(
        "Set ``spec.serviceAccountName`` on every ``TaskRun`` and "
        "``PipelineRun`` to a least-privilege ServiceAccount that "
        "carries only the secrets and RBAC the run actually needs. "
        "Falling back to the namespace's ``default`` SA grants "
        "access to whatever cluster-admin or wildcard role someone "
        "later binds to ``default`` — a privilege-escalation surface "
        "that should never be load-bearing for build pods."
    ),
    docs_note=(
        "An explicit ``serviceAccountName: default`` setting is "
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


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("TaskRun", "PipelineRun"):
            continue
        examined += 1
        spec = doc.data.get("spec") or {}
        if not isinstance(spec, dict):
            spec = {}
        if _missing_or_default(spec):
            offenders.append(f"{doc.kind}/{doc.name}")
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No TaskRun / PipelineRun documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every Run sets a non-default serviceAccountName."
        if passed else
        f"{len(offenders)} run(s) use the default ServiceAccount: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Bind a least-privilege "
        f"SA created for this pipeline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
