"""K8S-011 — Pod ``serviceAccountName`` unset or 'default'."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_workload_pod_specs

RULE = Rule(
    id="K8S-011",
    title="Pod serviceAccountName unset or 'default'",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Bind every workload to a dedicated, narrow ``ServiceAccount``. "
        "The 'default' SA exists in every namespace and tends to "
        "accrete RoleBindings over time — using it gives the workload "
        "every privilege any other service in the namespace ever "
        "needed. Create a per-workload SA with the minimum RBAC "
        "needed and reference it via ``spec.serviceAccountName``."
    ),
    docs_note=(
        "Both an unset ``serviceAccountName`` (which defaults to "
        "``default``) and an explicit ``serviceAccountName: default`` "
        "fail the rule. Pair this with K8S-012 to also disable token "
        "auto-mounting where the workload doesn't need API access."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        sa = ps.get("serviceAccountName")
        if sa in (None, "", "default"):
            offenders.append(f"{m.kind}/{m.name}")
    passed = not offenders
    desc = (
        "Every workload binds an explicit non-default ServiceAccount."
        if passed else
        f"{len(offenders)} workload(s) use the default ServiceAccount: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
