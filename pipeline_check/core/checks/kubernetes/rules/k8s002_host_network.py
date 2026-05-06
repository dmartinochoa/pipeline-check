"""K8S-002 — Pod ``hostNetwork: true`` shares the host's network stack."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_workload_pod_specs

RULE = Rule(
    id="K8S-002",
    title="Pod hostNetwork: true",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-ISOLATION"),
    cwe=("CWE-668",),
    recommendation=(
        "Set ``spec.hostNetwork: false`` (the default) on every "
        "workload. ``hostNetwork: true`` puts the pod directly on the "
        "node's network namespace, exposing every host-bound listener "
        "to the container and bypassing CNI network policies."
    ),
    docs_note=(
        "Compromised containers on hostNetwork can sniff or interfere "
        "with traffic from every other pod on the node. Reserve the "
        "flag for system DaemonSets that genuinely require it (CNI "
        "agents, ingress data planes); applications never need it."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if ps.get("hostNetwork") is True:
            offenders.append(f"{m.kind}/{m.name}")
    passed = not offenders
    desc = (
        "No workload sets ``hostNetwork: true``."
        if passed else
        f"{len(offenders)} workload(s) set ``hostNetwork: true``: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
