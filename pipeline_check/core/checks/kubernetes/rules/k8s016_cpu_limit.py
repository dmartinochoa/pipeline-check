"""K8S-016 — Container missing ``resources.limits.cpu``."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    container_name,
    iter_containers,
    iter_workload_pod_specs,
)

RULE = Rule(
    id="K8S-016",
    title="Container missing resources.limits.cpu",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-770",),
    recommendation=(
        "Set ``resources.limits.cpu`` on every container. CPU "
        "throttling is the kernel's defense against a neighbour "
        "consuming all node cycles — without a limit, a "
        "compromised container can stall everything else on the "
        "node, including the kubelet. Pair the limit with a "
        "``requests.cpu`` for scheduling."
    ),
    docs_note=(
        "Lower severity than K8S-015 because CPU throttling is "
        "self-healing (workloads slow down rather than die) and "
        "some controllers (e.g. SchedulerProfile, LimitRange) "
        "supply a cluster-default cpu limit transparently."
    ),
)


def _has_cpu_limit(c: dict[str, Any]) -> bool:
    res = c.get("resources")
    if not isinstance(res, dict):
        return False
    limits = res.get("limits")
    if not isinstance(limits, dict):
        return False
    cpu = limits.get("cpu")
    if isinstance(cpu, (int, float)):
        return cpu > 0
    return isinstance(cpu, str) and bool(cpu.strip())


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            if not _has_cpu_limit(c):
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}"
                )
    passed = not offenders
    desc = (
        "Every container declares a CPU limit."
        if passed else
        f"{len(offenders)} container(s) missing resources.limits.cpu: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
