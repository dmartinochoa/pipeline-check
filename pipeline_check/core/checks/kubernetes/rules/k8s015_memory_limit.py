"""K8S-015. Container missing ``resources.limits.memory``."""
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
    id="K8S-015",
    title="Container missing resources.limits.memory",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-770",),
    recommendation=(
        "Set ``resources.limits.memory`` on every container. Without "
        "a memory limit, a leaking or compromised container can "
        "consume the node's RAM until the kernel OOM-kills "
        "neighbouring pods, taking down workloads that share the "
        "node. Pair the limit with a ``requests.memory`` to inform "
        "the scheduler."
    ),
    docs_note=(
        "Init containers and ephemeral containers are also checked: "
        "a leaking init container holds a slot on the node until it "
        "completes and can crowd out other pods just as readily as "
        "an application container."
    ),
)


def _has_mem_limit(c: dict[str, Any]) -> bool:
    res = c.get("resources")
    if not isinstance(res, dict):
        return False
    limits = res.get("limits")
    if not isinstance(limits, dict):
        return False
    mem = limits.get("memory")
    return isinstance(mem, str) and bool(mem.strip())


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            if not _has_mem_limit(c):
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}"
                )
    passed = not offenders
    desc = (
        "Every container declares a memory limit."
        if passed else
        f"{len(offenders)} container(s) missing resources.limits.memory: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
