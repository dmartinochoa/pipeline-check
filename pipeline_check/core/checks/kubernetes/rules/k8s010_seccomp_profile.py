"""K8S-010. Container seccompProfile not set to RuntimeDefault/Localhost."""
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
    id="K8S-010",
    title="Container seccompProfile not RuntimeDefault or Localhost",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-693",),
    recommendation=(
        "Set ``securityContext.seccompProfile.type: RuntimeDefault`` "
        "(or ``Localhost`` with a path to your tuned profile) at "
        "either pod or container level. Without seccomp, every "
        "syscall is reachable from the container, modern kernel "
        "CVEs (e.g. ``io_uring``) become trivially exploitable."
    ),
    docs_note=(
        "Pod-level ``securityContext.seccompProfile`` covers all "
        "containers in the pod. Either path passes this rule. The "
        "default of ``Unconfined`` (or unset, which inherits the "
        "node default, usually Unconfined) fails."
    ),
)


def _profile_ok(sc: Any) -> bool:
    if not isinstance(sc, dict):
        return False
    sp = sc.get("seccompProfile")
    if not isinstance(sp, dict):
        return False
    return sp.get("type") in {"RuntimeDefault", "Localhost"}


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        pod_ok = _profile_ok(ps.get("securityContext"))
        for kind, c in iter_containers(ps):
            if pod_ok or _profile_ok(c.get("securityContext")):
                continue
            offenders.append(
                f"{m.kind}/{m.name} {kind}={container_name(c)}"
            )
    passed = not offenders
    desc = (
        "Every container is covered by a RuntimeDefault or Localhost "
        "seccomp profile."
        if passed else
        f"{len(offenders)} container(s) run without a seccomp "
        f"profile: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
