"""K8S-024. Container missing livenessProbe and readinessProbe."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    container_name,
    iter_containers,
    iter_workload_pod_specs,
    manifest_location,
)

RULE = Rule(
    id="K8S-024",
    title="Container missing both livenessProbe and readinessProbe",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-MONITOR",),
    cwe=("CWE-754",),
    recommendation=(
        "Define at least one of ``livenessProbe`` or "
        "``readinessProbe`` on every long-running container. Without "
        "probes, a wedged pod stays listed as ``Running`` and keeps "
        "receiving traffic, which masks incidents and amplifies the "
        "blast radius of a single faulty replica."
    ),
    docs_note=(
        "Init containers and ephemeral debug containers are exempt, "
        "neither makes sense to probe. Jobs and CronJobs are also "
        "exempt because Kubernetes treats them as one-shot work; "
        "completion is the lifecycle signal, not health."
    ),
)


_PROBELESS_KINDS_OK = frozenset({"Job", "CronJob"})


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if m.kind in _PROBELESS_KINDS_OK:
            continue
        for kind, c in iter_containers(ps):
            if kind != "container":
                continue
            has_liveness = isinstance(c.get("livenessProbe"), dict)
            has_readiness = isinstance(c.get("readinessProbe"), dict)
            if not (has_liveness or has_readiness):
                offenders.append(
                    f"{m.kind}/{m.name} container={container_name(c)}"
                )
                locations.append(manifest_location(m, c))
    passed = not offenders
    desc = (
        "Every long-running container declares at least one health probe."
        if passed else
        f"{len(offenders)} container(s) declare neither liveness nor "
        f"readiness probe: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
