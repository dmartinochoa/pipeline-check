"""K8S-028. Container declares ``hostPort``, exposing service on the node IP."""
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
    id="K8S-028",
    title="Container declares hostPort",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG",),
    cwe=("CWE-668",),
    recommendation=(
        "Drop ``hostPort`` from container ports and use a Service "
        "(ClusterIP / NodePort / LoadBalancer) to publish the "
        "workload. ``hostPort`` binds directly to the node IP, "
        "bypasses the cluster's network model, and creates a "
        "node-level scheduling constraint that fails replicas with "
        "the same port. Workloads that genuinely need node-port "
        "binding (some CNI/storage agents) should declare it on a "
        "DaemonSet with ``hostNetwork: true`` already approved by "
        "review."
    ),
    docs_note=(
        "``hostPort`` was the pre-Service way to publish a pod's "
        "port and survives in legacy manifests. Modern clusters use "
        "Services, which integrate with the kube-proxy, ingress "
        "controllers, and NetworkPolicies. ``hostPort`` is invisible "
        "to all of those, a port-scan from any other pod that "
        "knows the node IP reaches the workload directly. If a "
        "DaemonSet legitimately needs it (host-agent shape), "
        "suppress this rule with a brief ``.pipelinecheckignore`` "
        "rationale rather than leaving it open across the catalog."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            ports = c.get("ports")
            if not isinstance(ports, list):
                continue
            for entry in ports:
                if not isinstance(entry, dict):
                    continue
                hp: Any = entry.get("hostPort")
                if isinstance(hp, int) and hp > 0:
                    offenders.append(
                        f"{m.kind}/{m.name} {kind}={container_name(c)}: "
                        f"hostPort={hp}"
                    )
    passed = not offenders
    desc = (
        "No container declares a ``hostPort``."
        if passed else
        f"{len(offenders)} container(s) bind to a node-level port: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
