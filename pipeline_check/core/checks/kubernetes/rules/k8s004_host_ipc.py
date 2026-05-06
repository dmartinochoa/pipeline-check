"""K8S-004 — Pod ``hostIPC: true`` shares the host's IPC namespace."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_workload_pod_specs

RULE = Rule(
    id="K8S-004",
    title="Pod hostIPC: true",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-ISOLATION"),
    cwe=("CWE-668",),
    recommendation=(
        "Set ``spec.hostIPC: false`` (the default) on every workload. "
        "``hostIPC: true`` lets the container read and write the "
        "host's shared-memory segments and POSIX message queues, "
        "exposing data exchanged by every other process on the node."
    ),
    docs_note=(
        "Modern applications coordinate via gRPC / sockets, never via "
        "host IPC. Treat this flag as a strong red flag in code "
        "review unless paired with a documented system-level use case."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if ps.get("hostIPC") is True:
            offenders.append(f"{m.kind}/{m.name}")
    passed = not offenders
    desc = (
        "No workload sets ``hostIPC: true``."
        if passed else
        f"{len(offenders)} workload(s) set ``hostIPC: true``: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
