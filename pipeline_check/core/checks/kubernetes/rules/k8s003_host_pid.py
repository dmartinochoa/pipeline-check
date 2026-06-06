"""K8S-003. Pod ``hostPID: true`` shares the host's process namespace."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_workload_pod_specs, manifest_location

RULE = Rule(
    id="K8S-003",
    title="Pod hostPID: true",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-ISOLATION"),
    cwe=("CWE-668",),
    recommendation=(
        "Set ``spec.hostPID: false`` (the default) on every workload. "
        "``hostPID: true`` makes every host process visible inside the "
        "container, and combined with privileged execution allows "
        "trivial escape via ``nsenter`` / ``/proc/<pid>/root``."
    ),
    docs_note=(
        "There is no application use case for hostPID. Only specialized "
        "node agents (process exporters, debuggers) legitimately need "
        "it, and those are typically deployed via a system DaemonSet "
        "with an explicit security review."
    ),
    exploit_example=(
        "# Vulnerable: ``hostPID: true`` lets the Pod see every\n"
        "# process on the node. A compromise of the Pod can\n"
        "# ``ps aux`` for credentials in other containers'\n"
        "# command lines, attach a debugger to other processes,\n"
        "# or use ``nsenter`` from the host PID namespace to\n"
        "# escape into any other container.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: debugger }\n"
        "spec:\n"
        "  hostPID: true\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: app@sha256:abc123...\n"
        "\n"
        "# Safe: default Pod PID namespace.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: app }\n"
        "spec:\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: app@sha256:abc123..."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if ps.get("hostPID") is True:
            offenders.append(f"{m.kind}/{m.name}")
            locations.append(manifest_location(m, ps))
    passed = not offenders
    desc = (
        "No workload sets ``hostPID: true``."
        if passed else
        f"{len(offenders)} workload(s) set ``hostPID: true``: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
