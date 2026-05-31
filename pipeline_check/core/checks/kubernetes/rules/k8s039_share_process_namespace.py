"""K8S-039. Pod uses ``shareProcessNamespace: true``."""
from __future__ import annotations

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_workload_pod_specs

RULE = Rule(
    id="K8S-039",
    title="Pod uses shareProcessNamespace: true",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-668",),
    recommendation=(
        "Drop ``spec.shareProcessNamespace: true`` from the pod "
        "spec. Containers in the pod will go back to having "
        "isolated PID namespaces, each sees only its own "
        "processes, can't ``ptrace`` neighbors, and can't read "
        "their ``/proc/<pid>/environ`` for env-var-leaked secrets. "
        "If the requirement is sidecar-style log collection or "
        "process-level cooperation, prefer a sidecar pattern that "
        "exchanges data through a shared volume rather than "
        "collapsing the namespace."
    ),
    docs_note=(
        "``shareProcessNamespace: true`` makes every container in "
        "the pod share a single PID namespace. Any container can "
        "then enumerate every other container's processes "
        "(``ps``), read their environment variables and CLI args "
        "from ``/proc/<pid>/``, send them signals, and (with the "
        "right capabilities) ``ptrace`` them. A compromised "
        "sidecar, debug shell, logging agent, observability "
        "exporter, gets a free pivot into every primary "
        "container's secrets. The default is ``false``; setting "
        "it explicitly to ``true`` is the failing shape."
    ),
    known_fp=(
        "Debug pods that explicitly need ``ps`` / ``strace`` "
        "across container boundaries, but those are typically "
        "ephemeralContainers attached to a running pod, not "
        "long-lived pod specs in a manifest. If a permanent "
        "workload genuinely requires it, ignore the rule with "
        "a documented justification.",
    ),
    exploit_example=(
        "# Vulnerable: a pod that shares one PID namespace across\n"
        "# its containers.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: app\n"
        "spec:\n"
        "  shareProcessNamespace: true\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: web:1.2.3\n"
        "    - name: logger\n"
        "      image: third-party/log-agent:latest\n"
        "\n"
        "# Attack: every container in the pod shares one PID namespace,\n"
        "# so the logger sidecar can `ps` the app's processes and read\n"
        "# their secrets straight out of /proc/<pid>/environ and the\n"
        "# command line. A compromised or malicious sidecar pivots into\n"
        "# the primary container's credentials with no escape needed.\n"
        "\n"
        "# Safe: drop the field so containers keep isolated PID\n"
        "# namespaces.\n"
        "spec:\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: web:1.2.3"
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if ps.get("shareProcessNamespace") is True:
            offenders.append(f"{m.kind}/{m.name}")
            line = _line_of(ps) or _line_of(m.data)
            locations.append(Location(
                path=m.path, start_line=line, end_line=line,
                doc_index=m.doc_index,
            ))
    passed = not offenders
    desc = (
        "No pod sets shareProcessNamespace: true."
        if passed else
        f"{len(offenders)} pod(s) collapse PID isolation between "
        f"containers: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
