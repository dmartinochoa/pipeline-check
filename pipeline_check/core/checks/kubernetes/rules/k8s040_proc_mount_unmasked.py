"""K8S-040. Container with ``procMount: Unmasked``."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    container_name,
    iter_containers,
    iter_workload_pod_specs,
)

RULE = Rule(
    id="K8S-040",
    title="Container securityContext.procMount: Unmasked",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-668",),
    recommendation=(
        "Remove ``securityContext.procMount: Unmasked`` (or set it "
        "explicitly to ``Default``). The default ``Default`` "
        "procMount type masks several kernel- and node-information "
        "paths under ``/proc`` (``/proc/asound``, ``/proc/acpi``, "
        "``/proc/kcore``, ``/proc/keys``, ``/proc/latency_stats``, "
        "``/proc/timer_list``, ``/proc/timer_stats``, "
        "``/proc/sched_debug``, ``/proc/scsi``) and remounts "
        "``/proc/sys`` as read-only. These maskings are what stop "
        "a container from reading the host's kernel structures or "
        "writing to ``/proc/sys`` and breaking the kernel out of "
        "namespace isolation. ``Unmasked`` undoes all of that."
    ),
    docs_note=(
        "``procMount: Unmasked`` is rarely needed in practice. It "
        "exists for nested-container / KubeVirt scenarios where the "
        "container itself runs an inner container runtime that "
        "needs to set up its own ``/proc`` masking. For an "
        "ordinary application container, ``Unmasked`` is a runtime-"
        "isolation regression that exposes kernel-information "
        "paths and writable ``/proc/sys`` entries to the workload. "
        "Pod Security Standards classify ``Unmasked`` as "
        "'restricted'-violating; the rule fires when any container "
        "(``containers``, ``initContainers``, ``ephemeralContainers``) "
        "explicitly sets ``procMount: Unmasked``."
    ),
    exploit_example=(
        "# Vulnerable: ``procMount: Unmasked`` removes the\n"
        "# default kernel-managed masks on ``/proc``. The\n"
        "# container can read kernel internals\n"
        "# (``/proc/kallsyms``, ``/proc/kcore``) and write to\n"
        "# ``/proc/sysrq-trigger`` to crash the node.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: debug-tool }\n"
        "spec:\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: app@sha256:abc123...\n"
        "      securityContext:\n"
        "        procMount: Unmasked\n"
        "\n"
        "# Safe: default ``procMount: Default`` keeps the\n"
        "# masks. Container processes see a sanitized /proc\n"
        "# with kernel internals hidden.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: app }\n"
        "spec:\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: app@sha256:abc123...\n"
        "      # procMount: Default (implicit)"
    ),
)


def _sec_ctx(c: dict[str, Any]) -> dict[str, Any]:
    sc = c.get("securityContext")
    return sc if isinstance(sc, dict) else {}


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            sc = _sec_ctx(c)
            if sc.get("procMount") == "Unmasked":
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}"
                )
                line = _line_of(sc) or _line_of(c)
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
    passed = not offenders
    desc = (
        "No container sets procMount: Unmasked."
        if passed else
        f"{len(offenders)} container(s) run with procMount: "
        f"Unmasked: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
