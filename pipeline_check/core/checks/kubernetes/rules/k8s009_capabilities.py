"""K8S-009 — Container capabilities not dropping ALL or adding dangerous caps."""
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

#: Capabilities that grant kernel-level escape paths if added to a container.
_DANGEROUS_CAPS: frozenset[str] = frozenset({
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "DAC_READ_SEARCH", "DAC_OVERRIDE", "SYS_RAWIO", "SYS_BOOT",
    "BPF", "PERFMON",
})

RULE = Rule(
    id="K8S-009",
    title="Container capabilities not dropping ALL / adding dangerous caps",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-272",),
    recommendation=(
        "Drop every capability and add back only what the workload "
        "actually needs:\n\n"
        "    securityContext:\n"
        "      capabilities:\n"
        "        drop: [\"ALL\"]\n"
        "        add: [\"NET_BIND_SERVICE\"]   # only if binding <1024\n\n"
        "Most stateless services need no capabilities at all. Avoid "
        "``SYS_ADMIN`` (effectively root), ``SYS_PTRACE`` (process "
        "snooping), ``NET_ADMIN`` (raw socket access), and "
        "``SYS_MODULE`` (kernel module loading)."
    ),
    docs_note=(
        "Fails when the container does NOT drop ``ALL`` *or* when "
        "``capabilities.add`` includes any of: SYS_ADMIN, NET_ADMIN, "
        "SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, DAC_OVERRIDE, "
        "SYS_RAWIO, SYS_BOOT, BPF, PERFMON, or the literal ``ALL``."
    ),
)


def _sec_ctx(c: dict[str, Any]) -> dict[str, Any]:
    sc = c.get("securityContext")
    return sc if isinstance(sc, dict) else {}


def _cap_list(caps: dict[str, Any], key: str) -> list[str]:
    v = caps.get(key)
    if not isinstance(v, list):
        return []
    return [str(x).upper() for x in v if isinstance(x, str)]


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            caps = _sec_ctx(c).get("capabilities") or {}
            if not isinstance(caps, dict):
                caps = {}
            drop = _cap_list(caps, "drop")
            add = _cap_list(caps, "add")
            why: list[str] = []
            if "ALL" not in drop:
                why.append("does not drop ALL")
            dangerous = [a for a in add if a in _DANGEROUS_CAPS]
            if dangerous:
                why.append(f"adds {','.join(dangerous)}")
            if why:
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)} "
                    f"({'; '.join(why)})"
                )
    passed = not offenders
    desc = (
        "Every container drops ALL capabilities and adds none that "
        "are dangerous."
        if passed else
        f"{len(offenders)} container(s) misuse capabilities: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
