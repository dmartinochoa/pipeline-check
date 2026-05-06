"""K8S-008 — Container ``readOnlyRootFilesystem`` not true."""
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
    id="K8S-008",
    title="Container readOnlyRootFilesystem not true",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``securityContext.readOnlyRootFilesystem: true`` on every "
        "container. A read-only root filesystem stops attackers from "
        "dropping additional payloads into ``/tmp``, ``/var``, or "
        "writable system paths. Mount tmpfs ``emptyDir`` volumes for "
        "the directories the application genuinely needs to write to."
    ),
    docs_note=(
        "Many post-exploitation toolchains (cryptominers, persistence "
        "implants, shell-callbacks) assume a writable root. Locking "
        "it down forces the attacker to use distroless or runtime "
        "tmpfs they can't easily place."
    ),
)


def _sec_ctx(c: dict[str, Any]) -> dict[str, Any]:
    sc = c.get("securityContext")
    return sc if isinstance(sc, dict) else {}


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            if _sec_ctx(c).get("readOnlyRootFilesystem") is not True:
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}"
                )
    passed = not offenders
    desc = (
        "Every container sets ``readOnlyRootFilesystem: true``."
        if passed else
        f"{len(offenders)} container(s) leave the root filesystem "
        f"writable: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
