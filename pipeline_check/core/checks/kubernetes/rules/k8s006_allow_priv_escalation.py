"""K8S-006. Container ``allowPrivilegeEscalation`` not explicitly false."""
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
    id="K8S-006",
    title="Container allowPrivilegeEscalation not explicitly false",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-269",),
    recommendation=(
        "Set ``securityContext.allowPrivilegeEscalation: false`` on "
        "every container. The Linux ``no_new_privs`` flag stops "
        "setuid binaries and capabilities from gaining elevated "
        "privileges, without this, a compromised process can escape "
        "via setuid utilities still installed in many base images."
    ),
    docs_note=(
        "The default for non-root containers is True (Pod Security "
        "Standard 'baseline' allows this; 'restricted' does not). "
        "An explicit ``false`` is required because Kubernetes treats "
        "an unset field as a deferral to the cluster admission "
        "controller, which may not enforce ``restricted``."
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
            if sc.get("allowPrivilegeEscalation") is not False:
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}"
                )
                # Anchor on the securityContext block when present,
                # otherwise the container, same fallback shape as K8S-005.
                line = _line_of(sc) or _line_of(c)
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
    passed = not offenders
    desc = (
        "Every container sets ``allowPrivilegeEscalation: false``."
        if passed else
        f"{len(offenders)} container(s) leave ``allowPrivilegeEscalation`` "
        f"unset or true: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
