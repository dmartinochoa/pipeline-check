"""K8S-035 — Container ``securityContext.runAsUser`` is 0 (root)."""
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
    id="K8S-035",
    title="Container securityContext.runAsUser is 0",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "Set ``securityContext.runAsUser`` to a non-zero UID (e.g. "
        "1000 or any application-specific value) on every workload "
        "container. The corresponding ``runAsGroup`` and "
        "``fsGroup`` should also be non-zero. Root inside a "
        "container is not isolation — a kernel CVE, a misconfigured "
        "mount, or a mis-applied capability collapses straight into "
        "the host."
    ),
    docs_note=(
        "K8S-007 covers ``runAsNonRoot: false`` (the boolean form). "
        "This rule covers the explicit numeric form: a container "
        "that sets ``runAsUser: 0`` runs as root regardless of "
        "``runAsNonRoot`` being declared elsewhere — Kubernetes "
        "won't reject the spec, it just runs the container as root. "
        "The two rules are paired so neither shape slips through "
        "alone. The pod-level ``securityContext.runAsUser`` "
        "inherits to every container that doesn't override it; "
        "this rule fires on the *effective* UID, walking pod-level "
        "first then per-container override."
    ),
)


def _effective_uid(podspec: dict[str, Any], container: dict[str, Any]) -> Any:
    """Return the runAsUser the container will run with.

    Per-container ``securityContext.runAsUser`` wins; pod-level is
    the fallback. ``None`` means the field is absent at both levels
    — the kubelet uses whatever UID the image was built with, which
    is outside this rule's scope (covered by K8S-007's runAsNonRoot
    check)."""
    c_sc = container.get("securityContext")
    if isinstance(c_sc, dict) and "runAsUser" in c_sc:
        return c_sc.get("runAsUser")
    p_sc = podspec.get("securityContext")
    if isinstance(p_sc, dict) and "runAsUser" in p_sc:
        return p_sc.get("runAsUser")
    return None


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            uid = _effective_uid(ps, c)
            if uid == 0:
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}: "
                    f"runAsUser=0"
                )
                # Anchor on the container's securityContext when
                # present; otherwise the pod-level securityContext
                # is the inherited offender.
                c_sc = c.get("securityContext") if isinstance(c, dict) else None
                anchor = c_sc if isinstance(c_sc, dict) and "runAsUser" in c_sc else (
                    ps.get("securityContext") if isinstance(ps.get("securityContext"), dict)
                    else c
                )
                line = _line_of(anchor) if isinstance(anchor, dict) else None
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
    passed = not offenders
    desc = (
        "No workload container is configured with runAsUser: 0."
        if passed else
        f"{len(offenders)} container(s) explicitly run as uid 0: "
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
