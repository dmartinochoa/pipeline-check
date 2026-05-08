"""K8S-013 — Pod uses a ``hostPath`` volume."""
from __future__ import annotations

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_volumes, iter_workload_pod_specs

RULE = Rule(
    id="K8S-013",
    title="Pod uses a hostPath volume",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-ISOLATION"),
    cwe=("CWE-732",),
    recommendation=(
        "Replace ``hostPath`` volumes with ``configMap``, ``secret``, "
        "``emptyDir``, ``persistentVolumeClaim``, or CSI volumes. "
        "``hostPath`` opens a direct read/write window onto the "
        "node's filesystem; combined with even mild container "
        "compromise it gives the attacker access to other pods' "
        "data, kubelet credentials, and the container runtime."
    ),
    docs_note=(
        "Some legitimate system DaemonSets need hostPath (log "
        "collectors, CSI node plugins). Those should be deployed "
        "with explicit security review and a narrow ``path:``; "
        "this rule fires regardless because *application* workloads "
        "should never use hostPath."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for v in iter_volumes(ps):
            hp = v.get("hostPath")
            if isinstance(hp, dict):
                vol_name = v.get("name", "?")
                offenders.append(f"{m.kind}/{m.name} volume={vol_name}")
                # Land on the ``hostPath:`` block when it carries
                # source-line markers; fall back to the volume entry.
                line = _line_of(hp) or _line_of(v)
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
    passed = not offenders
    desc = (
        "No workload uses hostPath volumes."
        if passed else
        f"{len(offenders)} hostPath volume(s) declared: "
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
