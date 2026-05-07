"""K8S-030 — Workload schedules onto a control-plane node."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    iter_workload_pod_specs,
)

#: Node-role labels that mark a control-plane node. ``master`` is the
#: legacy spelling kept by older clusters; ``control-plane`` is the
#: post-1.24 canonical key.
_CONTROL_PLANE_LABELS: frozenset[str] = frozenset({
    "node-role.kubernetes.io/control-plane",
    "node-role.kubernetes.io/master",
})

#: Workloads in these namespaces may legitimately need to land on the
#: control plane (kube-proxy, calico-node, audit shippers).
_EXEMPT_NAMESPACES: frozenset[str] = frozenset({
    "kube-system",
})


RULE = Rule(
    id="K8S-030",
    title="Workload schedules onto a control-plane node",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-ISOLATION"),
    cwe=("CWE-250",),
    recommendation=(
        "Drop the ``nodeSelector`` and ``tolerations`` entries that "
        "target ``node-role.kubernetes.io/control-plane`` (or the "
        "legacy ``master`` spelling) from non-system workloads. A pod "
        "scheduled on a control-plane node shares the kernel with "
        "the API server, etcd, and kubelet credentials — credential "
        "theft from any such pod yields cluster-wide takeover. "
        "Application workloads belong on dedicated worker nodes; "
        "system add-ons that legitimately need control-plane "
        "scheduling should run as a DaemonSet in ``kube-system``."
    ),
    docs_note=(
        "Fires on a non-system workload whose ``spec.nodeSelector`` "
        "contains a control-plane role label, OR whose "
        "``spec.tolerations`` carries an entry with a control-plane "
        "taint key. Either condition is sufficient to land the pod "
        "on the control plane (the toleration is what survives the "
        "node taint; the nodeSelector picks the node)."
    ),
    known_fp=(
        "Audit/log shippers and CNI agents in kube-system are exempt by "
        "namespace. A workload that legitimately needs to run on the "
        "control plane outside kube-system is rare enough to warrant "
        "an explicit ``.pipelinecheckignore`` rationale.",
    ),
)


def _selector_targets_cp(selector: Any) -> bool:
    if not isinstance(selector, dict):
        return False
    return any(k in _CONTROL_PLANE_LABELS for k in selector)


def _toleration_targets_cp(tolerations: Any) -> bool:
    if not isinstance(tolerations, list):
        return False
    for t in tolerations:
        if not isinstance(t, dict):
            continue
        key = t.get("key")
        if isinstance(key, str) and key in _CONTROL_PLANE_LABELS:
            return True
    return False


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if m.namespace in _EXEMPT_NAMESPACES:
            continue
        hits: list[str] = []
        if _selector_targets_cp(ps.get("nodeSelector")):
            hits.append("nodeSelector")
        if _toleration_targets_cp(ps.get("tolerations")):
            hits.append("tolerations")
        if hits:
            offenders.append(f"{m.kind}/{m.name}: {'+'.join(hits)}")
    passed = not offenders
    desc = (
        "No non-system workload targets the control-plane node role."
        if passed else
        f"{len(offenders)} workload(s) schedule onto the control plane: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
