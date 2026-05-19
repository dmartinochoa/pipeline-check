"""K8S-029. RoleBinding subjects include the namespace's ``default`` ServiceAccount."""
from __future__ import annotations

from typing import Any

from ..._primitives.anchors import k8s_sa
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from ..base import KubernetesContext

#: Namespaces whose ``default`` SA legitimately needs grants from
#: bootstrap manifests shipped by the control plane.
_EXEMPT_NAMESPACES: frozenset[str] = frozenset({
    "kube-system",
    "kube-public",
    "kube-node-lease",
})


RULE = Rule(
    id="K8S-029",
    title="RoleBinding grants permissions to the default ServiceAccount",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Bind permissions to a dedicated ServiceAccount, not to "
        "``default``. Every pod that omits ``serviceAccountName`` runs "
        "as the namespace's ``default`` SA, so a binding to it grants "
        "the same verbs to every untargeted pod in that namespace, "
        "including future workloads. Create a purpose-built SA, set "
        "``automountServiceAccountToken: false`` on the default, and "
        "bind to the new SA explicitly."
    ),
    docs_note=(
        "Fires when a ``RoleBinding`` or ``ClusterRoleBinding`` lists "
        "``kind: ServiceAccount, name: default`` among its subjects. "
        "``kube-system``, ``kube-public``, and ``kube-node-lease`` are "
        "exempt because control-plane bootstrap manifests legitimately "
        "grant the default SA there."
    ),
    known_fp=(
        "Charts that intentionally re-use the default SA in single-tenant "
        "namespaces. Consider creating a named SA anyway. It keeps the "
        "audit log unambiguous about which workload made an API call.",
    ),
)


def _subject_targets_default(s: Any) -> tuple[bool, str]:
    if not isinstance(s, dict):
        return False, ""
    if s.get("kind") != "ServiceAccount":
        return False, ""
    if s.get("name") != "default":
        return False, ""
    ns = s.get("namespace")
    return True, ns if isinstance(ns, str) else ""


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    # ResourceAnchor phase 1: emit one k8s_sa anchor per
    # ``(namespace, default)`` pair this binding grants to. AC-021
    # intersects against ARGO-003's workflow-SA anchors (also
    # ``(namespace, default)`` for workflows that omit
    # serviceAccountName), confirming the Argo workflow runs in a
    # namespace whose default SA actually has a binding.
    anchor_set: dict[str, ResourceAnchor] = {}
    for m in ctx.manifests:
        if m.kind not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        subjects = m.data.get("subjects")
        if not isinstance(subjects, list):
            continue
        # For RoleBinding the binding namespace defaults to the binding's
        # own namespace when the subject omits one. ClusterRoleBinding
        # subjects must specify a namespace explicitly.
        binding_ns = m.namespace
        for s in subjects:
            hit, sub_ns = _subject_targets_default(s)
            if not hit:
                continue
            ns = sub_ns or binding_ns
            if ns in _EXEMPT_NAMESPACES:
                continue
            ns_disp = ns or "(no-namespace)"
            offenders.append(
                f"{m.kind}/{m.name} → ServiceAccount/default@{ns_disp}"
            )
            built = k8s_sa(ns if ns else None, "default")
            if built is not None:
                anchor_set[built.identity] = built
    passed = not offenders
    desc = (
        "No RoleBinding grants permissions to a default ServiceAccount."
        if passed else
        f"{len(offenders)} binding(s) target the default SA: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=tuple(anchor_set.values()),
    )
