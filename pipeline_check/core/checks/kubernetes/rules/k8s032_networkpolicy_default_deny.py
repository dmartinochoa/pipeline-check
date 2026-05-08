"""K8S-032 — Namespace lacks a default-deny NetworkPolicy."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-032",
    title="Namespace lacks default-deny NetworkPolicy",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-NETWORK-SEG", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-668",),
    recommendation=(
        "Apply a default-deny NetworkPolicy in every namespace that "
        "carries workloads. The canonical shape is ``podSelector: {}`` "
        "(matches every pod) plus ``policyTypes: [Ingress, Egress]`` "
        "with no ``ingress:`` / ``egress:`` rules — every flow is "
        "denied unless a more permissive NetworkPolicy in the same "
        "namespace explicitly allows it. Pair with per-workload "
        "allow-list policies for the flows the application actually "
        "needs."
    ),
    docs_note=(
        "Kubernetes' default network model is allow-everything: "
        "without any NetworkPolicy targeting a namespace, every pod "
        "can talk to every other pod across every namespace, and "
        "every pod can reach the internet. A default-deny policy "
        "flips the default to deny, so the only flows that work are "
        "those an explicit allow policy permits. The check fires "
        "on namespaces declared in the manifest set that have at "
        "least one workload but no default-deny NetworkPolicy "
        "covering them. Cross-doc correlation: it walks the full "
        "manifest stream to match Namespace/workload/NetworkPolicy "
        "across files."
    ),
    known_fp=(
        "Mesh-managed clusters (Istio, Linkerd, Cilium ClusterMesh) "
        "often delegate L4 default-deny to the mesh's authorization "
        "policy. The check only looks at native NetworkPolicy and "
        "won't see that.",
        "kube-system / kube-public / kube-node-lease are exempt — "
        "control-plane components frequently need open networking "
        "and have their own admission-time guards.",
    ),
)


_EXEMPT_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})

#: Workload kinds that mean "this namespace has pods running in it".
#: Imported from base lazily to avoid circular dependency at module
#: load time. We replicate the small set here rather than re-import
#: ``WORKLOAD_KINDS`` so this rule stays self-contained.
_WORKLOAD_KINDS = frozenset({
    "Pod", "Deployment", "StatefulSet", "DaemonSet",
    "ReplicaSet", "Job", "CronJob",
})


def _is_default_deny(np_data: dict[str, Any]) -> bool:
    """Return True if *np_data* is the canonical default-deny shape.

    Matches a NetworkPolicy whose ``podSelector`` is the empty
    mapping (every pod) and which has neither ``ingress:`` nor
    ``egress:`` rules — or one whose ``policyTypes`` declares Ingress
    / Egress without populating the corresponding rule list. Both
    forms are equivalent in Kubernetes' admission semantics.
    """
    spec = np_data.get("spec")
    if not isinstance(spec, dict):
        return False
    selector = spec.get("podSelector")
    if not isinstance(selector, dict) or selector:
        return False
    ingress = spec.get("ingress")
    egress = spec.get("egress")
    has_ingress_rules = isinstance(ingress, list) and len(ingress) > 0
    has_egress_rules = isinstance(egress, list) and len(egress) > 0
    return not has_ingress_rules and not has_egress_rules


def _namespace_of(m_data: dict[str, Any]) -> str:
    metadata = m_data.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    ns = metadata.get("namespace")
    return ns if isinstance(ns, str) else ""


def check(ctx: KubernetesContext) -> Finding:
    from ..base import Manifest
    declared_namespaces: dict[str, Manifest] = {}
    namespaces_with_workloads: set[str] = set()
    namespaces_with_default_deny: set[str] = set()
    for m in ctx.manifests:
        if m.kind == "Namespace":
            declared_namespaces[m.name] = m
        elif m.kind in _WORKLOAD_KINDS:
            ns = _namespace_of(m.data) or "default"
            namespaces_with_workloads.add(ns)
        elif m.kind == "NetworkPolicy":
            if _is_default_deny(m.data):
                ns = _namespace_of(m.data) or "default"
                namespaces_with_default_deny.add(ns)
    # Fire on namespaces declared (or implied by a workload) that
    # carry workloads but no default-deny NetworkPolicy.
    candidates = (set(declared_namespaces) | namespaces_with_workloads) - _EXEMPT_NAMESPACES
    offenders: list[str] = []
    locations: list[Location] = []
    for ns in sorted(candidates):
        if ns not in namespaces_with_workloads:
            # An empty namespace doesn't need a default-deny — there's
            # nothing in it to deny. Skip.
            continue
        if ns in namespaces_with_default_deny:
            continue
        offenders.append(f"namespace/{ns}")
        ns_manifest = declared_namespaces.get(ns)
        if ns_manifest is not None:
            line = _line_of(ns_manifest.data.get("metadata") or {})
            locations.append(Location(
                path=ns_manifest.path, start_line=line, end_line=line,
                doc_index=ns_manifest.doc_index,
            ))
    passed = not offenders
    desc = (
        "Every namespace with workloads has a default-deny NetworkPolicy."
        if passed else
        f"{len(offenders)} namespace(s) carry workloads but lack a "
        f"default-deny NetworkPolicy: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
