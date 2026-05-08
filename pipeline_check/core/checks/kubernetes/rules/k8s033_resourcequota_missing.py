"""K8S-033 — Namespace lacks ResourceQuota or LimitRange."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-033",
    title="Namespace lacks ResourceQuota or LimitRange",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-BUILD-ENV"),
    cwe=("CWE-770",),
    recommendation=(
        "Apply a ``ResourceQuota`` *and* a ``LimitRange`` to every "
        "namespace that hosts application workloads. ResourceQuota "
        "caps the namespace's total CPU / memory / pod / object "
        "consumption; LimitRange enforces per-pod request / limit "
        "defaults so a workload that forgets to declare its own "
        "doesn't get unbounded scheduling. Together they bound the "
        "blast radius of a runaway, leaky, or attacker-driven pod "
        "explosion to a single namespace."
    ),
    docs_note=(
        "Without a ResourceQuota, a single namespace can consume "
        "the cluster's entire scheduling capacity — a fork bomb in "
        "a CronJob, a memory leak in a Deployment, or a "
        "cryptominer that landed via a fork-PR build can starve "
        "every other tenant. Without a LimitRange, individual pods "
        "without explicit ``resources:`` requests get a default of "
        "zero — the scheduler treats them as best-effort and packs "
        "them on any node, including ones already at memory "
        "pressure. The two work together: quota caps the "
        "aggregate, range caps the per-workload baseline. Cross-doc "
        "correlation: walks the manifest stream to match Namespace "
        "/ workload / ResourceQuota / LimitRange across files."
    ),
)


_EXEMPT_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})

_WORKLOAD_KINDS = frozenset({
    "Pod", "Deployment", "StatefulSet", "DaemonSet",
    "ReplicaSet", "Job", "CronJob",
})


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
    namespaces_with_quota: set[str] = set()
    namespaces_with_limit_range: set[str] = set()
    for m in ctx.manifests:
        if m.kind == "Namespace":
            declared_namespaces[m.name] = m
        elif m.kind in _WORKLOAD_KINDS:
            ns = _namespace_of(m.data) or "default"
            namespaces_with_workloads.add(ns)
        elif m.kind == "ResourceQuota":
            ns = _namespace_of(m.data) or "default"
            namespaces_with_quota.add(ns)
        elif m.kind == "LimitRange":
            ns = _namespace_of(m.data) or "default"
            namespaces_with_limit_range.add(ns)
    candidates = (set(declared_namespaces) | namespaces_with_workloads) - _EXEMPT_NAMESPACES
    offenders: list[str] = []
    locations: list[Location] = []
    for ns in sorted(candidates):
        if ns not in namespaces_with_workloads:
            continue
        missing: list[str] = []
        if ns not in namespaces_with_quota:
            missing.append("ResourceQuota")
        if ns not in namespaces_with_limit_range:
            missing.append("LimitRange")
        if missing:
            offenders.append(f"namespace/{ns} (missing: {', '.join(missing)})")
            ns_manifest = declared_namespaces.get(ns)
            if ns_manifest is not None:
                line = _line_of(ns_manifest.data.get("metadata") or {})
                locations.append(Location(
                    path=ns_manifest.path, start_line=line, end_line=line,
                    doc_index=ns_manifest.doc_index,
                ))
    passed = not offenders
    desc = (
        "Every namespace with workloads has both ResourceQuota and "
        "LimitRange."
        if passed else
        f"{len(offenders)} namespace(s) lack ResourceQuota / "
        f"LimitRange: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
