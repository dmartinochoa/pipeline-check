"""K8S-023 — Namespace missing Pod Security Admission enforcement label."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-023",
    title="Namespace missing Pod Security Admission enforcement label",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-NETWORK-SEG"),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``metadata.labels.pod-security.kubernetes.io/enforce`` "
        "to ``baseline`` or ``restricted`` on every Namespace. "
        "Without an enforce label the namespace runs the cluster's "
        "default policy, which on most installations is ``privileged`` "
        "and silently admits pods that violate every K8S-002..010 rule."
    ),
    docs_note=(
        "Pod Security Admission (PSA) replaced the deprecated "
        "PodSecurityPolicy in 1.25. The three levels are ``privileged``, "
        "``baseline``, and ``restricted``; ``baseline`` is a sensible "
        "production default and ``restricted`` matches the spirit of "
        "K8S-005..010. ``kube-system`` is exempt by convention since "
        "control-plane pods may legitimately need elevated permissions."
    ),
    known_fp=(
        "Single-tenant clusters running only operator-managed workloads "
        "may apply PSA via an admission webhook instead. The label-based "
        "check can't see that.",
    ),
)


_PSA_KEY = "pod-security.kubernetes.io/enforce"
_EXEMPT_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})


def _labels(m_data: dict[str, Any]) -> dict[str, Any]:
    metadata = m_data.get("metadata")
    if not isinstance(metadata, dict):
        return {}
    labels = metadata.get("labels")
    return labels if isinstance(labels, dict) else {}


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m in ctx.manifests:
        if m.kind != "Namespace":
            continue
        if m.name in _EXEMPT_NAMESPACES:
            continue
        labels = _labels(m.data)
        level = labels.get(_PSA_KEY)
        if not isinstance(level, str) or level == "privileged":
            offenders.append(f"Namespace/{m.name}")
    passed = not offenders
    desc = (
        "Every Namespace declares a Pod Security Admission "
        "enforce level of baseline or restricted."
        if passed else
        f"{len(offenders)} Namespace(s) lack a baseline/restricted "
        f"PSA enforce label: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
