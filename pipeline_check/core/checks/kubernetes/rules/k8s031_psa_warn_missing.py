"""K8S-031. Namespace missing the PSA ``warn`` label."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-031",
    title="Namespace missing PSA warn label",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``metadata.labels.pod-security.kubernetes.io/warn`` on "
        "every Namespace, ideally one tier ahead of the enforce label "
        "(e.g. ``enforce: baseline`` + ``warn: restricted``). The warn "
        "level surfaces violations as ``kubectl apply`` warnings "
        "without rejecting the resource, developers see what would "
        "break before an enforcement upgrade lands."
    ),
    docs_note=(
        "Pod Security Admission supports three modes: ``enforce`` "
        "(reject), ``audit`` (log to API audit), and ``warn`` (return "
        "a kubectl warning). K8S-023 covers ``enforce``; this rule "
        "covers ``warn``. The convention from upstream PSA docs is to "
        "set ``warn`` to the next-strictest tier above your current "
        "``enforce`` so an upgrade from baseline to restricted is a "
        "predictable rollout, not a surprise."
    ),
    known_fp=(
        "Single-tenant clusters may set ``warn`` and ``audit`` "
        "globally via the AdmissionConfiguration ``defaults:`` block "
        "instead of per-namespace labels. The label-based check "
        "can't see that.",
    ),
)


_PSA_WARN_KEY = "pod-security.kubernetes.io/warn"
_EXEMPT_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})


def _labels(m_data: dict[str, Any]) -> dict[str, Any]:
    metadata = m_data.get("metadata")
    if not isinstance(metadata, dict):
        return {}
    labels = metadata.get("labels")
    return labels if isinstance(labels, dict) else {}


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "Namespace":
            continue
        if m.name in _EXEMPT_NAMESPACES:
            continue
        labels = _labels(m.data)
        warn = labels.get(_PSA_WARN_KEY)
        if not isinstance(warn, str) or not warn.strip():
            offenders.append(f"Namespace/{m.name}")
            line = _line_of(labels) or _line_of(m.data.get("metadata") or {})
            locations.append(Location(
                path=m.path, start_line=line, end_line=line,
                doc_index=m.doc_index,
            ))
    passed = not offenders
    desc = (
        "Every Namespace declares a Pod Security Admission warn level."
        if passed else
        f"{len(offenders)} Namespace(s) lack a PSA warn label: "
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
