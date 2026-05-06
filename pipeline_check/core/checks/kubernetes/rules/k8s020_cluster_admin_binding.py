"""K8S-020 — ClusterRoleBinding grants ``cluster-admin`` or ``system:masters``."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext

#: Built-in role refs that confer full cluster control.
_ADMIN_ROLES: frozenset[str] = frozenset({
    "cluster-admin",
    "admin",
    "system:masters",
})

RULE = Rule(
    id="K8S-020",
    title="ClusterRoleBinding grants cluster-admin or system:masters",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Replace cluster-admin / system:masters bindings with "
        "narrowly-scoped ClusterRoles or namespace-scoped Roles. "
        "Granting cluster-admin to a service account is equivalent "
        "to giving every pod that uses it root on every node — "
        "credential theft from any such pod becomes immediate "
        "cluster takeover. Audit-log every existing cluster-admin "
        "binding and replace each with the minimum verbs/resources "
        "the consumer actually needs."
    ),
    docs_note=(
        "The rule fires on a ``ClusterRoleBinding`` whose "
        "``roleRef.name`` is ``cluster-admin``, ``admin``, or "
        "``system:masters``. Subject type does not matter — even "
        "binding cluster-admin to a Group is a cluster-takeover "
        "risk."
    ),
)


def _admin_role(roleref: Any) -> bool:
    if not isinstance(roleref, dict):
        return False
    return roleref.get("name") in _ADMIN_ROLES


def _subject_str(s: Any) -> str:
    if not isinstance(s, dict):
        return "?"
    kind = s.get("kind", "?")
    name = s.get("name", "?")
    ns = s.get("namespace")
    return f"{kind}/{name}" + (f"@{ns}" if isinstance(ns, str) and ns else "")


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m in ctx.manifests:
        if m.kind != "ClusterRoleBinding":
            continue
        if not _admin_role(m.data.get("roleRef")):
            continue
        roleref_name = m.data.get("roleRef", {}).get("name")
        subjects = m.data.get("subjects")
        subjects_disp = (
            ", ".join(_subject_str(s) for s in subjects[:3])
            if isinstance(subjects, list) and subjects
            else "(no subjects)"
        )
        offenders.append(
            f"ClusterRoleBinding/{m.name} → {roleref_name} "
            f"[{subjects_disp}]"
        )
    passed = not offenders
    desc = (
        "No ClusterRoleBinding grants cluster-admin or system:masters."
        if passed else
        f"{len(offenders)} binding(s) confer full cluster control: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
