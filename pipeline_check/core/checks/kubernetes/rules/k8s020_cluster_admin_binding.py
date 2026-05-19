"""K8S-020. ClusterRoleBinding grants ``cluster-admin`` or ``system:masters``."""
from __future__ import annotations

from typing import Any

from ..._primitives.anchors import k8s_sa
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, ResourceAnchor, Severity
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
        "to giving every pod that uses it root on every node, "
        "credential theft from any such pod becomes immediate "
        "cluster takeover. Audit-log every existing cluster-admin "
        "binding and replace each with the minimum verbs/resources "
        "the consumer actually needs."
    ),
    docs_note=(
        "The rule fires on a ``ClusterRoleBinding`` whose "
        "``roleRef.name`` is ``cluster-admin``, ``admin``, or "
        "``system:masters``. Subject type does not matter, even "
        "binding cluster-admin to a Group is a cluster-takeover "
        "risk."
    ),
    incident_refs=(
        "[Tesla Kubernetes dashboard compromise](https://redlock.io/cloud-security-trends-october-2018) "
        "(RedLock, 2018): an unauthenticated Kubernetes dashboard "
        "exposed to the internet held tokens for service accounts "
        "bound to cluster-admin. Attackers used the dashboard "
        "credentials to deploy crypto-mining workloads with full "
        "cluster access. Least-privilege RBAC would have capped "
        "the blast radius even after dashboard exposure.",
        "Argo CD [CVE-2022-24348](https://www.cve.org/CVERecord?id=CVE-2022-24348) "
        "(2022): a Helm path-traversal bug let a project member read "
        "other applications' YAML, exposing credentials. Combined "
        "with the default cluster-admin RBAC install, the recovered "
        "tokens were a direct cluster takeover. Argo's recommendation "
        "post-fix was to scope the controller's RBAC away from "
        "cluster-admin so a similar future bug couldn't escalate "
        "the same way.",
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
    locations: list[Location] = []
    # ResourceAnchor phase 1: emit one k8s_sa anchor per
    # cluster-admin binding's ServiceAccount subject. AC-011
    # intersects this with K8S-013's pod-SA anchors and AC-020
    # intersects with TKN-004's Task-SA anchors so the chain only
    # confirms when the host-escape primitive runs as the SA that
    # has cluster-admin. Group / User subjects don't map to k8s_sa
    # — they're a different identity kind and not in scope for
    # phase 1.
    anchor_set: dict[str, ResourceAnchor] = {}
    for m in ctx.manifests:
        if m.kind != "ClusterRoleBinding":
            continue
        roleref = m.data.get("roleRef")
        if not _admin_role(roleref):
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
        # Anchor on the roleRef block, that's where the offending
        # cluster-admin name lives. Falls back to the manifest's
        # top line when the loader didn't preserve nested marks.
        line = _line_of(roleref) if isinstance(roleref, dict) else None
        locations.append(Location(
            path=m.path, start_line=line, end_line=line,
            doc_index=m.doc_index,
        ))
        if isinstance(subjects, list):
            for s in subjects:
                if not isinstance(s, dict):
                    continue
                if s.get("kind") != "ServiceAccount":
                    continue
                sub_name = s.get("name")
                sub_ns = s.get("namespace")
                if not isinstance(sub_name, str):
                    continue
                built = k8s_sa(
                    sub_ns if isinstance(sub_ns, str) else None,
                    sub_name,
                )
                if built is not None:
                    anchor_set[built.identity] = built
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
        locations=locations,
        resource_anchors=tuple(anchor_set.values()),
    )
