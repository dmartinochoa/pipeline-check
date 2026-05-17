"""K8S-042. RoleBinding / ClusterRoleBinding grants access to unauthenticated callers."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

#: Subjects that resolve to unauthenticated requests. Granting RBAC
#: to any of these is equivalent to making the bound permissions
#: world-readable / world-writable across the apiserver.
_ANONYMOUS_SUBJECTS: frozenset[str] = frozenset({
    "system:anonymous",
    "system:unauthenticated",
})

RULE = Rule(
    id="K8S-042",
    title="RoleBinding grants access to system:anonymous / system:unauthenticated",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-862",),
    recommendation=(
        "Remove the binding's subject entry for ``system:anonymous`` "
        "or ``system:unauthenticated``. Anything bound to either "
        "subject is reachable without an authentication token, "
        "anyone who can hit the apiserver, including from inside an "
        "untrusted pod or from the public internet on an exposed "
        "apiserver, gets the bound verbs. If the workload genuinely "
        "needs unauthenticated read access (rare, usually only for "
        "OIDC discovery or the deprecated "
        "``system:public-info-viewer`` shape), audit the bound "
        "ClusterRole's verbs+resources and confirm no write or "
        "secret-read verb is included."
    ),
    docs_note=(
        "Kubernetes resolves authentication failures into the "
        "``system:anonymous`` user (member of "
        "``system:unauthenticated`` group) rather than rejecting the "
        "request outright, so any RBAC subject naming either of "
        "those values applies to requests with no Authorization "
        "header. The rule fires on both ``RoleBinding`` (namespace-"
        "scoped) and ``ClusterRoleBinding`` (cluster-scoped) "
        "subjects. Pairs with K8S-020: cluster-admin bound to a "
        "named SA is bad; cluster-admin bound to ``system:anonymous`` "
        "is cluster takeover by anyone with TCP/443 to the "
        "apiserver."
    ),
)


def _flag(subject: Any) -> str | None:
    if not isinstance(subject, dict):
        return None
    name = subject.get("name")
    kind = subject.get("kind")
    if not isinstance(name, str) or name not in _ANONYMOUS_SUBJECTS:
        return None
    return f"{kind or '?'}/{name}"


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        subjects = m.data.get("subjects")
        if not isinstance(subjects, list):
            continue
        hits: list[str] = []
        for s in subjects:
            tag = _flag(s)
            if tag is not None:
                hits.append(tag)
        if not hits:
            continue
        role_ref = m.data.get("roleRef")
        role_name = (
            role_ref.get("name") if isinstance(role_ref, dict) else "?"
        )
        offenders.append(
            f"{m.kind}/{m.name} → {role_name} [{', '.join(hits)}]"
        )
        line = _line_of(subjects)
        locations.append(Location(
            path=m.path, start_line=line, end_line=line,
            doc_index=m.doc_index,
        ))
    passed = not offenders
    desc = (
        "No RoleBinding / ClusterRoleBinding grants access to "
        "system:anonymous or system:unauthenticated."
        if passed else
        f"{len(offenders)} binding(s) grant access to unauthenticated "
        f"callers: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Anything bound here is "
        f"reachable without an apiserver auth token."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
