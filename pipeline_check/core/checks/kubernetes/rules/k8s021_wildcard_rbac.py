"""K8S-021. Role/ClusterRole grants wildcard verbs+resources."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-021",
    title="Role or ClusterRole grants wildcard verbs+resources",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-5"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Replace ``verbs: [\"*\"]`` and ``resources: [\"*\"]`` with "
        "explicit lists. Wildcards bypass the principle of least "
        "privilege: today they grant `read pods` and tomorrow they "
        "grant `delete crds` because a new resource was registered "
        "in that apiGroup. Explicit verbs (``get``, ``list``, "
        "``watch``) and explicit resources (``configmaps``, "
        "``services``) keep grants stable across cluster upgrades."
    ),
    docs_note=(
        "Fires on any rule entry where BOTH ``verbs`` and "
        "``resources`` contain a literal ``\"*\"``. A wildcard in "
        "only one of the two is still risky but is often a "
        "legitimate read-everything pattern (e.g. monitoring); "
        "this rule targets the strict superset 'do anything to "
        "everything'."
    ),
    exploit_example=(
        "# Vulnerable: a Role / ClusterRole that grants verbs:\n"
        "# [\"*\"] on resources: [\"*\"]. Equivalent to admin on\n"
        "# the scope (namespace for Role, cluster for\n"
        "# ClusterRole). Any compromise of a subject bound to\n"
        "# this role becomes admin.\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata: { name: do-everything }\n"
        "rules:\n"
        "  - apiGroups: [\"*\"]\n"
        "    resources: [\"*\"]\n"
        "    verbs: [\"*\"]\n"
        "\n"
        "# Safe: enumerate the verbs + resources the workload\n"
        "# actually needs. New requirements force a Role review.\n"
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: Role\n"
        "metadata:\n"
        "  name: app-pod-reader\n"
        "  namespace: app\n"
        "rules:\n"
        "  - apiGroups: [\"\"]\n"
        "    resources: [\"pods\", \"pods/log\"]\n"
        "    verbs: [\"get\", \"list\", \"watch\"]"
    ),
)


def _has_wildcard(items: Any) -> bool:
    return isinstance(items, list) and any(
        x == "*" for x in items if isinstance(x, str)
    )


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind not in ("Role", "ClusterRole"):
            continue
        rules = m.data.get("rules")
        if not isinstance(rules, list):
            continue
        for idx, r in enumerate(rules):
            if not isinstance(r, dict):
                continue
            if _has_wildcard(r.get("verbs")) and _has_wildcard(r.get("resources")):
                offenders.append(f"{m.kind}/{m.name} rules[{idx}]")
                # Anchor on the offending rule entry, that's the
                # specific verbs+resources pair the user needs to
                # narrow.
                line = _line_of(r)
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
    passed = not offenders
    desc = (
        "No Role / ClusterRole grants wildcard verbs+resources."
        if passed else
        f"{len(offenders)} rule entr(ies) grant '*' on '*': "
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
