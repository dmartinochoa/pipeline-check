"""K8S-019. Workload deployed in the ``default`` namespace."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext, is_workload, manifest_location

RULE = Rule(
    id="K8S-019",
    title="Workload deployed in the 'default' namespace",
    severity=Severity.LOW,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``metadata.namespace`` to a dedicated namespace per "
        "workload (or per environment). The ``default`` namespace "
        "tends to accumulate cluster-wide RoleBindings, "
        "NetworkPolicies, and operators that grant broader access "
        "than intended; placing application workloads there means "
        "every privilege grant in default applies to them. A "
        "purpose-built namespace also lets you enforce Pod Security "
        "Standards (``pod-security.kubernetes.io/enforce`` label) "
        "scoped to that workload."
    ),
    docs_note=(
        "Severity is LOW because in a well-curated cluster the "
        "default namespace is empty by policy. If your cluster "
        "treats default as a sandbox you can suppress this rule "
        "via ``.pipelinecheckignore``."
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if not is_workload(m):
            continue
        ns = m.namespace or ""
        if ns == "" or ns == "default":
            offenders.append(f"{m.kind}/{m.name}")
            locations.append(manifest_location(m, m.data))
    passed = not offenders
    desc = (
        "No workload is deployed in the default namespace."
        if passed else
        f"{len(offenders)} workload(s) live in the default namespace: "
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
