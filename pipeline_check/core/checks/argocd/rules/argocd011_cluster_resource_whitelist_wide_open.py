"""ARGOCD-011. AppProject cluster-resource whitelist is wide open."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_appprojects

RULE = Rule(
    id="ARGOCD-011",
    title="Argo CD AppProject cluster-resource whitelist is wide open",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-5"),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-862", "CWE-269"),
    recommendation=(
        "Restrict ``spec.clusterResourceWhitelist`` to the exact "
        "(group, kind) tuples the project's Applications need. The "
        "default (an empty list) blocks all cluster-scoped writes, "
        "which is the safest posture for namespace-scoped workloads. "
        "A wildcard (``{group: '*', kind: '*'}``) allows the project "
        "to install ClusterRoleBindings, CustomResourceDefinitions, "
        "ValidatingAdmissionWebhooks, and PodSecurityPolicies — every "
        "category capable of cluster takeover.\n\n"
        "Typical narrow allowlist for a workload project:\n\n"
        "    spec:\n"
        "      clusterResourceWhitelist: []\n"
        "      namespaceResourceWhitelist:\n"
        "        - { group: '', kind: ConfigMap }\n"
        "        - { group: '', kind: Service }\n"
        "        - { group: apps, kind: Deployment }\n\n"
        "Projects that legitimately install cluster-scoped resources "
        "(an operator project, a CRD-management project) should "
        "enumerate the specific kinds, never wildcards."
    ),
    docs_note=(
        "Reads ``spec.clusterResourceWhitelist`` from each AppProject "
        "and fires when the list contains an entry with "
        "``{group: '*', kind: '*'}`` (the explicit wildcard). The "
        "empty-list default passes the rule (it blocks all "
        "cluster-scoped writes). Partially-wildcarded entries "
        "(``{group: '*', kind: ClusterRole}`` or "
        "``{group: rbac.authorization.k8s.io, kind: '*'}``) also "
        "trip the rule because either axis being a wildcard means "
        "the other axis can't bound the blast radius.\n\n"
        "Pairs with ARGOCD-002 (destinations wildcard, which "
        "controls *where* an Application can deploy). This rule "
        "controls *what kinds* it can deploy."
    ),
    known_fp=(
        "Operator-installation projects that legitimately need "
        "broad cluster-resource creation rights (the only way "
        "to install some operators is via CRD + ClusterRole + "
        "ClusterRoleBinding). Suppress per project with a one-line "
        "rationale naming the operator and the install procedure "
        "that requires the broad rights.",
    ),
    incident_refs=(
        "Common over-provisioning pattern: a contributor adds "
        "``clusterResourceWhitelist: [{group: '*', kind: '*'}]`` to "
        "an AppProject during an operator install, never tightens "
        "it back. Months later, an Application under that project "
        "is deployed with a malicious ClusterRoleBinding (via "
        "a compromised git commit or a typo in a values file); "
        "the binding lands without any AppProject-side gate.",
    ),
    exploit_example=(
        "# Vulnerable: project allows any cluster-scoped kind.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: AppProject\n"
        "metadata: { name: workloads, namespace: argocd }\n"
        "spec:\n"
        "  sourceRepos: [https://github.com/example/manifests]\n"
        "  destinations: [{ server: https://kubernetes.default.svc, namespace: '*' }]\n"
        "  clusterResourceWhitelist:\n"
        "    - { group: '*', kind: '*' }\n"
        "\n"
        "# Attack: a malicious manifest in the source repo declares\n"
        "# a ClusterRoleBinding granting cluster-admin to the\n"
        "# attacker's ServiceAccount. The AppProject's wide-open\n"
        "# whitelist allows the binding through; Argo CD applies it;\n"
        "# the attacker now has cluster-admin everywhere the\n"
        "# binding's subjects can reach.\n"
        "\n"
        "# Safe: explicit allowlist.\n"
        "spec:\n"
        "  clusterResourceWhitelist: []   # blocks all cluster writes\n"
        "  namespaceResourceWhitelist:\n"
        "    - { group: '', kind: ConfigMap }\n"
        "    - { group: '', kind: Service }\n"
        "    - { group: apps, kind: Deployment }"
    ),
)


def _is_wildcard_entry(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    group = entry.get("group")
    kind = entry.get("kind")
    if not isinstance(group, str) or not isinstance(kind, str):
        return False
    return group == "*" or kind == "*"


def check(ctx: ArgoCDContext) -> Finding:
    projects = list(iter_appprojects(ctx))
    if not projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no AppProjects)",
            description=(
                "No AppProject documents in scope; nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for proj in projects:
        spec = proj.data.get("spec")
        if not isinstance(spec, dict):
            continue
        whitelist = spec.get("clusterResourceWhitelist")
        if not isinstance(whitelist, list) or not whitelist:
            continue  # Empty / unset = safe (blocks all cluster writes)
        for entry in whitelist:
            if _is_wildcard_entry(entry):
                grp = entry.get("group", "")
                knd = entry.get("kind", "")
                offenders.append(
                    f"{proj.display}: clusterResourceWhitelist "
                    f"includes {{group: {grp!r}, kind: {knd!r}}}"
                )
                break
    passed = not offenders
    desc = (
        "Every AppProject's clusterResourceWhitelist either omits "
        "wildcards or is empty (default-deny)."
        if passed else
        f"{len(offenders)} AppProject(s) wildcard cluster "
        f"resources: {'; '.join(offenders[:3])}"
        f"{' …' if len(offenders) > 3 else ''}. Any Application "
        f"under the project can install ClusterRoleBindings, "
        f"CRDs, webhooks, etc."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=projects[0].display,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
