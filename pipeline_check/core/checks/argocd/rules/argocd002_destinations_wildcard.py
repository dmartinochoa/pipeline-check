"""ARGOCD-002. AppProject permits any destination cluster/namespace."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_appprojects

RULE = Rule(
    id="ARGOCD-002",
    title="Argo CD AppProject permits any destination cluster or namespace",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-862",),
    recommendation=(
        "Replace ``server: '*'`` / ``namespace: '*'`` in "
        "``spec.destinations[]`` with explicit cluster URLs and "
        "namespace lists. A wildcard destination lets any Application "
        "under the project deploy to kube-system on the management "
        "cluster, which converts an Application-create permission "
        "into cluster-admin."
    ),
    docs_note=(
        "Walks ``spec.destinations[]``. Fires when any entry sets "
        "``server`` or ``name`` to ``\"*\"`` or sets ``namespace`` "
        "to ``\"*\"``. Both axes evaluated independently; either "
        "wildcarded fails the check."
    ),
    exploit_example=(
        "# Vulnerable: the project can deploy anywhere on any cluster.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: AppProject\n"
        "metadata: { name: default, namespace: argocd }\n"
        "spec:\n"
        "  sourceRepos:\n"
        "    - https://github.com/example-corp/payments-manifests\n"
        "  destinations:\n"
        "    - { server: '*', namespace: '*' }\n"
        "\n"
        "# Safe: explicit cluster + namespace allowlist.\n"
        "spec:\n"
        "  destinations:\n"
        "    - server: https://kubernetes.default.svc\n"
        "      namespace: payments-prod\n"
        "    - server: https://kubernetes.default.svc\n"
        "      namespace: payments-staging"
    ),
)


def check(ctx: ArgoCDContext) -> Finding:
    offenders: list[str] = []
    projects = list(iter_appprojects(ctx))
    for proj in projects:
        spec = proj.data.get("spec") or {}
        if not isinstance(spec, dict):
            continue
        dests = spec.get("destinations")
        if not isinstance(dests, list):
            continue
        for d in dests:
            if not isinstance(d, dict):
                continue
            server = d.get("server")
            name = d.get("name")
            namespace = d.get("namespace")
            bad = []
            if server == "*" or name == "*":
                bad.append("server '*'")
            if namespace == "*":
                bad.append("namespace '*'")
            if bad:
                offenders.append(
                    f"{proj.display}: destination wildcard ({', '.join(bad)})"
                )
    if not projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No Argo CD AppProject documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every AppProject destination pins a concrete cluster + namespace."
        if passed else
        f"{len(offenders)} wildcard destination(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
