"""ARGOCD-009. argocd-cm enables anonymous access."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, argocd_cm

RULE = Rule(
    id="ARGOCD-009",
    title="Argo CD anonymous access enabled",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-306",),
    recommendation=(
        "Remove the ``users.anonymous.enabled: \"true\"`` entry from "
        "``argocd-cm`` (or set it to ``\"false\"``). With anonymous "
        "access on, the Argo CD UI / API answers requests carrying "
        "no token, and whatever permissions ``role:readonly`` (or "
        "the default policy) grants are reachable without "
        "authentication."
    ),
    docs_note=(
        "Reads ``data.users.anonymous.enabled`` on the "
        "``argocd-cm`` ConfigMap. ConfigMap data values are always "
        "stringified by Kubernetes, but the YAML loader can hand us "
        "either ``\"true\"`` or boolean ``true`` depending on how "
        "the manifest was written, so both forms fail the check."
    ),
    exploit_example=(
        "# Vulnerable: anyone on the network reaching the Argo CD\n"
        "# API server gets ``role:readonly`` (or whatever default\n"
        "# policy.default grants).\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: { name: argocd-cm, namespace: argocd }\n"
        "data:\n"
        "  users.anonymous.enabled: \"true\"\n"
        "\n"
        "# Safe: drop the key entirely (the default is off) or set\n"
        "# false explicitly.\n"
        "data:\n"
        "  users.anonymous.enabled: \"false\""
    ),
)


_TRUTHY = {"true", "True", "TRUE", "yes", "1"}


def _is_truthy(v: object) -> bool:
    if v is True:
        return True
    if isinstance(v, str) and v.strip() in _TRUTHY:
        return True
    return False


def check(ctx: ArgoCDContext) -> Finding:
    cm = argocd_cm(ctx)
    if cm is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No argocd-cm ConfigMap to check.",
            recommendation="No action required.", passed=True,
        )
    data = cm.data.get("data") or {}
    if not isinstance(data, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="argocd-cm has no data map.",
            recommendation="No action required.", passed=True,
        )
    if _is_truthy(data.get("users.anonymous.enabled")):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="argocd-cm sets users.anonymous.enabled to a truthy value.",
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd",
        description="Anonymous access is disabled.",
        recommendation=RULE.recommendation, passed=True,
    )
