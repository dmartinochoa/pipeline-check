"""ARGOCD-014. argocd-cm enables the web terminal via exec.enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, argocd_cm

RULE = Rule(
    id="ARGOCD-014",
    title="Argo CD web terminal enabled via exec.enabled",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-284", "CWE-668"),
    recommendation=(
        "Set ``exec.enabled`` to ``\"false\"`` in ``argocd-cm`` (or "
        "drop the key, since the terminal is off by default). If a "
        "terminal is genuinely needed for break-glass debugging, "
        "gate it behind a narrowly scoped ``exec`` RBAC role bound to "
        "a single named group, and audit every session. The web "
        "terminal opens an interactive shell into any managed pod, so "
        "it sits at the top of the blast-radius ladder."
    ),
    docs_note=(
        "Reads ``data.exec.enabled`` on the ``argocd-cm`` ConfigMap. "
        "ConfigMap data values are always stringified by Kubernetes, "
        "but the YAML loader can hand us either ``\"true\"`` or "
        "boolean ``true`` depending on how the manifest was written, "
        "so both forms fail the check. The terminal also needs the "
        "``exec`` RBAC verb; this rule fires on the global toggle "
        "regardless of the RBAC scope."
    ),
    known_fp=(
        "Platform teams that restrict the ``exec`` RBAC verb to a "
        "small break-glass role sometimes accept the terminal being "
        "enabled. The rule still fires; confirm the RBAC scope (see "
        "ARGOCD-004) before treating it as benign, and suppress per "
        "instance with a rationale naming the scoped role.",
    ),
    exploit_example=(
        "# Vulnerable: the web terminal is on, and a permissive\n"
        "# default policy hands the exec verb to every user.\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: { name: argocd-cm, namespace: argocd }\n"
        "data:\n"
        "  exec.enabled: \"true\"\n"
        "\n"
        "# Attack: a logged-in user opens a terminal into a running\n"
        "# pod from the UI, reads the pod's mounted service-account\n"
        "# token at /var/run/secrets/kubernetes.io/serviceaccount,\n"
        "# and pivots to the Kubernetes API with that identity.\n"
        "\n"
        "# Safe: drop the key (default off) or set it false.\n"
        "data:\n"
        "  exec.enabled: \"false\""
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
    if _is_truthy(data.get("exec.enabled")):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description=(
                "argocd-cm sets exec.enabled to a truthy value, "
                "opening the web terminal into managed pods."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd",
        description="The web terminal is disabled.",
        recommendation=RULE.recommendation, passed=True,
    )
