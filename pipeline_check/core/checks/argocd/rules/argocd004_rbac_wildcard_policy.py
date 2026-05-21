"""ARGOCD-004. argocd-rbac-cm grants wildcard authority."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, argocd_rbac_cm

RULE = Rule(
    id="ARGOCD-004",
    title="Argo CD RBAC policy grants wildcard authority",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-2",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-732", "CWE-269"),
    recommendation=(
        "Scope each ``p, <role>, <resource>, <action>, <object>, "
        "allow`` line in ``argocd-rbac-cm`` ``policy.csv`` to a "
        "specific resource / action / object. Replace ``*, *, *, *, "
        "allow`` and ``applications, *, */*, allow`` patterns with "
        "explicit per-project grants (``applications, get, "
        "payments/*, allow``). Restrict ``g, …, role:admin`` "
        "bindings to a single named SSO group."
    ),
    docs_note=(
        "Parses the ``policy.csv`` (and any ``policy.<role>.csv``) "
        "key on ``data:`` in the ``argocd-rbac-cm`` ConfigMap. "
        "Fires on lines tokenizing to ``p, <role>, *, *, *, allow``, "
        "``p, <role>, applications, *, */*, allow``, or "
        "``g, <subject>, role:admin``. Comment lines (``#``) and "
        "explicit denies (``..., deny``) are ignored."
    ),
    exploit_example=(
        "# Vulnerable: the policy.csv embedded in the ConfigMap\n"
        "# grants every authenticated user full admin.\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: { name: argocd-rbac-cm, namespace: argocd }\n"
        "data:\n"
        "  policy.csv: |\n"
        "    p, role:org-admin, *, *, *, allow\n"
        "    g, my-org:everyone, role:org-admin\n"
        "\n"
        "# Safer: explicit per-project, per-action grants.\n"
        "data:\n"
        "  policy.csv: |\n"
        "    p, role:payments-deployer, applications, sync, payments/*, allow\n"
        "    p, role:payments-deployer, applications, get, payments/*, allow\n"
        "    g, my-org:payments-oncall, role:payments-deployer"
    ),
)


def _iter_policy_lines(data: dict[str, Any]) -> list[tuple[str, str]]:
    """Yield ``(key, line)`` for every non-blank, non-comment line in
    every ``policy*.csv`` entry on the ConfigMap's data map."""
    out: list[tuple[str, str]] = []
    for k, v in data.items():
        if not isinstance(k, str) or not k.startswith("policy"):
            continue
        if not k.endswith(".csv"):
            continue
        if not isinstance(v, str):
            continue
        for raw in v.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            out.append((k, line))
    return out


def _tokens(line: str) -> list[str]:
    return [t.strip() for t in line.split(",")]


def check(ctx: ArgoCDContext) -> Finding:
    rbac = argocd_rbac_cm(ctx)
    if rbac is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No argocd-rbac-cm ConfigMap to check.",
            recommendation="No action required.", passed=True,
        )
    data = rbac.data.get("data") or {}
    if not isinstance(data, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="argocd-rbac-cm has no data map.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    for csv_key, line in _iter_policy_lines(data):
        toks = _tokens(line)
        if len(toks) >= 6 and toks[0] == "p" and toks[-1] == "allow":
            resource, action, obj = toks[2], toks[3], toks[4]
            if (resource == "*" and action == "*" and obj == "*") or (
                resource == "applications" and action == "*" and obj == "*/*"
            ):
                offenders.append(f"{csv_key}: wildcard policy '{line}'")
        elif len(toks) >= 3 and toks[0] == "g" and toks[-1] == "role:admin":
            offenders.append(f"{csv_key}: admin role binding '{line}'")
    passed = not offenders
    desc = (
        "No wildcard authority grants in argocd-rbac-cm."
        if passed else
        f"{len(offenders)} wildcard / admin grant(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
