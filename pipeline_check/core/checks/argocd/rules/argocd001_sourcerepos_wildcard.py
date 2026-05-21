"""ARGOCD-001. AppProject permits any source repository."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_appprojects

RULE = Rule(
    id="ARGOCD-001",
    title="Argo CD AppProject permits any source repository",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5", "CICD-SEC-1"),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-862",),
    recommendation=(
        "Replace ``sourceRepos: ['*']`` with the explicit list of "
        "Git remotes the project is allowed to deploy from. A "
        "wildcard means any user who can create an Application "
        "under this project can point it at any repo Argo CD's "
        "service account has credentials for, including private "
        "internal repos with secrets in their manifests."
    ),
    docs_note=(
        "Fires when ``spec.sourceRepos`` contains ``\"*\"`` (case-"
        "sensitive). Also fires when the field is missing or empty, "
        "matching Argo CD's pre-2.5 default-allow behavior."
    ),
    exploit_example=(
        "# Vulnerable: any Application under this project can point\n"
        "# at any repo.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: AppProject\n"
        "metadata: { name: default, namespace: argocd }\n"
        "spec:\n"
        "  sourceRepos: ['*']\n"
        "  destinations: [{ server: '*', namespace: '*' }]\n"
        "\n"
        "# Safe: explicit allowlist of trusted remotes.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: AppProject\n"
        "metadata: { name: payments, namespace: argocd }\n"
        "spec:\n"
        "  sourceRepos:\n"
        "    - https://github.com/example-corp/payments-manifests\n"
        "    - https://github.com/example-corp/payments-charts"
    ),
)


def check(ctx: ArgoCDContext) -> Finding:
    offenders: list[str] = []
    projects = list(iter_appprojects(ctx))
    for proj in projects:
        spec = proj.data.get("spec") or {}
        if not isinstance(spec, dict):
            continue
        repos = spec.get("sourceRepos")
        if not isinstance(repos, list) or not repos:
            offenders.append(f"{proj.display}: sourceRepos missing/empty (default-allow)")
            continue
        if any(r == "*" for r in repos if isinstance(r, str)):
            offenders.append(f"{proj.display}: sourceRepos contains '*'")
    if not projects:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No Argo CD AppProject documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every AppProject restricts sourceRepos to an explicit list."
        if passed else
        f"{len(offenders)} AppProject(s) allow any source repo: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
