"""SM-002 — Secrets Manager resource policy allows a wildcard principal."""
from __future__ import annotations

from ..._iam_policy import iter_allow, public_principal
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SM-002",
    title="Secrets Manager resource policy allows wildcard principal",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove Allow statements whose Principal is ``*`` from every "
        "Secrets Manager resource policy, or scope them with a ``Condition`` "
        "restricting the source account/org (``aws:PrincipalOrgID``). A "
        "wildcard-principal policy allows any AWS account to call "
        "``GetSecretValue`` on the secret."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for secret in catalog.secrets():
        name = secret.get("Name", "<unnamed>")
        arn = secret.get("ARN", "")
        policy = catalog.secret_resource_policy(arn or name)
        if policy is None:
            continue
        offenders = [
            idx for idx, stmt in enumerate(iter_allow(policy))
            if public_principal(stmt)
        ]
        passed = not offenders
        if passed:
            desc = f"Resource policy on '{name}' has no wildcard-principal Allow."
        else:
            desc = (
                f"Resource policy on '{name}' has Allow statement(s) at "
                f"indexes {offenders} granting access to Principal: '*'. "
                "Any AWS account can call GetSecretValue."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
