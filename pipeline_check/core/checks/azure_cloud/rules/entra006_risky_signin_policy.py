"""ENTRA-006. No Conditional Access sign-in risk policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ENTRA-006",
    title="No Conditional Access sign-in risk policy",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-308",),
    recommendation=(
        "Create a Conditional Access policy that evaluates sign-in "
        "risk. For medium and high risk levels, require MFA or block "
        "the sign-in. This uses Entra ID Protection signals to detect "
        "anomalous logins."
    ),
    docs_note=(
        "Sign-in risk policies use machine-learning signals (unfamiliar "
        "location, impossible travel, anonymous IP) to detect "
        "credential compromise in real time. Without a risk-based "
        "policy, these signals are generated but never acted on."
    ),
    exploit_example=(
        "An attacker logs in from an anonymous VPN with stolen "
        "credentials. Entra ID Protection flags the sign-in as high "
        "risk, but without a Conditional Access policy the session "
        "proceeds unchallenged."
    ),
)

_RISK_LEVELS = {"low", "medium", "high"}


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    policies = catalog.conditional_access_policies()
    resource = "Entra ID Conditional Access"

    has_risk_policy = False
    for policy in policies:
        state = policy.get("state", "")
        if state != "enabled":
            continue
        conditions = policy.get("conditions") or {}
        sign_in_risk = conditions.get("signInRiskLevels") or []
        if any(
            isinstance(level, str) and level.lower() in _RISK_LEVELS
            for level in sign_in_risk
        ):
            has_risk_policy = True
            break

    if has_risk_policy:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "At least one enabled Conditional Access policy "
                "evaluates sign-in risk levels."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        ))
    else:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "No enabled Conditional Access policy evaluates sign-in "
                "risk. Anomalous sign-in signals from Entra ID "
                "Protection are not enforced."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
