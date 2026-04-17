"""IAM-007 — IAM user access keys older than 90 days."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="IAM-007",
    title="IAM user has access key older than 90 days",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate or delete IAM access keys older than 90 days. Long-lived "
        "static credentials are the #1 way compromised CI credentials get "
        "reused across environments — prefer short-lived STS tokens via "
        "OIDC federation or an assumed role."
    ),
    docs_note=(
        "Every user in the account is evaluated — CI/CD tooling that still "
        "uses IAM users (older Jenkins agents, GitHub Actions pre-OIDC, "
        "third-party schedulers) shows up here. The 90-day window matches "
        "the common compliance baseline; rotate sooner if the key is used "
        "from on-prem or an untrusted runner."
    ),
)

_MAX_AGE_DAYS = 90


def check(catalog: ResourceCatalog) -> list[Finding]:
    now = datetime.now(tz=timezone.utc)
    threshold = timedelta(days=_MAX_AGE_DAYS)
    findings: list[Finding] = []
    for user in catalog.iam_users():
        user_name = user.get("UserName", "<unnamed>")
        keys = catalog.access_keys(user_name)
        active = [k for k in keys if k.get("Status") == "Active"]
        if not active:
            continue
        stale: list[tuple[str, int]] = []
        for key in active:
            created = key.get("CreateDate")
            if not hasattr(created, "tzinfo"):
                continue
            age = now - created
            if age > threshold:
                stale.append((key["AccessKeyId"], age.days))
        passed = not stale
        if passed:
            desc = (
                f"User '{user_name}' active access keys are all younger than "
                f"{_MAX_AGE_DAYS} days."
            )
        else:
            detail = ", ".join(f"{kid} ({days}d)" for kid, days in stale)
            desc = (
                f"User '{user_name}' has active access key(s) older than "
                f"{_MAX_AGE_DAYS} days: {detail}."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=user_name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
