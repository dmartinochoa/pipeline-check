"""GCIAM-002. Service account has user-managed key."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCIAM-002",
    title="Service account has user-managed key",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-321",),
    recommendation=(
        "Delete user-managed keys and use workload identity "
        "federation, attached service accounts, or the metadata "
        "server instead. User-managed keys are long-lived credentials "
        "that cannot be automatically rotated by GCP."
    ),
    docs_note=(
        "User-managed service account keys are JSON files that act "
        "as permanent credentials. They don't expire by default, "
        "can be downloaded by anyone with the right IAM role, and "
        "are the most common GCP credential found in public leaks."
    ),
    exploit_example=(
        "A developer commits a service account key JSON file to a "
        "public repository. Automated scanners pick it up within "
        "minutes and use it to access the project's resources."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for sa in catalog.service_accounts():
        email = sa.get("email", "<unknown>")
        if sa.get("disabled"):
            continue
        keys = catalog.service_account_keys(email)
        user_keys = [
            k for k in keys
            if k.get("key_type") == "USER_MANAGED"
        ]
        if user_keys:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=email,
                description=(
                    f"Service account {email} has "
                    f"{len(user_keys)} user-managed key(s). "
                    "User-managed keys are long-lived and "
                    "cannot be automatically rotated."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=email,
                description=(
                    f"Service account {email} has no user-managed keys."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
