"""GCIAM-006. Service account key older than 90 days."""
from __future__ import annotations

from datetime import UTC, datetime

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCIAM-006",
    title="Service account key older than 90 days",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-324",),
    recommendation=(
        "Rotate or delete user-managed service account keys older than "
        "90 days. Prefer workload identity federation to eliminate "
        "long-lived keys entirely."
    ),
    docs_note=(
        "Long-lived service account keys increase the blast radius of "
        "a credential leak. CIS GCP Foundations recommends rotating "
        "user-managed keys at most every 90 days."
    ),
    exploit_example=(
        "A service account key leaked in a CI log 6 months ago is "
        "still valid. An attacker uses it to authenticate and "
        "exfiltrate data because the key was never rotated."
    ),
)

_MAX_AGE_DAYS = 90


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(tz=UTC)
    for sa in catalog.service_accounts():
        email = sa.get("email", "<unknown>")
        if sa.get("disabled"):
            continue
        keys = catalog.service_account_keys(email)
        for key in keys:
            if key.get("key_type") != "USER_MANAGED":
                continue
            key_name = key.get("name", "<unknown>")
            valid_after = key.get("valid_after", "")
            try:
                created = datetime.fromisoformat(
                    valid_after.replace("Z", "+00:00"),
                )
                age_days = (now - created).days
            except (ValueError, TypeError):
                age_days = None
            if age_days is not None and age_days > _MAX_AGE_DAYS:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=email,
                    description=(
                        f"Key '{key_name}' for SA {email} is "
                        f"{age_days} days old (maximum: "
                        f"{_MAX_AGE_DAYS})."
                    ),
                    recommendation=RULE.recommendation,
                    passed=False,
                ))
            elif age_days is not None:
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=email,
                    description=(
                        f"Key '{key_name}' for SA {email} is "
                        f"{age_days} days old."
                    ),
                    recommendation=RULE.recommendation,
                    passed=True,
                ))
            else:
                # Creation timestamp missing / unparseable: surface the
                # key instead of dropping it silently, since its rotation
                # age can't be verified.
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=email,
                    description=(
                        f"Key '{key_name}' for SA {email} has an "
                        f"unparseable creation timestamp "
                        f"({valid_after!r}); rotation age can't be "
                        "verified. Review this key manually."
                    ),
                    recommendation=RULE.recommendation,
                    passed=False,
                ))
    return findings
