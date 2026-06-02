"""AZST-006. Storage account access keys not rotated within 90 days."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZST-006",
    title="Storage account access keys not rotated within 90 days",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-324",),
    recommendation=(
        "Rotate storage account access keys at least every 90 days. "
        "Use Azure Key Vault to manage key rotation automatically, or "
        "switch to Azure AD-based authentication to eliminate shared "
        "keys entirely."
    ),
    docs_note=(
        "Storage account keys are long-lived shared secrets with full "
        "read/write access. If a key is leaked in a CI/CD log or "
        "environment variable, an attacker retains access until the "
        "key is manually rotated."
    ),
    exploit_example=(
        "A storage account key is inadvertently logged in a pipeline "
        "run. Because the key has not been rotated in over a year, "
        "the attacker uses it months later to exfiltrate pipeline "
        "state and inject malicious artifacts."
    ),
)

_MAX_AGE_DAYS = 90


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(tz=UTC)
    threshold = now - timedelta(days=_MAX_AGE_DAYS)
    for account in catalog.storage_accounts():
        name = getattr(account, "name", "<unnamed>")
        key_creation = getattr(account, "key_creation_time", None)
        if key_creation is None:
            # The Azure SDK only populates key_creation_time when a key
            # rotation policy is configured. Its absence does not mean the
            # keys are stale; emit an advisory rather than a hard failure.
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=Severity.INFO,
                resource=name,
                description=(
                    f"Storage account '{name}' does not expose key "
                    "creation time (no rotation policy is configured). "
                    "Verify key rotation manually."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
            continue

        key1_time = getattr(key_creation, "key1", None)
        key2_time = getattr(key_creation, "key2", None)
        stale_keys: list[str] = []
        if key1_time and key1_time < threshold:
            stale_keys.append("key1")
        if key2_time and key2_time < threshold:
            stale_keys.append("key2")

        passed = len(stale_keys) == 0
        if passed:
            desc = (
                f"Storage account '{name}' has access keys rotated "
                f"within the last {_MAX_AGE_DAYS} days."
            )
        else:
            desc = (
                f"Storage account '{name}' has stale access keys: "
                f"{', '.join(stale_keys)}. Keys have not been rotated "
                f"within {_MAX_AGE_DAYS} days."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
