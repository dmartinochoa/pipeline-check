"""AZST-002. Storage account allows non-HTTPS traffic."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZST-002",
    title="Storage account allows non-HTTPS traffic",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Enable 'Secure transfer required' on the storage account to "
        "reject all HTTP requests. All modern Azure SDKs and tools "
        "default to HTTPS."
    ),
    docs_note=(
        "Without the secure-transfer flag, data in transit (including "
        "artifacts, secrets, and pipeline state) can be intercepted "
        "on shared networks."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for account in catalog.storage_accounts():
        name = getattr(account, "name", "<unnamed>")
        https_only = getattr(account, "enable_https_traffic_only", True)
        passed = bool(https_only)
        if passed:
            desc = f"Storage account '{name}' requires HTTPS."
        else:
            desc = (
                f"Storage account '{name}' allows non-HTTPS traffic. "
                "Data in transit can be intercepted."
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
