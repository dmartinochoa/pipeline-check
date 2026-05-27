"""AZST-004. Storage account minimum TLS version below 1.2."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZST-004",
    title="Storage account minimum TLS version below 1.2",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-326",),
    recommendation=(
        "Set the storage account's minimum TLS version to TLS1_2. "
        "TLS 1.0 and 1.1 have known cryptographic weaknesses and are "
        "deprecated by most compliance frameworks."
    ),
    docs_note=(
        "Storage accounts that accept TLS 1.0 or 1.1 expose data in "
        "transit to downgrade attacks. Azure supports TLS 1.2 as the "
        "minimum; enforcing it prevents clients from negotiating "
        "weaker protocol versions."
    ),
    exploit_example=(
        "An attacker on a shared network forces a TLS downgrade to "
        "1.0 and exploits known BEAST/POODLE vulnerabilities to "
        "intercept pipeline artifacts stored in the account."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for account in catalog.storage_accounts():
        name = getattr(account, "name", "<unnamed>")
        min_tls = getattr(account, "minimum_tls_version", None)
        tls_str = str(min_tls) if min_tls else "TLS1_0"
        passed = tls_str == "TLS1_2"
        if passed:
            desc = (
                f"Storage account '{name}' enforces TLS 1.2 as the "
                "minimum version."
            )
        else:
            desc = (
                f"Storage account '{name}' allows TLS version "
                f"'{tls_str}'. Clients can negotiate deprecated "
                "protocol versions."
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
