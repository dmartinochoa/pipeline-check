"""AZST-001. Storage account allows public blob access."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZST-001",
    title="Storage account allows public blob access",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Set 'Allow Blob public access' to disabled on the storage "
        "account. Use SAS tokens or Azure AD RBAC for legitimate "
        "access patterns."
    ),
    docs_note=(
        "When blob public access is enabled at the account level, "
        "individual containers can be configured for anonymous read "
        "access. Artifacts, build logs, and SBOM files stored in "
        "publicly accessible containers are exposed to the internet."
    ),
    exploit_example=(
        "An attacker discovers a publicly accessible container holding "
        "build artifacts. The artifacts contain embedded credentials "
        "or internal configuration files, enabling lateral movement "
        "into the CI/CD pipeline."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for account in catalog.storage_accounts():
        name = getattr(account, "name", "<unnamed>")
        allow_public = getattr(account, "allow_blob_public_access", None)
        if allow_public is None:
            allow_public = True
        passed = not allow_public
        if passed:
            desc = f"Storage account '{name}' has public blob access disabled."
        else:
            desc = (
                f"Storage account '{name}' allows public blob access. "
                "Containers in this account can be configured for "
                "anonymous read access."
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
