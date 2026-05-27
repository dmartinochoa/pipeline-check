"""AZAPP-003. App Service does not use a managed identity."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZAPP-003",
    title="App Service does not use a managed identity",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Assign a system-assigned or user-assigned managed identity "
        "to the App Service. Managed identities eliminate the need "
        "for stored credentials when accessing Azure resources."
    ),
    docs_note=(
        "Without a managed identity, the App Service must store "
        "connection strings, client secrets, or certificates in "
        "application settings or Key Vault references. Managed "
        "identities provide automatic credential rotation and "
        "eliminate secret sprawl."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.web_apps():
        app = entry["app"]
        name = getattr(app, "name", "<unnamed>")
        identity = getattr(app, "identity", None)
        identity_type = str(getattr(identity, "type", "None")).lower() if identity else "none"
        passed = identity_type != "none" and identity is not None
        if passed:
            desc = (
                f"App Service '{name}' has a managed identity "
                f"configured (type: {identity_type})."
            )
        else:
            desc = (
                f"App Service '{name}' does not have a managed "
                "identity. The app must store credentials explicitly "
                "to access Azure resources."
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
