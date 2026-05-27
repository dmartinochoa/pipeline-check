"""AZAPP-001. App Service does not enforce HTTPS."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZAPP-001",
    title="App Service does not enforce HTTPS",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Enable 'HTTPS Only' on the App Service. This redirects all "
        "HTTP traffic to HTTPS, preventing data from being "
        "transmitted in cleartext."
    ),
    docs_note=(
        "Without HTTPS-only mode, clients can connect over HTTP and "
        "transmit authentication tokens, API keys, and application "
        "data in cleartext. This is exploitable on shared or "
        "compromised networks."
    ),
    exploit_example=(
        "A pipeline dashboard served by App Service accepts HTTP. "
        "An attacker on the same network intercepts the session "
        "cookie over cleartext HTTP and hijacks the operator's "
        "session."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.web_apps():
        app = entry["app"]
        name = getattr(app, "name", "<unnamed>")
        https_only = getattr(app, "https_only", False)
        passed = bool(https_only)
        if passed:
            desc = (
                f"App Service '{name}' enforces HTTPS-only traffic."
            )
        else:
            desc = (
                f"App Service '{name}' does not enforce HTTPS. "
                "Clients can connect over unencrypted HTTP."
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
