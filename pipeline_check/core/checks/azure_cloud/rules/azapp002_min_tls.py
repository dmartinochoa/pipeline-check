"""AZAPP-002. App Service minimum TLS version below 1.2."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZAPP-002",
    title="App Service minimum TLS version below 1.2",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-326",),
    recommendation=(
        "Set the App Service minimum TLS version to 1.2 (or higher). "
        "TLS 1.0 and 1.1 have known weaknesses and are deprecated "
        "across most compliance frameworks."
    ),
    docs_note=(
        "App Services that accept TLS 1.0 or 1.1 are vulnerable to "
        "protocol downgrade attacks. Enforcing TLS 1.2 as the floor "
        "prevents clients from negotiating weaker ciphers."
    ),
    exploit_example=(
        "An attacker forces a TLS downgrade on a CI/CD webhook "
        "endpoint hosted on App Service. The weaker cipher suite "
        "allows the attacker to decrypt webhook payloads containing "
        "repository events and secret references."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.web_apps():
        app = entry["app"]
        config = entry.get("config")
        name = getattr(app, "name", "<unnamed>")
        min_tls = getattr(config, "min_tls_version", None) if config else None
        tls_str = str(min_tls) if min_tls else "1.0"
        passed = tls_str >= "1.2"
        if passed:
            desc = (
                f"App Service '{name}' enforces TLS {tls_str} as the "
                "minimum version."
            )
        else:
            desc = (
                f"App Service '{name}' allows TLS version {tls_str}. "
                "Clients can negotiate deprecated protocol versions."
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
