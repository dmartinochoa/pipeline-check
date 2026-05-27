"""AZAPP-005. App Service FTP access not disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZAPP-005",
    title="App Service FTP access not disabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Set the App Service FTP state to 'Disabled' or 'FtpsOnly'. "
        "Plain FTP transmits credentials and file contents in "
        "cleartext. Prefer deployment via Azure DevOps, GitHub "
        "Actions, or the Kudu ZIP API."
    ),
    docs_note=(
        "FTP deployment is a legacy mechanism that sends files and "
        "credentials unencrypted. FTPS (FTP over TLS) is acceptable "
        "but disabling FTP entirely is preferred."
    ),
)

_ACCEPTABLE_STATES = {"disabled", "ftpsonly"}


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.web_apps():
        app = entry["app"]
        config = entry.get("config")
        name = getattr(app, "name", "<unnamed>")
        ftp_state = str(
            getattr(config, "ftp_state", "AllAllowed"),
        ).lower() if config else "allallowed"
        passed = ftp_state in _ACCEPTABLE_STATES
        if passed:
            desc = (
                f"App Service '{name}' has FTP state set to "
                f"'{ftp_state}'."
            )
        else:
            desc = (
                f"App Service '{name}' allows plain FTP (state: "
                f"'{ftp_state}'). Credentials and files are "
                "transmitted unencrypted."
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
