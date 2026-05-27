"""AZAPP-004. App Service has remote debugging enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZAPP-004",
    title="App Service has remote debugging enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-489",),
    recommendation=(
        "Disable remote debugging on the App Service. Remote "
        "debugging opens additional ports and reduces the security "
        "posture of the app. Use Application Insights or log "
        "streaming for production diagnostics."
    ),
    docs_note=(
        "Remote debugging exposes a debug endpoint that accepts "
        "incoming connections. In production, this is an unnecessary "
        "attack surface. Azure automatically disables remote debugging "
        "after 48 hours, but it can be re-enabled."
    ),
    exploit_example=(
        "An attacker discovers a remote debugging endpoint on an "
        "App Service hosting a pipeline orchestrator. The debug "
        "port allows arbitrary code execution in the application "
        "context, exposing pipeline secrets."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for entry in catalog.web_apps():
        app = entry["app"]
        config = entry.get("config")
        name = getattr(app, "name", "<unnamed>")
        remote_debug = getattr(
            config, "remote_debugging_enabled", False,
        ) if config else False
        passed = not bool(remote_debug)
        if passed:
            desc = (
                f"App Service '{name}' has remote debugging disabled."
            )
        else:
            desc = (
                f"App Service '{name}' has remote debugging enabled. "
                "A debug endpoint is exposed that accepts incoming "
                "connections."
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
