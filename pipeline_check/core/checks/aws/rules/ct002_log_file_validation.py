"""CT-002 — CloudTrail log-file integrity validation disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CT-002",
    title="CloudTrail log-file validation disabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-354",),
    recommendation=(
        "Set ``LogFileValidationEnabled=true`` on every CloudTrail trail. "
        "Log validation produces a signed digest file alongside each log "
        "object so tampering by an attacker who also has S3 write access "
        "can be detected after the fact."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for trail in catalog.cloudtrail_trails():
        name = trail.get("Name", "<unnamed>")
        passed = bool(trail.get("LogFileValidationEnabled"))
        if passed:
            desc = f"Trail '{name}' enables log-file validation."
        else:
            desc = (
                f"Trail '{name}' does not enable log-file validation. An "
                "attacker with S3 write access can tamper with log objects "
                "without leaving a detectable integrity gap."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
