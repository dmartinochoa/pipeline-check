"""AZMON-005. NSG flow log retention less than 90 days."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZMON-005",
    title="NSG flow log retention less than 90 days",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-779",),
    recommendation=(
        "Set NSG flow log retention to at least 90 days. Longer "
        "retention enables forensic analysis of network traffic "
        "patterns during incident investigations."
    ),
    docs_note=(
        "Short flow log retention periods limit the ability to "
        "investigate lateral movement and data exfiltration. "
        "Compliance frameworks typically require at least 90 days "
        "of network log retention."
    ),
)

_MIN_RETENTION_DAYS = 90


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    flow_logs = catalog.nsg_flow_logs()

    for fl in flow_logs:
        fl_name = getattr(fl, "name", "<unnamed>")
        target_id = getattr(fl, "target_resource_id", "")
        retention = getattr(fl, "retention_policy", None)
        enabled = getattr(retention, "enabled", False) if retention else False
        days = getattr(retention, "days", 0) if retention else 0

        if not enabled:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=fl_name,
                description=(
                    f"Flow log '{fl_name}' (target: {target_id}) does "
                    "not have a retention policy enabled. Logs are not "
                    "automatically managed."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        elif days == 0:
            # days=0 with retention enabled means retain indefinitely,
            # which satisfies any minimum-days requirement.
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=fl_name,
                description=(
                    f"Flow log '{fl_name}' retains logs indefinitely "
                    "(days=0 means no expiry)."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
        elif days < _MIN_RETENTION_DAYS:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=fl_name,
                description=(
                    f"Flow log '{fl_name}' retains logs for {days} days "
                    f"(minimum: {_MIN_RETENTION_DAYS})."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=fl_name,
                description=(
                    f"Flow log '{fl_name}' retains logs for {days} days "
                    f"(>= {_MIN_RETENTION_DAYS})."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
