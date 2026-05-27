"""AZNW-002. NSG does not have flow logging enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZNW-002",
    title="NSG does not have flow logging enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable NSG flow logs for every network security group. "
        "Send flow logs to a Storage account and optionally to a "
        "Log Analytics workspace for Traffic Analytics."
    ),
    docs_note=(
        "NSG flow logs record network traffic metadata (source, "
        "destination, port, protocol, action). Without them, "
        "incident responders have no visibility into lateral "
        "movement or data exfiltration paths."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    nsgs = catalog.network_security_groups()
    flow_logs = catalog.nsg_flow_logs()

    # Build a set of NSG resource IDs that have flow logs.
    logged_nsg_ids: set[str] = set()
    for fl in flow_logs:
        target_id = getattr(fl, "target_resource_id", "") or ""
        if target_id:
            logged_nsg_ids.add(target_id.lower())

    for nsg in nsgs:
        nsg_name = getattr(nsg, "name", "<unnamed>")
        nsg_id = str(getattr(nsg, "id", "")).lower()
        passed = nsg_id in logged_nsg_ids if nsg_id else False
        if passed:
            desc = (
                f"NSG '{nsg_name}' has flow logging enabled."
            )
        else:
            desc = (
                f"NSG '{nsg_name}' does not have flow logging "
                "enabled. Network traffic metadata is not recorded."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=nsg_name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
