"""AZNW-004. NSG has no explicit deny-all inbound rule."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZNW-004",
    title="NSG has no explicit deny-all inbound rule",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Add an explicit deny-all inbound rule at the lowest priority "
        "in the NSG. While Azure NSGs have an implicit deny, an "
        "explicit rule makes the intent visible, auditable, and "
        "prevents accidental over-permissive rules from dominating."
    ),
    docs_note=(
        "Azure NSGs include an implicit deny-all at priority 65500, "
        "but it is invisible in portal and audit exports. An explicit "
        "deny-all at a lower priority (e.g. 4096) documents the "
        "security intent and is visible in compliance reports."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for nsg in catalog.network_security_groups():
        nsg_name = getattr(nsg, "name", "<unnamed>")
        rules = getattr(nsg, "security_rules", []) or []
        has_deny_all = False
        for rule in rules:
            direction = str(getattr(rule, "direction", "")).lower()
            access = str(getattr(rule, "access", "")).lower()
            src = str(getattr(rule, "source_address_prefix", ""))
            dest_port = str(getattr(rule, "destination_port_range", ""))
            if (
                direction == "inbound"
                and access == "deny"
                and src == "*"
                and dest_port == "*"
            ):
                has_deny_all = True
                break

        passed = has_deny_all
        if passed:
            desc = (
                f"NSG '{nsg_name}' has an explicit deny-all inbound "
                "rule."
            )
        else:
            desc = (
                f"NSG '{nsg_name}' does not have an explicit deny-all "
                "inbound rule. The security intent relies solely on "
                "the implicit Azure default deny."
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
