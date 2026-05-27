"""GCNET-002. No default-deny ingress firewall rule configured."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCNET-002",
    title="No default-deny ingress firewall rule configured",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Create a low-priority (e.g. 65534) INGRESS DENY ALL rule "
        "for 0.0.0.0/0 on each VPC network. This ensures that only "
        "explicitly allowed traffic reaches instances."
    ),
    docs_note=(
        "GCP's implied firewall rules deny all ingress and allow all "
        "egress by default, but auto-created rules in the default "
        "network override this. An explicit deny-all ingress rule at "
        "low priority makes the deny posture visible and auditable."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    firewalls = catalog.compute_firewalls()
    resource = f"projects/{catalog.session.project_id}"
    # Look for an explicit deny-all ingress rule from 0.0.0.0/0
    has_deny_all = False
    for fw in firewalls:
        if fw.get("disabled"):
            continue
        direction = fw.get("direction", "")
        if direction != "INGRESS":
            continue
        source_ranges = fw.get("source_ranges", [])
        # A deny-all rule has no "allowed" entries and covers 0.0.0.0/0
        allowed = fw.get("allowed", [])
        if "0.0.0.0/0" in source_ranges and not allowed:
            has_deny_all = True
            break
    if has_deny_all:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "A default-deny ingress firewall rule exists for "
                "0.0.0.0/0."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        ))
    else:
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=resource,
            description=(
                "No explicit default-deny ingress firewall rule found "
                "for 0.0.0.0/0. Traffic may reach instances through "
                "permissive default rules."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
