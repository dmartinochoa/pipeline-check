"""AZNW-003. Application Gateway does not have WAF enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZNW-003",
    title="Application Gateway does not have WAF enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-693",),
    recommendation=(
        "Deploy Application Gateways with the WAF_v2 SKU and attach "
        "a WAF policy in Prevention mode. WAF protects web-facing "
        "applications from OWASP Top 10 attacks (SQL injection, XSS, "
        "request smuggling)."
    ),
    docs_note=(
        "Application Gateways without WAF pass all HTTP traffic "
        "directly to backend pools. Attacks against web applications "
        "behind the gateway are not inspected or blocked."
    ),
    exploit_example=(
        "An attacker sends an SQL injection payload through the "
        "Application Gateway to a pipeline dashboard. Without WAF "
        "inspection, the payload reaches the backend and extracts "
        "pipeline credentials from the database."
    ),
)

_WAF_TIERS = {"waf", "waf_v2"}


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for gw in catalog.application_gateways():
        name = getattr(gw, "name", "<unnamed>")
        sku = getattr(gw, "sku", None)
        tier = str(getattr(sku, "tier", "")).lower() if sku else ""
        waf_config = getattr(gw, "web_application_firewall_configuration", None)
        firewall_policy = getattr(gw, "firewall_policy", None)
        has_waf = (
            tier in _WAF_TIERS
            or waf_config is not None
            or firewall_policy is not None
        )
        passed = has_waf
        if passed:
            desc = (
                f"Application Gateway '{name}' has WAF enabled "
                f"(tier: {tier})."
            )
        else:
            desc = (
                f"Application Gateway '{name}' does not have WAF "
                f"enabled (tier: {tier}). HTTP traffic is not inspected "
                "for web attacks."
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
