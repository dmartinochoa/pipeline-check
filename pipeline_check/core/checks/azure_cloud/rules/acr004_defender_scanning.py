"""ACR-004. Container registry does not have Defender scanning enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ACR-004",
    title="Container registry Defender scanning not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-1395",),
    recommendation=(
        "Enable Microsoft Defender for Containers on the subscription "
        "and configure the quarantine policy on Premium-tier "
        "registries. Defender scans images for OS and language-level "
        "vulnerabilities on push and import."
    ),
    docs_note=(
        "Without vulnerability scanning, container images with known "
        "CVEs flow through the CI/CD pipeline into production. "
        "Defender for Containers provides both push-time and "
        "continuous scanning."
    ),
    exploit_example=(
        "A base image with a critical OpenSSL vulnerability is pushed "
        "to the registry. Without Defender scanning, the pipeline "
        "deploys it to production, where the vulnerability is "
        "exploited for remote code execution."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for registry in catalog.container_registries():
        name = getattr(registry, "name", "<unnamed>")
        sku_name = str(getattr(getattr(registry, "sku", None), "name", "")).lower()
        policies = getattr(registry, "policies", None)
        quarantine = getattr(policies, "quarantine_policy", None) if policies else None
        quarantine_status = str(getattr(quarantine, "status", "disabled")).lower() if quarantine else "disabled"
        # Defender scanning is a subscription-level setting, but
        # quarantine policy on Premium registries is the per-registry
        # indicator.  For non-Premium registries, we flag as a warning.
        if sku_name != "premium":
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Container registry '{name}' uses the '{sku_name}' "
                    "SKU. Quarantine policy (and by extension Defender "
                    "image scanning) requires the Premium tier."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
            continue
        passed = quarantine_status == "enabled"
        if passed:
            desc = (
                f"Container registry '{name}' has the quarantine policy "
                "enabled for Defender vulnerability scanning."
            )
        else:
            desc = (
                f"Container registry '{name}' does not have the "
                "quarantine policy enabled. Pushed images are not "
                "held for vulnerability scanning."
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
