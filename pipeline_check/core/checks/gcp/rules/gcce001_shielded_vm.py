"""GCCE-001. Compute instance does not have Shielded VM enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCCE-001",
    title="Compute instance does not have Shielded VM enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-693",),
    recommendation=(
        "Enable Shielded VM with both vTPM and integrity monitoring "
        "on all Compute Engine instances. Shielded VM verifies the "
        "boot chain and detects boot-level rootkits."
    ),
    docs_note=(
        "Shielded VM uses Secure Boot, vTPM, and integrity monitoring "
        "to defend against boot-level and kernel-level malware. "
        "Without it, an attacker who gains root can install a "
        "persistent rootkit that survives reboots."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.compute_instances():
        name = inst.get("name", "<unnamed>")
        config = inst.get("shielded_instance_config")
        vtpm = config.get("enable_vtpm", False) if config else False
        integrity = (
            config.get("enable_integrity_monitoring", False)
            if config
            else False
        )
        if vtpm and integrity:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' has Shielded VM enabled "
                    "(vTPM and integrity monitoring)."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
        else:
            missing: list[str] = []
            if not vtpm:
                missing.append("vTPM")
            if not integrity:
                missing.append("integrity monitoring")
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' is missing Shielded VM "
                    f"features: {', '.join(missing)}."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
