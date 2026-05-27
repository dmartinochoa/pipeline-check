"""GCKMS-003. KMS key not using HSM protection level."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCKMS-003",
    title="KMS key not using HSM protection level",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Use HSM (Hardware Security Module) protection level for "
        "keys that protect sensitive data. HSM keys never leave "
        "the hardware boundary."
    ),
    docs_note=(
        "SOFTWARE protection level keys are managed in software; "
        "HSM protection level keys are backed by Cloud HSM "
        "(FIPS 140-2 Level 3). HSM adds defense against certain "
        "insider and physical-access threats."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for key in catalog.kms_keys():
        name = key.get("name", "<unnamed>")
        protection = key.get("protection_level", "SOFTWARE")
        passed = protection == "HSM"
        if passed:
            desc = f"KMS key '{name}' uses HSM protection level."
        else:
            desc = (
                f"KMS key '{name}' uses {protection} protection level "
                "instead of HSM."
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
