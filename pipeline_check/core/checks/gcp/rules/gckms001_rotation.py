"""GCKMS-001. KMS key rotation period exceeds 365 days."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCKMS-001",
    title="KMS key rotation period exceeds 365 days",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-324",),
    recommendation=(
        "Set the rotation period to 365 days or less. GCP "
        "automatically creates a new key version when the rotation "
        "period elapses."
    ),
    docs_note=(
        "Regular key rotation limits the window of exposure if a key "
        "version is compromised. CIS GCP Foundations requires "
        "rotation within 365 days for symmetric encryption keys."
    ),
)

_MAX_ROTATION_DAYS = 365


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for key in catalog.kms_keys():
        name = key.get("name", "<unnamed>")
        purpose = key.get("purpose", "")
        if purpose != "ENCRYPT_DECRYPT":
            continue
        rotation_days = key.get("rotation_period_days")
        if rotation_days is None:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"KMS key '{name}' has no automatic rotation "
                    "period configured."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        elif rotation_days > _MAX_ROTATION_DAYS:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"KMS key '{name}' rotates every "
                    f"{int(rotation_days)} days (maximum: "
                    f"{_MAX_ROTATION_DAYS})."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"KMS key '{name}' rotates every "
                    f"{int(rotation_days)} days."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
