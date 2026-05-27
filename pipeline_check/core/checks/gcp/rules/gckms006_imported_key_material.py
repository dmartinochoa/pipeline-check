"""GCKMS-006. KMS key uses imported (external) key material."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCKMS-006",
    title="KMS key uses imported (external) key material",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-321",),
    recommendation=(
        "Document the key material import process and ensure the "
        "external key material is stored securely. Consider using "
        "GCP-generated key material (SOFTWARE or HSM protection "
        "level) unless regulatory requirements mandate external "
        "key management."
    ),
    docs_note=(
        "Keys with EXTERNAL or EXTERNAL_VPC protection level use "
        "key material imported from outside GCP. The security of "
        "these keys depends on the external key management "
        "infrastructure, which is outside GCP's control."
    ),
)

_EXTERNAL_LEVELS = frozenset({"EXTERNAL", "EXTERNAL_VPC"})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for key in catalog.kms_keys():
        name = key.get("name", "<unnamed>")
        protection_level = key.get("protection_level", "SOFTWARE")
        if protection_level in _EXTERNAL_LEVELS:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"KMS key '{name}' uses imported key material "
                    f"(protection_level={protection_level}). Key "
                    "security depends on the external key management "
                    "infrastructure."
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
                    f"KMS key '{name}' uses GCP-managed key material "
                    f"(protection_level={protection_level})."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
