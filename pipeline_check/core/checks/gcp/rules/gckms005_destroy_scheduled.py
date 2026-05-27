"""GCKMS-005. KMS key has primary version scheduled for destruction."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCKMS-005",
    title="KMS key has primary version scheduled for destruction",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-324",),
    recommendation=(
        "Review keys with DESTROY_SCHEDULED primary versions. If the "
        "key is still in use, cancel the destruction. If intentional, "
        "ensure all dependent services have migrated to a new key "
        "before the destruction window closes."
    ),
    docs_note=(
        "A key version scheduled for destruction will become "
        "permanently unavailable after the scheduled destroy time. "
        "Any data encrypted with that version becomes unrecoverable. "
        "This check flags keys where the primary version is pending "
        "destruction."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for key in catalog.kms_keys():
        name = key.get("name", "<unnamed>")
        primary_state = key.get("primary_state")
        if primary_state == "DESTROY_SCHEDULED":
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"KMS key '{name}' has its primary version "
                    "scheduled for destruction. Data encrypted with "
                    "this version will become unrecoverable."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
        elif primary_state is not None:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"KMS key '{name}' primary version state: "
                    f"{primary_state}."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
    return findings
