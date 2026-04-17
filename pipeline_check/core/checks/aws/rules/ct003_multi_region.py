"""CT-003 — CloudTrail trail is not multi-region."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CT-003",
    title="CloudTrail trail is not multi-region",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Convert the trail to a multi-region trail. A single-region trail "
        "misses activity in every other region — an attacker aware of the "
        "scope can drive reconnaissance or persistence from an unlogged "
        "region."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for trail in catalog.cloudtrail_trails():
        name = trail.get("Name", "<unnamed>")
        passed = bool(trail.get("IsMultiRegionTrail"))
        if passed:
            desc = f"Trail '{name}' is multi-region."
        else:
            desc = (
                f"Trail '{name}' is region-scoped. Activity in other regions "
                "is not captured by this trail."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
