"""CB-007 — CodeBuild webhook attached without filter groups."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-007",
    title="CodeBuild webhook has no filter group",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-284",),
    recommendation=(
        "Define filter groups restricting triggers to specific branches, "
        "actors, and event types."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        webhook = project.get("webhook")
        if not webhook:
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=name,
                description="No webhook is attached to this project.",
                recommendation="No action required.",
                passed=True,
            ))
            continue
        groups = webhook.get("filterGroups") or []
        passed = bool(groups)
        desc = (
            f"Webhook defines {len(groups)} filter group(s)."
            if passed else
            "Webhook is attached but has no filter group. Any push from any "
            "principal will trigger a build."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
