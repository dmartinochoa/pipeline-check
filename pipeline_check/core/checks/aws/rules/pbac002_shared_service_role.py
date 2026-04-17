"""PBAC-002 — CodeBuild service role is shared across multiple projects."""
from __future__ import annotations

from collections import defaultdict

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="PBAC-002",
    title="CodeBuild service role shared across multiple projects",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-284",),
    recommendation=(
        "Create a dedicated IAM service role for each CodeBuild project, "
        "scoped to only the permissions that specific project requires. "
        "This limits the blast radius if one project's build is compromised."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    projects = catalog.codebuild_projects()
    role_to_projects: dict[str, list[str]] = defaultdict(list)
    for project in projects:
        role_arn = project.get("serviceRole", "")
        if role_arn:
            role_to_projects[role_arn].append(project["name"])

    findings: list[Finding] = []
    for project in sorted(projects, key=lambda p: p.get("name", "")):
        name = project.get("name", "<unnamed>")
        role_arn = project.get("serviceRole", "")
        if not role_arn:
            continue
        sharing = role_to_projects[role_arn]
        passed = len(sharing) <= 1
        if passed:
            desc = f"Project '{name}' uses a dedicated service role."
        else:
            others = sorted(p for p in sharing if p != name)
            others_str = ", ".join(others)
            desc = (
                f"Project '{name}' shares service role '{role_arn}' with "
                f"{len(others)} other project(s): {others_str}. "
                f"A compromised build in any of these projects can access "
                f"the same secrets, S3 buckets, and AWS resources as all others "
                f"using the same role."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
