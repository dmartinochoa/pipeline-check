"""PBAC-002 (Terraform). CodeBuild service role shared across projects."""
from __future__ import annotations

from collections import defaultdict

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..pbac import _pbac002_shared_role

RULE = Rule(
    id="PBAC-002",
    title="CodeBuild service role shared across multiple projects",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-5",),
    cwe=("CWE-269",),
    recommendation=(
        "Create one ``aws_iam_role`` per ``aws_codebuild_project`` and "
        "reference it via ``service_role``. Per-project roles cap the "
        "blast radius of a hijacked build to the resources that one "
        "project legitimately needs."
    ),
    docs_note=(
        "Counts ``aws_codebuild_project.service_role`` collisions. "
        "When two or more projects share the same role ARN, a build "
        "compromise in any one of them inherits the others' "
        "permissions wholesale."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    projects = list(ctx.resources("aws_codebuild_project"))
    role_map: dict[str, list[str]] = defaultdict(list)
    for r in projects:
        role = r.values.get("service_role", "")
        name = r.values.get("name") or r.name
        if role:
            role_map[role].append(name)
    findings: list[Finding] = []
    for r in sorted(projects, key=lambda x: x.values.get("name") or x.name):
        name = r.values.get("name") or r.name
        findings.append(_pbac002_shared_role(r.values, name, role_map))
    return findings
