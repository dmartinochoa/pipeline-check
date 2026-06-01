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
    exploit_example=(
        "# Vulnerable: two CodeBuild projects share one service role.\n"
        "resource \"aws_codebuild_project\" \"api\" {\n"
        "  name         = \"api\"\n"
        "  service_role = aws_iam_role.shared.arn\n"
        "}\n"
        "\n"
        "resource \"aws_codebuild_project\" \"infra\" {\n"
        "  name         = \"infra\"\n"
        "  service_role = aws_iam_role.shared.arn\n"
        "}\n"
        "\n"
        "# Attack: the shared role is the union of what every project\n"
        "# needs (api's S3 + secrets, infra's deploy permissions). A\n"
        "# build compromise in `api` (a malicious dependency, an\n"
        "# injected buildspec command) assumes the shared role and now\n"
        "# wields infra's deploy permissions too, so a low-value project\n"
        "# becomes the pivot into the high-value one.\n"
        "\n"
        "# Safe: one least-privilege role per project caps the blast\n"
        "# radius to that project's own resources.\n"
        "resource \"aws_codebuild_project\" \"api\" {\n"
        "  name         = \"api\"\n"
        "  service_role = aws_iam_role.api.arn\n"
        "}\n"
        "\n"
        "resource \"aws_codebuild_project\" \"infra\" {\n"
        "  name         = \"infra\"\n"
        "  service_role = aws_iam_role.infra.arn\n"
        "}"
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
