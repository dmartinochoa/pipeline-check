"""CB-007 (Terraform). CodeBuild webhook has no filter_group."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codebuild import _cb007_webhook_filter

RULE = Rule(
    id="CB-007",
    title="CodeBuild webhook has no filter_group",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    cwe=("CWE-732",),
    recommendation=(
        "Define ``filter_group`` blocks on the ``aws_codebuild_webhook`` "
        "resource that restrict triggers to specific branches, actors, "
        "and event types. At minimum include an ``ACTOR_ACCOUNT_ID`` "
        "filter to keep fork PRs from triggering builds."
    ),
    docs_note=(
        "Joins ``aws_codebuild_webhook`` records to their parent "
        "``aws_codebuild_project`` via ``project_name`` and reads "
        "``filter_group[*]``. A webhook with no filter group accepts "
        "every push event from every principal, including forks for "
        "public repositories."
    ),
    exploit_example=(
        "# Vulnerable: a CodeBuild webhook with no filter_group.\n"
        "resource \"aws_codebuild_webhook\" \"ci\" {\n"
        "  project_name = aws_codebuild_project.ci.name\n"
        "}\n"
        "\n"
        "# Attack: with no filter_group the webhook fires on every\n"
        "# event, including pull requests from forks of a public repo.\n"
        "# The fork PR's code (its buildspec, its scripts) runs in\n"
        "# CodeBuild with the project's IAM role and environment, so\n"
        "# anyone on the internet executes in your build account\n"
        "# (poisoned-pipeline execution).\n"
        "\n"
        "# Safe: restrict to trusted branches and actors.\n"
        "resource \"aws_codebuild_webhook\" \"ci\" {\n"
        "  project_name = aws_codebuild_project.ci.name\n"
        "  filter_group {\n"
        "    filter {\n"
        "      type    = \"HEAD_REF\"\n"
        "      pattern = \"^refs/heads/main$\"\n"
        "    }\n"
        "    filter {\n"
        "      type    = \"ACTOR_ACCOUNT_ID\"\n"
        "      pattern = \"^123456789012$\"\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    webhooks: dict[str, dict[str, Any]] = {}
    for r in ctx.resources("aws_codebuild_webhook"):
        proj = r.values.get("project_name", "")
        if proj:
            webhooks[proj] = r.values
    findings: list[Finding] = []
    for r in ctx.resources("aws_codebuild_project"):
        name = r.values.get("name") or r.name
        findings.append(_cb007_webhook_filter(webhooks.get(name), r.address))
    return findings
