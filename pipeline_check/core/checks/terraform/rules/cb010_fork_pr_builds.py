"""CB-010 (Terraform). CodeBuild webhook allows fork-PR builds."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import (
    _cb010,
    index_codebuild_webhooks,
    webhook_for_project,
)

RULE = Rule(
    id="CB-010",
    title="CodeBuild webhook allows fork-PR builds without actor filtering",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-863",),
    recommendation=(
        "Add an ``ACTOR_ACCOUNT_ID`` filter to every "
        "``filter_group`` whose ``EVENT`` filter covers a "
        "``PULL_REQUEST_*`` event. Without it, a fork-PR build runs "
        "with the project's service role."
    ),
    docs_note=(
        "Reads ``aws_codebuild_webhook.filter_group[*].filter[*]``. "
        "For each group that covers a ``PULL_REQUEST_*`` event, fires "
        "when no sibling ``ACTOR_ACCOUNT_ID`` filter constrains the "
        "PR author."
    ),
    exploit_example=(
        "# Vulnerable: build runs on PULL_REQUEST_MERGED or\n"
        "# PULL_REQUEST_CREATED from forks. A fork PR can inject\n"
        "# arbitrary code that executes with the project's IAM role.\n"
        'resource "aws_codebuild_project" "ci" {\n'
        "  source {\n"
        '    type     = "GITHUB"\n'
        '    location = "https://github.com/org/repo.git"\n'
        "  }\n"
        "}\n"
        'resource "aws_codebuild_webhook" "pr" {\n'
        "  project_name = aws_codebuild_project.ci.name\n"
        "  filter_group {\n"
        '    filter { type = "EVENT" pattern = "PULL_REQUEST_CREATED" }\n'
        "  }\n"
        "}\n"
        "\n"
        "# Safe: restrict to PUSH events on the main branch.\n"
        'resource "aws_codebuild_webhook" "push" {\n'
        "  project_name = aws_codebuild_project.ci.name\n"
        "  filter_group {\n"
        '    filter { type = "EVENT"      pattern = "PUSH" }\n'
        '    filter { type = "HEAD_REF"   pattern = "^refs/heads/main$" }\n'
        "  }\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    webhooks = index_codebuild_webhooks(ctx)
    findings: list[Finding] = []
    for r in ctx.resources("aws_codebuild_project"):
        hook = webhook_for_project(webhooks, r)
        if hook is not None:
            findings.append(_cb010(hook, r.address))
    return findings
