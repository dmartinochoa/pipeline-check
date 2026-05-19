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
