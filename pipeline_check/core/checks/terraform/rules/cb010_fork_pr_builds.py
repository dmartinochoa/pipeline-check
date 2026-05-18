"""CB-010 (Terraform). CodeBuild webhook allows fork-PR builds."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cb010

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
)


def check(ctx: TerraformContext) -> list[Finding]:
    webhooks: dict[str, dict[str, Any]] = {
        w.values.get("project_name", ""): w.values
        for w in ctx.resources("aws_codebuild_webhook")
    }
    findings: list[Finding] = []
    for r in ctx.resources("aws_codebuild_project"):
        name = r.values.get("name") or r.name
        hook = webhooks.get(name)
        if hook is not None:
            findings.append(_cb010(hook, r.address))
    return findings
