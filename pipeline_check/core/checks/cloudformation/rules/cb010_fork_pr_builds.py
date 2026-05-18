"""CB-010 (CloudFormation). CodeBuild webhook allows fork-PR builds."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _codebuild

RULE = Rule(
    id="CB-010",
    title="CodeBuild webhook allows fork-PR builds without actor filtering",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-863",),
    recommendation=(
        "Add an ``ACTOR_ACCOUNT_ID`` filter to every "
        "``Triggers.FilterGroups`` entry whose ``EVENT`` filter "
        "covers a ``PULL_REQUEST_*`` event. Without it, a fork-PR "
        "build runs with the project's service role."
    ),
    docs_note=(
        "Reads ``Triggers.FilterGroups[*]``. For each group that "
        "covers a ``PULL_REQUEST_*`` event, fires when no sibling "
        "``ACTOR_ACCOUNT_ID`` filter constrains the PR author."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codebuild(ctx) if f.check_id == "CB-010"]
