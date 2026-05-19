"""CWL-001 (Terraform). CodeBuild log group has no retention policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..extended import _cw_logs_checks

RULE = Rule(
    id="CWL-001",
    title="CodeBuild log group has no retention policy",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-1188",),
    recommendation=(
        "Set ``retention_in_days`` on every "
        "``aws_cloudwatch_log_group`` whose name starts with "
        "``/aws/codebuild/``. 30 / 90 / 365 days are typical; match "
        "the figure to your compliance regime."
    ),
    docs_note=(
        "Filters ``aws_cloudwatch_log_group`` by "
        "``name`` prefix ``/aws/codebuild/`` and reads "
        "``retention_in_days``. Unbounded retention isn't free; "
        "it also makes incident response harder when there are "
        "years of irrelevant logs to grep."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _cw_logs_checks(ctx) if f.check_id == "CWL-001"]
