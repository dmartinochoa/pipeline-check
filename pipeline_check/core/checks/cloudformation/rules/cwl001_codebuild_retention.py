"""CWL-001 (CloudFormation). CodeBuild log group has no retention."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..extended import _cw_logs

RULE = Rule(
    id="CWL-001",
    title="CodeBuild log group has no retention policy",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-1188",),
    recommendation=(
        "Set ``RetentionInDays`` on every ``AWS::Logs::LogGroup`` "
        "whose name starts with ``/aws/codebuild/``. 30 / 90 / 365 "
        "days are typical."
    ),
    docs_note=(
        "Filters ``AWS::Logs::LogGroup`` by ``LogGroupName`` prefix "
        "``/aws/codebuild/`` and reads ``RetentionInDays``. Unbounded "
        "retention isn't free; it also makes incident response "
        "harder when there are years of irrelevant logs to grep."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _cw_logs(ctx) if f.check_id == "CWL-001"]
