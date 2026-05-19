"""CB-004 (CloudFormation). CodeBuild TimeoutInMinutes too high."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..codebuild import _cb004_timeout

RULE = Rule(
    id="CB-004",
    title="No build timeout configured",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-400",),
    recommendation=(
        "Set ``TimeoutInMinutes`` to a value matched to your real "
        "build duration (15–60 minutes is typical). Pair with a "
        "CloudWatch alarm on ``AWS/CodeBuild`` ``BuildDuration``."
    ),
    docs_note=(
        "Reads ``AWS::CodeBuild::Project.Properties.TimeoutInMinutes``. "
        "Projects left at the AWS maximum of 480 minutes let a "
        "runaway or hijacked build consume compute and delay "
        "detection of a compromised pipeline stage."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb004_timeout(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
