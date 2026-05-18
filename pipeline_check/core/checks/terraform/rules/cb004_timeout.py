"""CB-004 (Terraform). CodeBuild build_timeout left at default."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codebuild import _cb004_timeout

RULE = Rule(
    id="CB-004",
    title="No build timeout configured",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-400",),
    recommendation=(
        "Set ``build_timeout`` to a value matched to your real build "
        "duration (15–60 minutes is typical). Pair with a CloudWatch "
        "alarm on ``AWS/CodeBuild`` ``BuildDuration`` so builds that "
        "approach the cap surface as runtime alerts, not stuck jobs."
    ),
    docs_note=(
        "Reads ``aws_codebuild_project.build_timeout`` (in minutes). "
        "Projects left at the AWS maximum of 480 minutes let a runaway "
        "or hijacked build consume compute and delay detection of a "
        "compromised pipeline stage."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb004_timeout(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
