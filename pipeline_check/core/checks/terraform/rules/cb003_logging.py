"""CB-003 (Terraform). CodeBuild build logging not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..codebuild import _cb003_logging_enabled

RULE = Rule(
    id="CB-003",
    title="Build logging not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable at least one of ``logs_config[0].cloudwatch_logs[0]."
        "status = \"ENABLED\"`` or ``logs_config[0].s3_logs[0].status = "
        "\"ENABLED\"``. CloudWatch is the easier default; pair S3 with "
        "an object-lock bucket if you need tamper-evident retention."
    ),
    docs_note=(
        "Reads both ``logs_config[0].cloudwatch_logs[0].status`` and "
        "``logs_config[0].s3_logs[0].status``. Without either, the "
        "build's stdout/stderr is captured only in the in-flight "
        "console view, audit and post-incident review have no record "
        "of what the build actually did."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [
        _cb003_logging_enabled(r.values, r.address)
        for r in ctx.resources("aws_codebuild_project")
    ]
