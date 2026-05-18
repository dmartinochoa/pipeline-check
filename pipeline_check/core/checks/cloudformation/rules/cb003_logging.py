"""CB-003 (CloudFormation). CodeBuild logging not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..codebuild import _cb003_logging_enabled

RULE = Rule(
    id="CB-003",
    title="Build logging not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Enable at least one of "
        "``LogsConfig.CloudWatchLogs.Status: ENABLED`` or "
        "``LogsConfig.S3Logs.Status: ENABLED``. CloudWatch is the "
        "easier default; pair S3 with an object-lock bucket for "
        "tamper-evident retention."
    ),
    docs_note=(
        "Reads both ``LogsConfig.CloudWatchLogs.Status`` and "
        "``LogsConfig.S3Logs.Status``. Without either, the build's "
        "stdout/stderr is captured only in the in-flight console "
        "view — audit and incident review have no record."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _cb003_logging_enabled(r.properties, r.address)
        for r in ctx.resources("AWS::CodeBuild::Project")
    ]
