"""S3-004 (CloudFormation). Artifact bucket access logging off."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..s3 import _s3004_logging
from ._s3_context import discover_targets

RULE = Rule(
    id="S3-004",
    title="Artifact bucket access logging not enabled",
    severity=Severity.LOW,
    owasp=("CICD-SEC-10",),
    cwe=("CWE-778",),
    recommendation=(
        "Set ``LoggingConfiguration.DestinationBucketName`` to a "
        "central, write-protected logging bucket. Access logs are "
        "what forensics use to reconstruct who pulled which artifact "
        "during an incident."
    ),
    docs_note=(
        "Reads ``AWS::S3::Bucket."
        "Properties.LoggingConfiguration.DestinationBucketName``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _s3004_logging(props, name) for name, props, _ in discover_targets(ctx)
    ]
