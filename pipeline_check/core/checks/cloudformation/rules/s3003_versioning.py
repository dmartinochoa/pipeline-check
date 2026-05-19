"""S3-003 (CloudFormation). Artifact bucket versioning not enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..s3 import _s3003_versioning
from ._s3_context import discover_targets

RULE = Rule(
    id="S3-003",
    title="Artifact bucket versioning not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-353",),
    recommendation=(
        "Set ``VersioningConfiguration.Status: Enabled`` on every "
        "artifact bucket. Versioning lets you recover from accidental "
        "or malicious overwrites without restoring from external "
        "backups."
    ),
    docs_note=(
        "Reads ``AWS::S3::Bucket."
        "Properties.VersioningConfiguration.Status`` — must be "
        "``Enabled``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _s3003_versioning(props, name) for name, props, _ in discover_targets(ctx)
    ]
