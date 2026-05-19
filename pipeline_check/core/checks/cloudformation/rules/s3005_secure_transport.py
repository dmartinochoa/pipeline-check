"""S3-005 (CloudFormation). Artifact bucket has no SecureTransport deny."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..s3 import _s3005_secure_transport
from ._s3_context import discover_targets

RULE = Rule(
    id="S3-005",
    title="Artifact bucket missing aws:SecureTransport deny",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Attach an ``AWS::S3::BucketPolicy`` carrying a ``Deny`` "
        "statement on ``Action: \"s3:*\"`` when "
        "``Bool aws:SecureTransport = false``."
    ),
    docs_note=(
        "Looks for an ``AWS::S3::BucketPolicy`` joined to the "
        "artifact bucket by ``Bucket`` (literal name or "
        "``{ Ref: <BucketLogicalId> }``). Parses the policy and "
        "scans for any ``Deny`` statement whose ``Condition`` "
        "matches ``aws:SecureTransport = false``."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _s3005_secure_transport(policy, name)
        for name, _, policy in discover_targets(ctx)
    ]
