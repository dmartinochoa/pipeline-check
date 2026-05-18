"""CA-001 (CloudFormation). CodeArtifact domain not CMK-encrypted."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-001",
    title="CodeArtifact domain not encrypted with customer KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``EncryptionKey`` on every "
        "``AWS::CodeArtifact::Domain`` to a customer-managed CMK ARN. "
        "The default AWS-owned key can't be rotated or scoped by IAM."
    ),
    docs_note=(
        "Reads ``AWS::CodeArtifact::Domain.Properties.EncryptionKey``. "
        "An empty value means anyone with ``codeartifact:Read*`` can "
        "read packages — the encryption key isn't a separate "
        "authorization boundary."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-001"]
