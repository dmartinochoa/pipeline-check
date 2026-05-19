"""KMS-001 (CloudFormation). KMS key has rotation disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _kms

RULE = Rule(
    id="KMS-001",
    title="Customer-managed symmetric KMS key has rotation disabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-322",),
    recommendation=(
        "Set ``EnableKeyRotation: true`` on every symmetric "
        "``AWS::KMS::Key``. KMS rotates the underlying key material "
        "once per year transparently, no downstream change is "
        "needed."
    ),
    docs_note=(
        "Reads ``AWS::KMS::Key.Properties.EnableKeyRotation`` on "
        "symmetric keys (``KeySpec`` = ``SYMMETRIC_DEFAULT`` or "
        "absent). Asymmetric keys are skipped — KMS doesn't rotate "
        "them, key replacement is the only path."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _kms(ctx) if f.check_id == "KMS-001"]
