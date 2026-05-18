"""SIGN-001 (CloudFormation). No Signer profile for Lambda code signing."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase4 import _sign001

RULE = Rule(
    id="SIGN-001",
    title="No active AWS Signer profile exists for the Lambda platform",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-345",),
    recommendation=(
        "Declare an ``AWS::Signer::SigningProfile`` with "
        "``PlatformId: AWSLambda-SHA384-ECDSA`` and reference it "
        "from an ``AWS::Lambda::CodeSigningConfig``. Without one, "
        "Lambda code signing has no signer to validate against "
        "(see LMB-001)."
    ),
    docs_note=(
        "Gated check: fires only when an ``AWS::Lambda::Function`` "
        "references ``CodeSigningConfigArn``. Passes when at least "
        "one ``AWS::Signer::SigningProfile`` with ``PlatformId`` "
        "starting with ``AWSLambda-`` exists in the template."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _sign001(ctx)
