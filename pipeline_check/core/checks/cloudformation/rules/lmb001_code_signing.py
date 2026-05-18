"""LMB-001 (CloudFormation). Lambda has no CodeSigningConfigArn."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..services import _lambda

RULE = Rule(
    id="LMB-001",
    title="Lambda function has no code-signing config",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-345",),
    recommendation=(
        "Set ``CodeSigningConfigArn`` on every "
        "``AWS::Lambda::Function`` to an "
        "``AWS::Lambda::CodeSigningConfig`` whose allowed publishers "
        "list signing profiles your release pipeline uses."
    ),
    docs_note=(
        "Reads ``AWS::Lambda::Function.Properties.CodeSigningConfigArn``. "
        "Without it, Lambda accepts any zip the deployer can upload "
        "— there's no cryptographic check that the artifact came "
        "from the expected pipeline."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [f for f in _lambda(ctx) if f.check_id == "LMB-001"]
