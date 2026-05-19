"""CCM-003 (Terraform). CodeCommit trigger targets cross-account."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _codecommit

RULE = Rule(
    id="CCM-003",
    title="CodeCommit trigger targets SNS/Lambda in a different account",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-942",),
    recommendation=(
        "Point ``aws_codecommit_trigger.destination_arn`` at an SNS "
        "topic or Lambda function in the same account. If "
        "cross-account is intentional, document the receiving account "
        "in your threat model and baseline this finding."
    ),
    docs_note=(
        "Compares ``aws_codecommit_trigger.destination_arn`` against "
        "the current account ID (from ``aws_caller_identity`` data "
        "source). A trigger whose destination lives in another account "
        "leaks repository activity outside the trust boundary."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codecommit(ctx) if f.check_id == "CCM-003"]
