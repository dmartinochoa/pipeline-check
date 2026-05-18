"""SIGN-001 (Terraform). No Signer profile for Lambda code signing."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase4 import _sign001

RULE = Rule(
    id="SIGN-001",
    title="No active AWS Signer profile exists for the Lambda platform",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-345",),
    recommendation=(
        "Declare an ``aws_signer_signing_profile`` with "
        "``platform_id = \"AWSLambda-SHA384-ECDSA\"`` and reference it "
        "from an ``aws_lambda_code_signing_config``. Without one, the "
        "Lambda code-signing config can't be wired (see LMB-001)."
    ),
    docs_note=(
        "Gated check: fires only when a ``aws_lambda_function`` "
        "references ``code_signing_config_arn``. Passes when at least "
        "one ``aws_signer_signing_profile`` with ``platform_id`` "
        "starting with ``AWSLambda-`` exists in the plan."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _sign001(ctx)
