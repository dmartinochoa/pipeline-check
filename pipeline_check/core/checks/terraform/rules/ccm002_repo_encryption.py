"""CCM-002 (Terraform). CodeCommit repository not CMK-encrypted."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _codecommit

RULE = Rule(
    id="CCM-002",
    title="CodeCommit repository not encrypted with customer KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``kms_key_id`` on every ``aws_codecommit_repository`` to "
        "a customer-managed CMK ARN. Source code carries IP, "
        "credentials, and customer data — the encryption boundary "
        "matters."
    ),
    docs_note=(
        "Reads ``aws_codecommit_repository.kms_key_id``. Empty values "
        "fall back to AWS-owned encryption, which can't be audited or "
        "scoped to a specific role via key policy."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codecommit(ctx) if f.check_id == "CCM-002"]
