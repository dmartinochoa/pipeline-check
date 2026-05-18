"""CA-001 (Terraform). CodeArtifact domain not encrypted with CMK."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _codeartifact

RULE = Rule(
    id="CA-001",
    title="CodeArtifact domain not encrypted with customer KMS CMK",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Set ``encryption_key`` on every ``aws_codeartifact_domain`` "
        "to a customer-managed KMS CMK ARN. The default AWS-owned key "
        "can't be rotated or scoped by IAM policy."
    ),
    docs_note=(
        "Reads ``aws_codeartifact_domain.encryption_key``. An empty "
        "value (or the default AWS-managed key) means anyone with "
        "``codeartifact:Read*`` can read packages — the encryption "
        "key isn't a separate authorization boundary."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _codeartifact(ctx) if f.check_id == "CA-001"]
