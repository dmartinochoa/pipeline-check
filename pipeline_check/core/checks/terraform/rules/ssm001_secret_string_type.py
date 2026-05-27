"""SSM-001 (Terraform). SSM parameter stores a secret as String."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _ssm

RULE = Rule(
    id="SSM-001",
    title="SSM parameter with secret-like name stored as String, not SecureString",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-312",),
    recommendation=(
        "Set ``type = \"SecureString\"`` on every ``aws_ssm_parameter`` "
        "whose name or value looks secret-like. SecureString parameters "
        "are encrypted with KMS and audited separately from plain "
        "``GetParameter`` access."
    ),
    docs_note=(
        "Checks ``aws_ssm_parameter.name`` against the standard "
        "secret-name regex (``PASSWORD``, ``TOKEN``, ``API_KEY``, …). "
        "If the name matches and ``type`` is ``String`` (the default), "
        "the value is stored in plaintext, visible to anyone with "
        "``ssm:GetParameter``."
    ),
    exploit_example=(
        "# Vulnerable: secret stored as SSM String (plaintext).\n"
        "# Readable by anyone with ssm:GetParameter; no\n"
        "# encryption at rest beyond the default EBS key.\n"
        'resource "aws_ssm_parameter" "token" {\n'
        '  name  = "/ci/deploy-token"\n'
        '  type  = "String"\n'
        '  value = "ghp_exampletoken123456"\n'
        "}\n"
        "\n"
        "# Safe: use SecureString (encrypted with KMS).\n"
        'resource "aws_ssm_parameter" "token" {\n'
        '  name  = "/ci/deploy-token"\n'
        '  type  = "SecureString"\n'
        '  value = "ghp_exampletoken123456"\n'
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _ssm(ctx) if f.check_id == "SSM-001"]
