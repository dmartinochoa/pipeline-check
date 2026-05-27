"""KMS-002 (Terraform). KMS key policy grants kms:* to a principal."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..services import _kms

RULE = Rule(
    id="KMS-002",
    title="KMS key policy grants kms:* to an IAM principal",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Enumerate the specific KMS actions each principal needs "
        "(``kms:Encrypt``, ``kms:Decrypt``, ``kms:GenerateDataKey``, "
        "``kms:DescribeKey``). Reserve ``kms:*`` for the root "
        "principal that owns the key."
    ),
    docs_note=(
        "Parses ``aws_kms_key.policy`` (or "
        "``aws_kms_key_policy.policy``). Fires on any ``Allow`` "
        "statement that pairs ``kms:*`` with a non-root IAM "
        "principal — that's the canonical key-compromise primitive."
    ),
    exploit_example=(
        "# Vulnerable: KMS key policy grants all actions to\n"
        "# every AWS principal. Any account can decrypt data.\n"
        'resource "aws_kms_key" "artifacts" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "kms:*"\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n"
        "\n"
        "# Safe: scope to the owning account.\n"
        'resource "aws_kms_key" "artifacts" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "arn:aws:iam::123456789012:root" }\n'
        '      Action    = "kms:*"\n'
        '      Resource  = "*"\n'
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return [f for f in _kms(ctx) if f.check_id == "KMS-002"]
