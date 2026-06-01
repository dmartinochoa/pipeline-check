"""S3-005 (Terraform). Pipeline artifact bucket has no SecureTransport deny."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..s3 import _s3005_secure_transport
from ._s3_context import artifact_buckets, index_by_bucket

RULE = Rule(
    id="S3-005",
    title="Artifact bucket missing aws:SecureTransport deny",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Attach an ``aws_s3_bucket_policy`` carrying a "
        "``Deny`` statement on ``Action: \"s3:*\"`` when "
        "``Bool aws:SecureTransport = false``. Validate the policy "
        "with Access Analyzer before applying."
    ),
    docs_note=(
        "Joins ``aws_s3_bucket_policy`` by ``bucket`` for every "
        "pipeline artifact bucket. Parses ``policy`` JSON and looks "
        "for any ``Deny`` statement whose ``Condition`` matches "
        "``aws:SecureTransport = false``. Without it, plaintext HTTP "
        "reads and writes still succeed."
    ),
    exploit_example=(
        "# Vulnerable: a pipeline artifact bucket with no policy denying\n"
        "# plaintext transport.\n"
        "resource \"aws_s3_bucket\" \"artifacts\" {\n"
        "  bucket = \"my-pipeline-artifacts\"\n"
        "}\n"
        "# (no aws_s3_bucket_policy is attached)\n"
        "\n"
        "# Attack: S3 still answers plaintext HTTP for this bucket, so a\n"
        "# build or deploy that fetches an artifact over http:// (a proxy\n"
        "# downgrade, a hardcoded endpoint) exposes it to an on-path\n"
        "# attacker, who reads the artifact or swaps the build output for\n"
        "# a trojaned one before it reaches the next stage.\n"
        "\n"
        "# Safe: deny every S3 action when the request did not arrive\n"
        "# over TLS.\n"
        "resource \"aws_s3_bucket_policy\" \"artifacts\" {\n"
        "  bucket = aws_s3_bucket.artifacts.id\n"
        "  policy = jsonencode({\n"
        "    Version = \"2012-10-17\"\n"
        "    Statement = [{\n"
        "      Effect    = \"Deny\"\n"
        "      Principal = \"*\"\n"
        "      Action    = \"s3:*\"\n"
        "      Resource = [\n"
        "        aws_s3_bucket.artifacts.arn,\n"
        "        \"${aws_s3_bucket.artifacts.arn}/*\",\n"
        "      ]\n"
        "      Condition = { Bool = { \"aws:SecureTransport\" = \"false\" } }\n"
        "    }]\n"
        "  })\n"
        "}"
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    buckets = artifact_buckets(ctx)
    pol = index_by_bucket(ctx, "aws_s3_bucket_policy")
    return [_s3005_secure_transport(pol.get(b), b) for b in sorted(buckets)]
