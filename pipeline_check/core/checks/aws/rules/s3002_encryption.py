"""S3-002. CodePipeline artifact bucket has no default server-side encryption."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="S3-002",
    title="Artifact bucket server-side encryption not configured",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Enable default bucket encryption using at minimum AES256 (SSE-S3). "
        "For stronger key control, use SSE-KMS with a customer-managed key."
    ),
    docs_note=(
        "Default bucket encryption applies SSE-S3 (AES256) to every "
        "PutObject. As of January 2023, AWS enables this on all new "
        "buckets automatically, but existing buckets created before "
        "then can still be unencrypted unless explicitly configured. "
        "Without it, individual objects can be uploaded without "
        "encryption (the client gets to choose)."
    ),
    exploit_example=(
        "# Vulnerable: artifact S3 bucket with no server-side\n"
        "# encryption configured. Build artifacts (binaries,\n"
        "# release tarballs, deploy plans) sit in plaintext;\n"
        "# anyone with ``s3:GetObject`` (or anyone who exfils\n"
        "# the bucket's backups) reads them.\n"
        "import boto3\n"
        "s3 = boto3.client('s3')\n"
        "# Empty / missing encryption config:\n"
        "try:\n"
        "    s3.get_bucket_encryption(Bucket='myorg-build-artifacts')\n"
        "except s3.exceptions.ClientError:\n"
        "    pass   # ServerSideEncryptionConfigurationNotFoundError\n"
        "\n"
        "# Safe: enable bucket-default SSE — AES-256 (SSE-S3)\n"
        "# is the minimum, SSE-KMS with a customer-managed key\n"
        "# adds key-rotation + finer-grained access auditing.\n"
        "s3.put_bucket_encryption(\n"
        "    Bucket='myorg-build-artifacts',\n"
        "    ServerSideEncryptionConfiguration={\n"
        "        'Rules': [{\n"
        "            'ApplyServerSideEncryptionByDefault': {\n"
        "                'SSEAlgorithm': 'aws:kms',\n"
        "                'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123:key/abc-...'\n"
        "            },\n"
        "            'BucketKeyEnabled': True,\n"
        "        }]\n"
        "    }\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    buckets = catalog.s3_artifact_buckets()
    if not buckets:
        return findings
    s3 = catalog.client("s3")
    for bucket in buckets:
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket)
            rules = (
                resp.get("ServerSideEncryptionConfiguration", {})
                .get("Rules", [])
            )
            encrypted = len(rules) > 0
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchBucket",
            ):
                encrypted = False
                rules = []
            else:
                findings.append(Finding(
                    check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                    resource=bucket,
                    description=f"Could not retrieve bucket encryption config: {exc}",
                    recommendation="Ensure s3:GetEncryptionConfiguration permission.",
                    passed=False,
                ))
                continue
        if encrypted:
            algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get(
                "SSEAlgorithm", "unknown"
            )
            desc = f"Artifact bucket is encrypted with {algo}."
        else:
            desc = (
                "No default server-side encryption is configured on the artifact "
                "bucket. Pipeline artifacts (source zips, compiled binaries) are "
                "stored unencrypted at rest."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=bucket, description=desc,
            recommendation=RULE.recommendation, passed=encrypted,
        ))
    return findings
