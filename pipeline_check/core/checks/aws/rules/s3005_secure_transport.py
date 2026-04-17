"""S3-005 — CodePipeline artifact bucket policy missing aws:SecureTransport Deny."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="S3-005",
    title="Artifact bucket missing aws:SecureTransport deny",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Add a Deny statement for s3:* with Bool "
        "aws:SecureTransport=false."
    ),
)


def _policy_denies_insecure_transport(doc: dict) -> bool:
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Deny":
            continue
        cond = stmt.get("Condition", {}) or {}
        for operator_block in cond.values():
            if not isinstance(operator_block, dict):
                continue
            if str(operator_block.get("aws:SecureTransport", "")).lower() == "false":
                return True
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    buckets = catalog.s3_artifact_buckets()
    if not buckets:
        return findings
    s3 = catalog.client("s3")
    for bucket in buckets:
        try:
            resp = s3.get_bucket_policy(Bucket=bucket)
            doc = json.loads(resp.get("Policy", "{}"))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchBucketPolicy", "NoSuchBucket"):
                findings.append(Finding(
                    check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                    resource=bucket,
                    description=(
                        "No bucket policy is attached — plaintext HTTP requests "
                        "are not explicitly denied."
                    ),
                    recommendation=(
                        "Attach a bucket policy with a Deny for s3:* when "
                        "aws:SecureTransport is false."
                    ),
                    passed=False,
                ))
                continue
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=bucket,
                description=f"Could not retrieve bucket policy: {exc}",
                recommendation="Ensure s3:GetBucketPolicy permission.",
                passed=False,
            ))
            continue
        except (ValueError, json.JSONDecodeError):
            doc = {}

        has_deny = _policy_denies_insecure_transport(doc)
        desc = (
            "Bucket policy denies non-TLS requests via aws:SecureTransport."
            if has_deny else
            "Bucket policy does not Deny requests where aws:SecureTransport is false."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=bucket, description=desc,
            recommendation=RULE.recommendation, passed=has_deny,
        ))
    return findings
