"""CP-002. CodePipeline artifact store uses default S3 SSE, not a CMK."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CP-002",
    title="Artifact store not encrypted with customer-managed KMS key",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Configure a customer-managed AWS KMS key as the encryptionKey for "
        "each artifact store. This enables key rotation, fine-grained access "
        "policies, and CloudTrail auditing of decrypt operations."
    ),
    docs_note=(
        "The pipeline's S3 artifact store holds intermediate build "
        "outputs handed between stages. Default SSE-S3 (AES256) "
        "encrypts at rest but uses an AWS-owned key whose policy "
        "you can't scope. A customer-managed CMK gives the same "
        "key-policy + CloudTrail Decrypt-event audit story you'd "
        "apply to Lambda code, Secrets Manager, or any other "
        "build output."
    ),
)


def _is_aws_managed_key(enc_key: dict[str, Any]) -> bool:
    """Return True when the encryptionKey refers to an AWS-managed (non-CMK) key.

    CodePipeline stores the key as ``{"type": "KMS", "id": "<alias-or-arn>"}``.
    AWS-managed keys use the ``alias/aws/*`` alias family or, when resolved to
    an ARN, the key ID can match ``aws/`` prefixes.  Checking the ``id`` field
    for these patterns catches both the alias form and the common ARN forms.
    """
    key_id = enc_key.get("id", "") or ""
    # alias/aws/s3, alias/aws/codepipeline, etc.
    if "alias/aws/" in key_id:
        return True
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for pipeline in catalog.codepipeline_pipelines():
        name = pipeline.get("name", "<unnamed>")
        stores: list[dict[str, Any]] = []
        if "artifactStore" in pipeline:
            stores.append(pipeline["artifactStore"])
        stores.extend((pipeline.get("artifactStores") or {}).values())
        not_cmk = [
            s.get("location", "unknown")
            for s in stores
            if "encryptionKey" not in s
            or _is_aws_managed_key(s.get("encryptionKey") or {})
        ]
        passed = not not_cmk
        if passed:
            desc = "All artifact stores use a customer-managed KMS encryption key."
        else:
            desc = (
                f"Artifact store(s) {not_cmk} lack a customer-managed KMS key "
                "(either no encryptionKey is set, or the key is AWS-managed). "
                "This reduces auditability and control over who can decrypt "
                "pipeline artifacts."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
