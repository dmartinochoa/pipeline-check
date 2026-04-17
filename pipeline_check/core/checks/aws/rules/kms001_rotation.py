"""KMS-001 — KMS customer-managed key has rotation disabled."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="KMS-001",
    title="KMS customer-managed key has rotation disabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-321",),
    recommendation=(
        "Enable annual rotation on every customer-managed KMS key used for "
        "CI/CD artifact, log, and secret encryption. Unrotated CMKs keep "
        "the same key material indefinitely, so a single cryptographic "
        "exposure (side-channel, accidental export) is permanent."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("kms")
    for key in catalog.kms_keys():
        if key.get("KeySpec", "") != "SYMMETRIC_DEFAULT":
            # Rotation isn't available for asymmetric/HMAC keys.
            continue
        arn = key.get("Arn", key.get("KeyId", "<unknown>"))
        try:
            resp = client.get_key_rotation_status(KeyId=key["KeyId"])
        except ClientError:
            continue
        enabled = bool(resp.get("KeyRotationEnabled"))
        desc = (
            f"Key {arn} has automatic rotation enabled."
            if enabled else
            f"Key {arn} has automatic rotation disabled."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=arn, description=desc,
            recommendation=RULE.recommendation, passed=enabled,
        ))
    return findings
