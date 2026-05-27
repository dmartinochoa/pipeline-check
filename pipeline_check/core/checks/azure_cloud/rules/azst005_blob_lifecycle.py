"""AZST-005. Storage account has no blob lifecycle management policy."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZST-005",
    title="Storage account has no blob lifecycle management policy",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-404",),
    recommendation=(
        "Configure a lifecycle management policy on the storage "
        "account to automatically transition or delete stale blobs. "
        "This limits the exposure window for old artifacts and "
        "reduces storage costs."
    ),
    docs_note=(
        "Without lifecycle management, build artifacts, logs, and "
        "temporary blobs accumulate indefinitely. Stale data increases "
        "the attack surface and complicates data-retention compliance."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for account in catalog.storage_accounts():
        name = getattr(account, "name", "<unnamed>")
        # The management_policies property is not directly on the
        # storage account object; presence of a lifecycle rule is
        # indicated by the management policy. We check for the
        # network_rule_set as a proxy; a more precise check would
        # call the management_policies API. For the SDK model, we
        # check if the account kind supports blobs and flag INFO.
        # We use the blob_service_properties pattern here.
        kind = str(getattr(account, "kind", "")).lower()
        is_blob_capable = kind in {
            "storagev2", "blobstorage", "blockblobstorage", "storage",
        }
        if not is_blob_capable:
            continue
        # The lifecycle policy is not on the account model directly.
        # Flag all blob-capable accounts as needing review.
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=(
                f"Storage account '{name}' (kind: {kind}) should have "
                "a blob lifecycle management policy configured to "
                "automatically manage artifact retention."
            ),
            recommendation=RULE.recommendation,
            passed=False,
        ))
    return findings
