"""AZVM-001. VM disks not encrypted with a customer-managed key / ADE."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AZVM-001",
    title="VM disks not encrypted with a customer-managed key or ADE",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-311",),
    recommendation=(
        "Enable Azure Disk Encryption (ADE) or server-side "
        "encryption with customer-managed keys on all VM OS and "
        "data disks. This protects data at rest from offline "
        "attacks on the underlying storage."
    ),
    docs_note=(
        "All Azure managed disks are SSE-encrypted at rest with "
        "platform-managed keys by default; this rule checks for the "
        "stronger customer-managed key (disk encryption set) or Azure "
        "Disk Encryption (ADE), which keep the key outside Azure's "
        "default control. A disk with neither can be read by an "
        "attacker who compromises the platform key path or the "
        "storage backing the VHD, including pipeline agent credentials "
        "and build artifacts."
    ),
    exploit_example=(
        "An attacker with storage account access snapshots an "
        "unencrypted CI agent VM disk, mounts it externally, and "
        "extracts SSH keys, pipeline tokens, and cached build "
        "secrets."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vm in catalog.virtual_machines():
        name = getattr(vm, "name", "<unnamed>")
        storage_profile = getattr(vm, "storage_profile", None)
        unencrypted_disks: list[str] = []

        # Check OS disk.
        os_disk = getattr(storage_profile, "os_disk", None) if storage_profile else None
        if os_disk:
            encryption = getattr(os_disk, "managed_disk", None)
            enc_settings = getattr(os_disk, "encryption_settings", None)
            disk_enc_set = getattr(
                getattr(encryption, "disk_encryption_set", None),
                "id", None,
            ) if encryption else None
            enc_enabled = getattr(enc_settings, "enabled", False) if enc_settings else False
            if not disk_enc_set and not enc_enabled:
                unencrypted_disks.append("OS disk")

        # Check data disks.
        data_disks = getattr(storage_profile, "data_disks", []) if storage_profile else []
        for dd in data_disks or []:
            dd_name = getattr(dd, "name", "data disk")
            encryption = getattr(dd, "managed_disk", None)
            disk_enc_set = getattr(
                getattr(encryption, "disk_encryption_set", None),
                "id", None,
            ) if encryption else None
            if not disk_enc_set:
                unencrypted_disks.append(dd_name)

        passed = len(unencrypted_disks) == 0
        if passed:
            desc = (
                f"VM '{name}' has all disks encrypted with a "
                "customer-managed key or Azure Disk Encryption."
            )
        else:
            desc = (
                f"VM '{name}' has disks without a customer-managed key "
                f"or Azure Disk Encryption (platform-managed SSE only): "
                f"{', '.join(unencrypted_disks)}."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=name,
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
