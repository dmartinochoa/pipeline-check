"""GCCE-002. Compute instance does not have OS Login enabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="GCCE-002",
    title="Compute instance does not have OS Login enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Set the metadata key 'enable-oslogin' to 'TRUE' on every "
        "instance (or at the project level). OS Login ties SSH "
        "access to IAM, removing the need to manage SSH keys."
    ),
    docs_note=(
        "OS Login uses IAM to manage SSH access to instances instead "
        "of SSH keys stored in project or instance metadata. Without "
        "it, anyone who can edit metadata can inject an SSH key and "
        "gain shell access."
    ),
)


# The GCE guest environment accepts several boolean spellings for the
# ``enable-oslogin`` metadata value, all case-insensitive.
_OSLOGIN_TRUTHY = frozenset({"true", "1", "y", "yes"})


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for inst in catalog.compute_instances():
        name = inst.get("name", "<unnamed>")
        metadata = inst.get("metadata", {})
        os_login = str(metadata.get("enable-oslogin", "")).strip().lower()
        if os_login in _OSLOGIN_TRUTHY:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' has OS Login enabled."
                ),
                recommendation=RULE.recommendation,
                passed=True,
            ))
        else:
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=name,
                description=(
                    f"Instance '{name}' does not have OS Login "
                    "enabled. SSH access is managed through metadata "
                    "keys instead of IAM."
                ),
                recommendation=RULE.recommendation,
                passed=False,
            ))
    return findings
