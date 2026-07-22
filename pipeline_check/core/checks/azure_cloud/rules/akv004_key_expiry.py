"""AKV-004. Key Vault key has no expiration date."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AKV-004",
    title="Key Vault key has no expiration date",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-324",),
    recommendation=(
        "Set an expiration date on all Key Vault keys. Rotate keys "
        "before expiration using automated rotation policies. Keys "
        "without expiration remain valid indefinitely if compromised."
    ),
    docs_note=(
        "Keys without an expiration date never trigger rotation "
        "reminders or policy violations. A compromised key stays "
        "valid until manually revoked, widening the blast radius."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vault in catalog.key_vaults():
        vault_name = getattr(vault, "name", "<unnamed>")
        keys = catalog.key_vault_keys(vault_name)
        for key in keys:
            kid = key.get("kid") or "<unknown>"
            key_id = kid.rsplit("/", 1)[-1] if "/" in kid else kid
            attrs = key.get("attributes", {})
            exp = attrs.get("exp")
            enabled = attrs.get("enabled", True)
            if not enabled:
                continue
            passed = exp is not None
            if passed:
                desc = (
                    f"Key '{key_id}' in vault '{vault_name}' has an "
                    "expiration date set."
                )
            else:
                desc = (
                    f"Key '{key_id}' in vault '{vault_name}' has no "
                    "expiration date. The key remains valid "
                    "indefinitely if compromised."
                )
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=f"{vault_name}/{key_id}",
                description=desc,
                recommendation=RULE.recommendation,
                passed=passed,
            ))
    return findings
