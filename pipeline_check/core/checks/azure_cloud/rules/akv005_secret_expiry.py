"""AKV-005. Key Vault secret has no expiration date."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AKV-005",
    title="Key Vault secret has no expiration date",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-324",),
    recommendation=(
        "Set an expiration date on all Key Vault secrets. Use "
        "automated rotation (Azure Key Vault rotation policies or "
        "Event Grid triggers) to rotate secrets before expiration."
    ),
    docs_note=(
        "Secrets without an expiration date never trigger rotation. "
        "A leaked API key or connection string stored without expiry "
        "remains usable until someone manually disables it."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vault in catalog.key_vaults():
        vault_name = getattr(vault, "name", "<unnamed>")
        secrets = catalog.key_vault_secrets(vault_name)
        for secret in secrets:
            sid = secret.get("id", "<unknown>")
            secret_id = sid.rsplit("/", 1)[-1] if "/" in sid else sid
            attrs = secret.get("attributes", {})
            exp = attrs.get("exp")
            enabled = attrs.get("enabled", True)
            if not enabled:
                continue
            passed = exp is not None
            if passed:
                desc = (
                    f"Secret '{secret_id}' in vault '{vault_name}' has "
                    "an expiration date set."
                )
            else:
                desc = (
                    f"Secret '{secret_id}' in vault '{vault_name}' has "
                    "no expiration date. The secret remains valid "
                    "indefinitely if leaked."
                )
            findings.append(Finding(
                check_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                resource=f"{vault_name}/{secret_id}",
                description=desc,
                recommendation=RULE.recommendation,
                passed=passed,
            ))
    return findings
