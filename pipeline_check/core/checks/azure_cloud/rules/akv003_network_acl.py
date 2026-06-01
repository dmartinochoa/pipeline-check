"""AKV-003. Key Vault allows access from all networks."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="AKV-003",
    title="Key Vault allows access from all networks",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-284",),
    recommendation=(
        "Set the Key Vault firewall default action to 'Deny' and add "
        "explicit network rules for trusted VNets, IPs, or private "
        "endpoints."
    ),
    docs_note=(
        "The default Key Vault firewall allows access from all "
        "networks. Restricting to known VNets and IPs limits the "
        "attack surface for credential theft and key exfiltration."
    ),
    exploit_example=(
        "A Key Vault keeps its firewall default action at 'Allow', so "
        "its data plane is reachable from any IP on the internet rather "
        "than only trusted VNets or private endpoints. The vault still "
        "requires an Azure AD token, but that token is now the only "
        "thing between the public internet and every secret, key, and "
        "certificate it holds. An attacker who steals a credential with "
        "data-plane access (a leaked service-principal secret, a token "
        "lifted from a compromised CI runner) reads the secrets "
        "directly from anywhere, with no need to first gain a foothold "
        "inside the network. A default action of 'Deny' would have "
        "rejected the request at the firewall before the token was even "
        "evaluated."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for vault in catalog.key_vaults():
        name = getattr(vault, "name", "<unnamed>")
        props = getattr(vault, "properties", None)
        network_acls = getattr(props, "network_acls", None) if props else None
        default_action = getattr(network_acls, "default_action", "Allow") if network_acls else "Allow"
        passed = str(default_action).lower() == "deny"
        if passed:
            desc = (
                f"Key Vault '{name}' denies access by default "
                "(network ACL is restrictive)."
            )
        else:
            desc = (
                f"Key Vault '{name}' allows access from all networks. "
                "The firewall default action is 'Allow'."
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
