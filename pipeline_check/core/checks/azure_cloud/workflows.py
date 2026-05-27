"""Azure Cloud rule orchestrator, runs every rule under ``azure_cloud/rules/``."""
from __future__ import annotations

from ..base import Finding, Severity
from ..rule import apply_rule_metadata, discover_rules
from ._catalog import ResourceCatalog
from ._session import AzureCloudSession
from .base import AzureCloudBaseCheck

_RULE_PREFIX_TO_SERVICE: dict[str, str] = {
    "ENTRA": "entra",
    "AZST": "storage",
    "AKV": "keyvault",
    "ACR": "acr",
    "AZMON": "monitor",
    "AZNW": "network",
    "AZAPP": "appservice",
    "AZSQL": "sql",
    "AZVM": "compute",
}

_DEGRADED: dict[str, tuple[str, str, str]] = {
    "entra": (
        "ENTRA-000",
        "Entra ID",
        "Ensure the credential has Directory.Read.All (MS Graph) "
        "permission for Entra ID checks.",
    ),
    "storage": (
        "AZST-000",
        "Azure Storage",
        "Ensure the credential has Reader role and "
        "Microsoft.Storage/storageAccounts/read permission.",
    ),
    "keyvault": (
        "AKV-000",
        "Azure Key Vault",
        "Ensure the credential has Reader role and "
        "Microsoft.KeyVault/vaults/read permission.",
    ),
    "acr": (
        "ACR-000",
        "Azure Container Registry",
        "Ensure the credential has Reader role and "
        "Microsoft.ContainerRegistry/registries/read permission.",
    ),
    "monitor": (
        "AZMON-000",
        "Azure Monitor",
        "Ensure the credential has Reader role and "
        "Microsoft.Insights/diagnosticSettings/read permission.",
    ),
    "authorization": (
        "ENTRA-000",
        "Azure Authorization",
        "Ensure the credential has Reader role and "
        "Microsoft.Authorization/roleAssignments/read permission.",
    ),
    "network": (
        "AZNW-000",
        "Azure Network",
        "Ensure the credential has Reader role and "
        "Microsoft.Network/networkSecurityGroups/read permission.",
    ),
    "appservice": (
        "AZAPP-000",
        "Azure App Service",
        "Ensure the credential has Reader role and "
        "Microsoft.Web/sites/read permission.",
    ),
    "sql": (
        "AZSQL-000",
        "Azure SQL Database",
        "Ensure the credential has Reader role and "
        "Microsoft.Sql/servers/read permission.",
    ),
    "compute": (
        "AZVM-000",
        "Azure Compute",
        "Ensure the credential has Reader role and "
        "Microsoft.Compute/virtualMachines/read permission.",
    ),
}


class AzureCloudRuleChecks(AzureCloudBaseCheck):
    """Runs every rule under ``pipeline_check.core.checks.azure_cloud.rules``."""

    def __init__(
        self, session: AzureCloudSession, target: str | None = None,
    ) -> None:
        super().__init__(session, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.azure_cloud.rules",
        )

    def run(self) -> list[Finding]:
        catalog = ResourceCatalog(self.session)
        pending: list[tuple[str, list[Finding]]] = []
        for rule, check_fn in self._rules:
            try:
                batch = check_fn(catalog) or []
            except Exception as exc:
                prefix = rule.id.split("-", 1)[0]
                svc = _RULE_PREFIX_TO_SERVICE.get(prefix, prefix.lower())
                catalog.errors.setdefault(
                    svc, f"{type(exc).__name__}: {exc}",
                )
                continue
            for finding in batch:
                apply_rule_metadata(finding, rule)
            pending.append((rule.id, batch))

        findings: list[Finding] = []
        degraded_services = set(catalog.errors)
        for rule_id, batch in pending:
            prefix = rule_id.split("-", 1)[0]
            svc = _RULE_PREFIX_TO_SERVICE.get(prefix)
            if svc in degraded_services:
                continue
            findings.extend(batch)

        for svc, msg in catalog.errors.items():
            meta = _DEGRADED.get(svc)
            if meta is None:
                continue
            check_id, label, recommendation = meta
            findings.append(Finding(
                check_id=check_id,
                title=f"{label} API access failed",
                severity=Severity.INFO,
                resource=label,
                description=(
                    f"Could not enumerate {label} resources: {msg}. "
                    "Rules depending on this data were skipped."
                ),
                recommendation=recommendation,
                passed=False,
            ))
        return findings
