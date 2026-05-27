"""Shared Azure Cloud resource catalog.

Every rule under ``pipeline_check.core.checks.azure_cloud.rules`` receives
a :class:`ResourceCatalog` rather than a bare session.  The catalog
enumerates each Azure resource type at most once per scan and caches
the result so multiple rules checking the same service don't repeat
API calls.

Each catalog method returns a (possibly empty) list on success.  On API
failure the error is recorded against a service tag so the orchestrator
can emit a single ``<PREFIX>-000`` degraded finding per service.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ._session import AzureCloudSession


class ResourceCatalog:
    """Lazy, caching facade over the Azure management APIs."""

    def __init__(self, session: AzureCloudSession) -> None:
        self.session = session
        self.errors: dict[str, str] = {}
        self._cache: dict[str, Any] = {}
        self._clients: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Client access
    # ------------------------------------------------------------------

    def mgmt_client(self, client_class: type, **kwargs: Any) -> Any:
        """Return a cached management client instance."""
        key = client_class.__name__
        if key not in self._clients:
            self._clients[key] = client_class(
                credential=self.session.credential,
                subscription_id=self.session.subscription_id,
                **kwargs,
            )
        return self._clients[key]

    # ------------------------------------------------------------------
    # Cache primitive
    # ------------------------------------------------------------------

    def _memo(self, key: str, loader: Callable[[], Any]) -> Any:
        if key in self._cache:
            return self._cache[key]
        try:
            value = loader()
        except Exception as exc:
            svc = key.split(":", 1)[0]
            self.errors.setdefault(svc, f"{type(exc).__name__}: {exc}")
            value = []
        self._cache[key] = value
        return value

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def storage_accounts(self) -> list[Any]:
        """Return every storage account in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.storage import StorageManagementClient
            client = self.mgmt_client(StorageManagementClient)
            return list(client.storage_accounts.list())
        return self._memo("storage:accounts", _load)

    # ------------------------------------------------------------------
    # Key Vault
    # ------------------------------------------------------------------

    def key_vaults(self) -> list[Any]:
        """Return every Key Vault in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            client = self.mgmt_client(KeyVaultManagementClient)
            return list(client.vaults.list_by_subscription())
        return self._memo("keyvault:vaults", _load)

    # ------------------------------------------------------------------
    # Container Registry
    # ------------------------------------------------------------------

    def container_registries(self) -> list[Any]:
        """Return every ACR registry in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.containerregistry import ContainerRegistryManagementClient
            client = self.mgmt_client(ContainerRegistryManagementClient)
            return list(client.registries.list())
        return self._memo("acr:registries", _load)

    # ------------------------------------------------------------------
    # Monitor
    # ------------------------------------------------------------------

    def diagnostic_settings(self) -> list[Any]:
        """Return subscription-level diagnostic settings."""
        def _load() -> list[Any]:
            from azure.mgmt.monitor import MonitorManagementClient
            client = self.mgmt_client(MonitorManagementClient)
            resource_uri = (
                f"/subscriptions/{self.session.subscription_id}"
            )
            return list(
                client.diagnostic_settings.list(resource_uri=resource_uri)
            )
        return self._memo("monitor:diagnostic_settings", _load)

    def activity_log_alerts(self) -> list[Any]:
        """Return all activity log alert rules in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.monitor import MonitorManagementClient
            client = self.mgmt_client(MonitorManagementClient)
            return list(
                client.activity_log_alerts.list_by_subscription_id()
            )
        return self._memo("monitor:activity_log_alerts", _load)

    # ------------------------------------------------------------------
    # Authorization (RBAC)
    # ------------------------------------------------------------------

    def role_assignments(self) -> list[Any]:
        """Return all role assignments in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.authorization import AuthorizationManagementClient
            client = self.mgmt_client(AuthorizationManagementClient)
            return list(client.role_assignments.list())
        return self._memo("authorization:role_assignments", _load)

    def role_definitions(self) -> dict[str, Any]:
        """Return role definitions keyed by role definition ID."""
        def _load() -> dict[str, Any]:
            from azure.mgmt.authorization import AuthorizationManagementClient
            client = self.mgmt_client(AuthorizationManagementClient)
            scope = f"/subscriptions/{self.session.subscription_id}"
            defs = {}
            for rd in client.role_definitions.list(scope=scope):
                defs[rd.id] = rd
            return defs
        return self._memo("authorization:role_definitions", _load)

    # ------------------------------------------------------------------
    # MS Graph (Entra ID) — REST-based, no azure-mgmt dependency
    # ------------------------------------------------------------------

    def _graph_get(self, path: str) -> list[dict[str, Any]]:
        """Paginated GET against the MS Graph v1.0 endpoint."""
        import requests

        token = self.session.credential.get_token(
            "https://graph.microsoft.com/.default"
        )
        headers = {"Authorization": f"Bearer {token.token}"}
        url = f"https://graph.microsoft.com/v1.0{path}"
        items: list[dict[str, Any]] = []
        while url:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return items

    def applications(self) -> list[dict[str, Any]]:
        """Return all app registrations from MS Graph."""
        def _load() -> list[dict[str, Any]]:
            return self._graph_get("/applications")
        return self._memo("entra:applications", _load)

    def service_principals(self) -> list[dict[str, Any]]:
        """Return all service principals from MS Graph."""
        def _load() -> list[dict[str, Any]]:
            return self._graph_get("/servicePrincipals")
        return self._memo("entra:service_principals", _load)

    def conditional_access_policies(self) -> list[dict[str, Any]]:
        """Return all Conditional Access policies from MS Graph."""
        def _load() -> list[dict[str, Any]]:
            return self._graph_get(
                "/identity/conditionalAccess/policies",
            )
        return self._memo("entra:conditional_access", _load)

    # ------------------------------------------------------------------
    # Key Vault data-plane
    # ------------------------------------------------------------------

    def _vault_data_get(
        self, vault_name: str, collection: str,
    ) -> list[dict[str, Any]]:
        """Paginated GET against a Key Vault data-plane endpoint."""
        import requests

        vault_uri = f"https://{vault_name}.vault.azure.net"
        token = self.session.credential.get_token(
            "https://vault.azure.net/.default",
        )
        headers = {"Authorization": f"Bearer {token.token}"}
        url = f"{vault_uri}/{collection}?api-version=7.4"
        items: list[dict[str, Any]] = []
        while url:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            items.extend(data.get("value", []))
            url = data.get("nextLink")
        return items

    def key_vault_keys(self, vault_name: str) -> list[dict[str, Any]]:
        """Return keys from a Key Vault data-plane endpoint."""
        def _load() -> list[dict[str, Any]]:
            return self._vault_data_get(vault_name, "keys")
        return self._memo(f"keyvault:keys:{vault_name}", _load)

    def key_vault_secrets(self, vault_name: str) -> list[dict[str, Any]]:
        """Return secrets from a Key Vault data-plane endpoint."""
        def _load() -> list[dict[str, Any]]:
            return self._vault_data_get(vault_name, "secrets")
        return self._memo(f"keyvault:secrets:{vault_name}", _load)

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def network_security_groups(self) -> list[Any]:
        """Return every NSG in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.network import NetworkManagementClient
            client = self.mgmt_client(NetworkManagementClient)
            return list(client.network_security_groups.list_all())
        return self._memo("network:nsgs", _load)

    def nsg_flow_logs(self) -> list[Any]:
        """Return NSG flow log configurations.

        Flow logs are a Network Watcher resource.  We enumerate all
        flow logs across every Network Watcher in the subscription.
        """
        def _load() -> list[Any]:
            from azure.mgmt.network import NetworkManagementClient
            client = self.mgmt_client(NetworkManagementClient)
            logs: list[Any] = []
            for watcher in client.network_watchers.list_all():
                rg = getattr(watcher, "id", "").split("/")[4] if getattr(watcher, "id", "") else None
                watcher_name = getattr(watcher, "name", None)
                if rg and watcher_name:
                    try:
                        for fl in client.flow_logs.list(rg, watcher_name):
                            logs.append(fl)
                    except Exception:
                        pass
            return logs
        return self._memo("network:flow_logs", _load)

    def application_gateways(self) -> list[Any]:
        """Return every Application Gateway in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.network import NetworkManagementClient
            client = self.mgmt_client(NetworkManagementClient)
            return list(client.application_gateways.list_all())
        return self._memo("network:app_gateways", _load)

    def public_ip_addresses(self) -> list[Any]:
        """Return every public IP address in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.network import NetworkManagementClient
            client = self.mgmt_client(NetworkManagementClient)
            return list(client.public_ip_addresses.list_all())
        return self._memo("network:public_ips", _load)

    # ------------------------------------------------------------------
    # App Service
    # ------------------------------------------------------------------

    def web_apps(self) -> list[dict[str, Any]]:
        """Return web apps with embedded site configuration.

        Each dict has ``app`` (the site object) and ``config`` (the
        ``SiteConfig`` from ``get_configuration``).  This avoids an
        N+1 query pattern in individual rules.
        """
        def _load() -> list[dict[str, Any]]:
            from azure.mgmt.web import WebSiteManagementClient
            client = self.mgmt_client(WebSiteManagementClient)
            results: list[dict[str, Any]] = []
            for app in client.web_apps.list():
                rg = getattr(app, "resource_group", None)
                app_name = getattr(app, "name", None)
                config = None
                if rg and app_name:
                    try:
                        config = client.web_apps.get_configuration(
                            rg, app_name,
                        )
                    except Exception:
                        pass
                results.append({"app": app, "config": config})
            return results
        return self._memo("appservice:web_apps", _load)

    # ------------------------------------------------------------------
    # SQL
    # ------------------------------------------------------------------

    def sql_servers(self) -> list[dict[str, Any]]:
        """Return SQL servers with embedded auditing and threat detection.

        Each dict has ``server``, ``auditing`` (blob auditing policy),
        ``threat_detection`` (advanced threat protection settings), and
        ``ad_admin`` (Azure AD administrator, or ``None``).
        """
        def _load() -> list[dict[str, Any]]:
            from azure.mgmt.sql import SqlManagementClient
            client = self.mgmt_client(SqlManagementClient)
            results: list[dict[str, Any]] = []
            for server in client.servers.list():
                rg = getattr(server, "id", "").split("/")[4] if getattr(server, "id", "") else None
                srv_name = getattr(server, "name", None)
                auditing = None
                threat = None
                ad_admin = None
                if rg and srv_name:
                    try:
                        auditing = client.server_blob_auditing_policies.get(
                            rg, srv_name,
                        )
                    except Exception:
                        pass
                    try:
                        threat = client.server_advanced_threat_protection_settings.get(
                            rg, srv_name,
                        )
                    except Exception:
                        pass
                    try:
                        admins = list(
                            client.server_azure_ad_administrators.list_by_server(
                                rg, srv_name,
                            ),
                        )
                        ad_admin = admins[0] if admins else None
                    except Exception:
                        pass
                results.append({
                    "server": server,
                    "auditing": auditing,
                    "threat_detection": threat,
                    "ad_admin": ad_admin,
                })
            return results
        return self._memo("sql:servers", _load)

    # ------------------------------------------------------------------
    # Compute
    # ------------------------------------------------------------------

    def virtual_machines(self) -> list[Any]:
        """Return every virtual machine in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.compute import ComputeManagementClient
            client = self.mgmt_client(ComputeManagementClient)
            return list(client.virtual_machines.list_all())
        return self._memo("compute:vms", _load)

    # ------------------------------------------------------------------
    # Monitor (extended)
    # ------------------------------------------------------------------

    def log_analytics_workspaces(self) -> list[Any]:
        """Return every Log Analytics workspace in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.loganalytics import LogAnalyticsManagementClient
            client = self.mgmt_client(LogAnalyticsManagementClient)
            return list(client.workspaces.list())
        return self._memo("monitor:workspaces", _load)

    def alert_rules(self) -> list[Any]:
        """Return all metric alert rules in the subscription."""
        def _load() -> list[Any]:
            from azure.mgmt.monitor import MonitorManagementClient
            client = self.mgmt_client(MonitorManagementClient)
            return list(client.alert_rules.list_by_subscription())
        return self._memo("monitor:alert_rules", _load)
