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
