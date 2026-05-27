"""Azure Cloud provider, builds an AzureCloudSession and wires the rule orchestrator.

To add a new Azure Cloud check
------------------------------
1. Create ``pipeline_check/core/checks/azure_cloud/rules/<id_lower>_<slug>.py``
   exporting ``RULE`` (:class:`Rule` metadata) and
   ``check(catalog: ResourceCatalog) -> list[Finding]``.
2. If the rule needs a new Azure service, add a memoized enumeration
   method to :class:`ResourceCatalog` in ``azure_cloud/_catalog.py``
   and register the rule's ID-prefix in
   ``azure_cloud/workflows.py``'s ``_RULE_PREFIX_TO_SERVICE`` and
   ``_DEGRADED`` maps.
3. Add tests in ``tests/azure_cloud/rules/``.

Every rule module is auto-discovered by :class:`AzureCloudRuleChecks`
via ``discover_rules("pipeline_check.core.checks.azure_cloud.rules")``.
"""
from __future__ import annotations

from typing import Any

from ..checks.azure_cloud._session import AzureCloudSession
from ..checks.azure_cloud.workflows import AzureCloudRuleChecks
from ..checks.base import BaseCheck
from .base import BaseProvider


class AzureCloudProvider(BaseProvider):
    """Azure Cloud posture provider (live API via azure-mgmt-* SDKs)."""

    NAME = "azure_cloud"

    def build_context(
        self,
        subscription_id: str | None = None,
        azure_tenant_id: str | None = None,
        **_: Any,
    ) -> AzureCloudSession:
        """Return an :class:`AzureCloudSession` for the given subscription."""
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError:
            raise ImportError(
                "The azure_cloud provider requires the Azure SDK. "
                "Install with: pip install pipeline-check[azure-cloud]"
            ) from None
        if not subscription_id:
            raise ValueError(
                "The azure_cloud provider requires --subscription-id."
            )
        kwargs: dict[str, str] = {}
        if azure_tenant_id:
            kwargs["tenant_id"] = azure_tenant_id
        credential = DefaultAzureCredential(**kwargs)
        return AzureCloudSession(
            credential=credential,
            subscription_id=subscription_id,
            tenant_id=azure_tenant_id,
        )

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [AzureCloudRuleChecks]
