"""Azure Cloud base check, wires management clients into subclasses."""
from __future__ import annotations

from pipeline_check.core.checks.base import BaseCheck, Finding, Severity

from ._session import AzureCloudSession

_CLIENT_CACHE_ATTR = "_pc_azure_client_cache"


class AzureCloudBaseCheck(BaseCheck["AzureCloudSession"]):
    """Base class for all Azure Cloud check modules."""

    PROVIDER = "azure_cloud"

    def __init__(
        self, session: AzureCloudSession, target: str | None = None,
    ) -> None:
        super().__init__(context=session, target=target)
        self.session: AzureCloudSession = session

    @staticmethod
    def degraded(
        check_id: str,
        resource: str,
        error: BaseException | str,
        recommendation: str,
    ) -> Finding:
        """Standard INFO-severity finding for API access failures."""
        return Finding(
            check_id=check_id,
            title=f"{resource} API access failed",
            severity=Severity.INFO,
            resource=resource,
            description=(
                f"Could not enumerate {resource} resources: {error}. "
                "Rules depending on this data were skipped."
            ),
            recommendation=recommendation,
            passed=False,
        )
