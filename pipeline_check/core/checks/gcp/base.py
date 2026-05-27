"""GCP base check, wires cloud clients into subclasses."""
from __future__ import annotations

from pipeline_check.core.checks.base import BaseCheck, Finding, Severity

from ._session import GCPSession

_CLIENT_CACHE_ATTR = "_pc_gcp_client_cache"


class GCPBaseCheck(BaseCheck["GCPSession"]):
    """Base class for all GCP check modules."""

    PROVIDER = "gcp"

    def __init__(
        self, session: GCPSession, target: str | None = None,
    ) -> None:
        super().__init__(context=session, target=target)
        self.session: GCPSession = session

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
