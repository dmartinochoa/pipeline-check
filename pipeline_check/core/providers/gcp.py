"""GCP provider, builds a GCPSession and wires the rule orchestrator.

To add a new GCP check
----------------------
1. Create ``pipeline_check/core/checks/gcp/rules/<id_lower>_<slug>.py``
   exporting ``RULE`` (:class:`Rule` metadata) and
   ``check(catalog: ResourceCatalog) -> list[Finding]``.
2. If the rule needs a new GCP service, add a memoized enumeration
   method to :class:`ResourceCatalog` in ``gcp/_catalog.py`` and
   register the rule's ID-prefix in ``gcp/workflows.py``'s
   ``_RULE_PREFIX_TO_SERVICE`` and ``_DEGRADED`` maps.
3. Add tests in ``tests/gcp/rules/``.

Every rule module is auto-discovered by :class:`GCPRuleChecks` via
``discover_rules("pipeline_check.core.checks.gcp.rules")``.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.gcp._session import GCPSession
from ..checks.gcp.workflows import GCPRuleChecks
from .base import BaseProvider


class GCPProvider(BaseProvider):
    """GCP cloud posture provider (live API via google-cloud-* SDKs)."""

    NAME = "gcp"

    def build_context(
        self,
        gcp_project: str | None = None,
        **_: Any,
    ) -> GCPSession:
        """Return a :class:`GCPSession` for the given project."""
        try:
            import google.auth
        except ImportError:
            raise ImportError(
                "The gcp provider requires the Google Cloud SDK. "
                "Install with: pip install pipeline-check[gcp]"
            ) from None
        if not gcp_project:
            raise ValueError(
                "The gcp provider requires --gcp-project."
            )
        credentials, _ = google.auth.default()
        return GCPSession(
            credentials=credentials,
            project_id=gcp_project,
        )

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [GCPRuleChecks]
