"""AWS-specific base check.

All AWS check modules subclass AWSBaseCheck, which wires the boto3 Session
into self.session. Use self.client("service-name") to obtain a boto3 client;
clients are cached per session so repeated lookups across check modules do
not re-instantiate the same service client.

Also exposes two shared helpers that used to be copy-pasted into every
check module:

- ``self.degraded(check_id, resource, error, recommendation)`` — builds the
  standard INFO-severity "API access failed" finding.
- ``self._paginate(client, op_name, key)`` — yields every item from a
  paginated list operation.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import boto3
from botocore.config import Config

from pipeline_check.core.checks.base import BaseCheck, Finding, Severity

_CLIENT_CACHE_ATTR = "_pc_client_cache"

# Adaptive retries handle throttling on large accounts where listing
# every pipeline/project/role can blow past the default 4-attempt budget.
_RETRY_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 10})


class AWSBaseCheck(BaseCheck):
    """Base class for all AWS check modules."""

    PROVIDER = "aws"

    def __init__(self, session: boto3.Session, target: str | None = None) -> None:
        super().__init__(context=session, target=target)
        self.session: boto3.Session = session

    def client(self, service_name: str) -> Any:
        """Return a cached boto3 client for *service_name* on this session.

        The client is configured with adaptive retries so transient
        ``ThrottlingException`` errors on large accounts are absorbed
        without per-check defensive code.

        Falls back to a fresh ``session.client(...)`` call if the session is
        a MagicMock or otherwise refuses an attribute set, so tests that
        stub ``session.client`` keep working.
        """
        cache = getattr(self.session, _CLIENT_CACHE_ATTR, None)
        if not isinstance(cache, dict):
            try:
                cache = {}
                setattr(self.session, _CLIENT_CACHE_ATTR, cache)
            except (AttributeError, TypeError):
                return _build_client(self.session, service_name)
        if service_name not in cache:
            cache[service_name] = _build_client(self.session, service_name)
        return cache[service_name]

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def degraded(
        check_id: str,
        resource: str,
        error: BaseException | str,
        recommendation: str,
    ) -> Finding:
        """Standard INFO-severity finding for API access failures.

        Every AWS module used to ship its own ``_xxx000_api_failed``
        factory. This one replaces them all.
        """
        return Finding(
            check_id=check_id,
            title=f"{resource} API access failed",
            severity=Severity.INFO,
            resource=resource,
            description=(
                f"Could not complete {resource} enumeration: {error}. "
                "Subsequent checks in this module were skipped."
            ),
            recommendation=recommendation,
            passed=False,
        )

    @staticmethod
    def _paginate(client: Any, op_name: str, key: str, **kwargs: Any) -> Iterator[Any]:
        """Yield every item from paginated list operation *op_name*.

        Example:
            for project_name in self._paginate(client, "list_projects", "projects"):
                ...
        """
        paginator = client.get_paginator(op_name)
        for page in paginator.paginate(**kwargs):
            yield from page.get(key, [])


def _build_client(session: boto3.Session, service_name: str) -> Any:
    """Construct a boto3 client with the retry-safe config.

    Separate function so tests that stub ``session.client`` with a
    MagicMock don't trip over unexpected ``config=`` kwargs — if the
    session refuses the kwarg, we fall back to a plain call.
    """
    try:
        return session.client(service_name, config=_RETRY_CONFIG)
    except TypeError:
        return session.client(service_name)
