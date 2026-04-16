"""AWS-specific base check.

All AWS check modules subclass AWSBaseCheck, which wires the boto3 Session
improinto self.session. Use self.client("service-name") to obtain a boto3 client;
clients are cached per session so repeated lookups across check modules do
not re-instantiate the same service client.
"""
from __future__ import annotations

from typing import Any

import boto3

from pipeline_check.core.checks.base import BaseCheck, Finding, Severity

_CLIENT_CACHE_ATTR = "_pc_client_cache"


class AWSBaseCheck(BaseCheck):
    """Base class for all AWS check modules."""

    PROVIDER = "aws"

    def __init__(self, session: boto3.Session, target: str | None = None) -> None:
        super().__init__(context=session, target=target)
        self.session: boto3.Session = session

    def client(self, service_name: str) -> Any:
        """Return a cached boto3 client for *service_name* on this session.

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
                return self.session.client(service_name)
        if service_name not in cache:
            cache[service_name] = self.session.client(service_name)
        return cache[service_name]
