"""Shared fixtures for Azure Cloud rule-module unit tests."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline_check.core.checks.azure_cloud._catalog import ResourceCatalog
from pipeline_check.core.checks.azure_cloud._session import AzureCloudSession


@pytest.fixture()
def make_catalog():
    """Factory that returns a ResourceCatalog with pre-populated cache.

    Usage:
        def test_x(make_catalog):
            cat = make_catalog(**{"storage:accounts": [mock_account]})
            rules.check(cat)
    """
    def _build(**cache_entries: object) -> ResourceCatalog:
        session = AzureCloudSession(
            credential=MagicMock(), subscription_id="sub-123",
        )
        catalog = ResourceCatalog(session)
        catalog._cache.update(cache_entries)
        return catalog
    return _build
