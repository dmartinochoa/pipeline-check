"""Shared fixtures for GCP rule-module unit tests."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pipeline_check.core.checks.gcp._catalog import ResourceCatalog
from pipeline_check.core.checks.gcp._session import GCPSession


@pytest.fixture()
def make_catalog():
    """Factory that returns a ResourceCatalog with pre-populated cache.

    Usage:
        def test_x(make_catalog):
            cat = make_catalog(**{"iam:project_policy": {...}})
            rules.check(cat)
    """
    def _build(**cache_entries: object) -> ResourceCatalog:
        session = GCPSession(credentials=MagicMock(), project_id="my-project")
        catalog = ResourceCatalog(session)
        catalog._cache.update(cache_entries)
        return catalog
    return _build
