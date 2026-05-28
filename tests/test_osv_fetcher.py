"""Regression tests for the OSV batch fetcher."""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from pipeline_check.core.checks._primitives.osv_fetcher import query_osv_batch


def _fake_urlopen(payload: dict[str, Any]) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


class _DictCache:
    def __init__(self) -> None:
        self.store: dict[str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        return self.store.get(key)

    def put(self, key: str, data: bytes) -> None:
        self.store[key] = data


_URLOPEN = (
    "pipeline_check.core.checks._primitives.osv_fetcher"
    ".urllib.request.urlopen"
)


class TestOsvShortResults:
    def test_truncated_results_not_cached_as_clean(self) -> None:
        # OSV returns ONE result entry for TWO queries (truncated). The
        # unpaired tail package must not be silently cached as
        # advisory-free; the batch is treated as an error instead.
        cache = _DictCache()
        warnings: list[str] = []
        queries = [
            ("pkg-a", "1.0.0", "PyPI"),
            ("pkg-b", "2.0.0", "PyPI"),
        ]
        payload = {"results": [{"vulns": []}]}
        with patch(_URLOPEN, return_value=_fake_urlopen(payload)):
            results = query_osv_batch(queries, cache=cache, warnings=warnings)
        assert results == {}
        assert cache.store == {}, "truncated batch must not cache anything"
        assert warnings and "truncated" in warnings[0].lower()

    def test_full_results_cache_normally(self) -> None:
        # One result per query: the second is vulnerable, both get cached.
        cache = _DictCache()
        warnings: list[str] = []
        queries = [
            ("pkg-a", "1.0.0", "PyPI"),
            ("pkg-b", "2.0.0", "PyPI"),
        ]
        payload = {
            "results": [
                {"vulns": []},
                {"vulns": [{"id": "GHSA-xxxx", "modified": "2026-01-01T00:00:00Z"}]},
            ],
        }
        with patch(_URLOPEN, return_value=_fake_urlopen(payload)):
            results = query_osv_batch(queries, cache=cache, warnings=warnings)
        assert ("pkg-b", "2.0.0") in results
        assert len(cache.store) == 2
        assert not warnings
