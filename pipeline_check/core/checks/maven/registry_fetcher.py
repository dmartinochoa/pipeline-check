"""Maven Central registry metadata fetcher.

Thin adapter on top of :mod:`pipeline_check.core.checks._primitives.
registry_fetcher`. Maven-specific bits:

* the search-API URL builder
  (``search.maven.org/solrsearch/select?q=g:GROUP+AND+a:ARTIFACT&core=gav``),
* the ``(group, artifact)`` -> ``"group:artifact"`` cache key,
* :func:`_parse_publish_times` over the ``response.docs`` array,
  which carries one record per version with a millisecond-Unix-epoch
  ``timestamp`` field.

The shared primitive owns the disk cache, the HTTP transport, the
dedup-fetch-parse loop, and the platform cache directory.

Public surface (``FileSystemCache``, ``HttpRegistryFetcher``,
``RegistryMetadataFetcher``, ``fetch_publish_times``,
``default_cache_dir``) is preserved verbatim so
``core/providers/maven.py`` doesn't need any import changes.

Threat-model note: this module issues HTTPS requests to
``search.maven.org``. It's opt-in via ``--resolve-remote`` at the
CLI; this module never reads the network unless a fetcher with a
real implementation is passed in.
"""
from __future__ import annotations

import datetime as _dt
import json
import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from .._primitives.registry_fetcher import (
    FileSystemCache as _FileSystemCache,
)
from .._primitives.registry_fetcher import (
    HttpGetFetcher as _HttpGetFetcher,
)
from .._primitives.registry_fetcher import (
    default_cache_dir as _default_cache_dir,
)
from .._primitives.registry_fetcher import (
    fetch_publish_times_generic,
)

FileSystemCache = _FileSystemCache

#: Maven Central caps ``rows=`` at 200 per request. Coordinates with
#: more than 200 versions truncate to the most recent 200 (sorted by
#: descending timestamp by default), which is the slice the cooldown
#: rule cares about anyway.
_DEFAULT_ROWS = 200


def default_cache_dir() -> Path:
    """Platform cache root + ``maven-registry/``."""
    return _default_cache_dir("maven-registry")


# ── Fetcher protocol + HTTP impl ─────────────────────────────────


class RegistryMetadataFetcher(Protocol):
    """Fetch a coordinate's version index from Maven Central."""

    def fetch(self, group_id: str, artifact_id: str) -> bytes | None:
        ...


class HttpRegistryFetcher:
    """Fetch via ``search.maven.org/solrsearch/select``.

    Public-only (no auth header) — Maven Central search is open.
    Returns ``None`` on 404 / 401 / network error so the caller can
    record a warning and proceed.
    """

    BASE_URL = "https://search.maven.org/solrsearch/select"

    def __init__(
        self,
        timeout: float = 10.0,
        rows: int = _DEFAULT_ROWS,
    ) -> None:
        self.timeout = timeout
        self.rows = rows
        self._http = _HttpGetFetcher(
            user_agent="pipeline-check-maven-fetcher",
            timeout=timeout,
        )

    def fetch(self, group_id: str, artifact_id: str) -> bytes | None:
        query = f'g:"{group_id}" AND a:"{artifact_id}"'
        params = urllib.parse.urlencode({
            "q": query,
            "core": "gav",
            "rows": str(self.rows),
            "wt": "json",
        })
        return self._http.get(f"{self.BASE_URL}?{params}")


# ── Per-version timestamp parser ─────────────────────────────────


def _parse_publish_times(blob: bytes) -> dict[str, _dt.datetime]:
    """Project a Maven Central ``gav`` response onto ``{version: ts}``.

    The search-API JSON shape is::

        {"response": {"docs": [
            {"id": "g:a:1.0", "g": "g", "a": "a", "v": "1.0",
             "timestamp": 1700000000000, ...},
            ...
        ]}}

    ``timestamp`` is millisecond Unix epoch (UTC) — the moment the
    artifact was ingested into Central. Entries that don't parse
    drop on the floor; a partial response never breaks the cooldown
    computation.
    """
    out: dict[str, _dt.datetime] = {}
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return out
    if not isinstance(doc, dict):
        return out
    response = doc.get("response")
    if not isinstance(response, dict):
        return out
    docs = response.get("docs")
    if not isinstance(docs, list):
        return out
    for rec in docs:
        if not isinstance(rec, dict):
            continue
        version = rec.get("v")
        ts_ms = rec.get("timestamp")
        if not isinstance(version, str) or not version:
            continue
        if not isinstance(ts_ms, (int, float)):
            continue
        # Reject obviously-bogus epoch values (negative, or far
        # enough in the future to suggest seconds-instead-of-ms).
        if ts_ms < 0:
            continue
        try:
            parsed = _dt.datetime.fromtimestamp(
                ts_ms / 1000.0, tz=_dt.UTC,
            )
        except (OSError, OverflowError, ValueError):
            continue
        # If the same version appears multiple times (shouldn't,
        # but ``gav`` can occasionally double-list), keep the
        # earliest ingest timestamp.
        existing = out.get(version)
        if existing is None or parsed < existing:
            out[version] = parsed
    return out


# ── Top-level convenience ────────────────────────────────────────


def fetch_publish_times(
    coordinates: Iterable[tuple[str, str]],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, dict[str, _dt.datetime]], list[str]]:
    """Resolve publish timestamps for every coordinate in *coordinates*.

    Deduplicates *coordinates* internally so the same
    ``group:artifact`` isn't fetched twice when the same dep appears
    in multiple POMs.
    """
    def _cache_key(coord: object) -> str | None:
        if not isinstance(coord, tuple) or len(coord) != 2:
            return None
        group_id, artifact_id = coord
        if not group_id or not artifact_id:
            return None
        return f"{group_id}:{artifact_id}"

    def _fetch_blob(coord: object) -> bytes | None:
        assert isinstance(coord, tuple) and len(coord) == 2
        return fetcher.fetch(coord[0], coord[1])

    return fetch_publish_times_generic(
        coordinates,
        cache_key=_cache_key,
        fetch_blob=_fetch_blob,
        parser=_parse_publish_times,
        cache=cache,
        ecosystem="maven",
    )


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_publish_times",
]
