"""npm registry metadata fetcher.

Thin adapter on top of :mod:`pipeline_check.core.checks._primitives.
registry_fetcher`. The shared primitive owns the disk cache, the
HTTP transport, the dedup-fetch-parse loop, and the platform cache
directory. This module supplies the npm-specific bits:

* ``BASE_URL = https://registry.npmjs.org`` + scoped-name encoding,
* the cache-key normalizer (npm preserves case + the ``@scope/``
  prefix),
* :func:`_parse_publish_times` over the packument's ``time`` block.

Public surface stays at the legacy shape: ``FileSystemCache``,
``HttpRegistryFetcher``, ``RegistryMetadataFetcher`` (Protocol),
``fetch_publish_times``, ``default_cache_dir``. Callers in
``core/providers/npm.py`` import these names exactly as before.

Threat-model note: this module issues HTTPS requests to
``registry.npmjs.org``. It's opt-in via ``--resolve-remote`` at the
CLI; this module never reads the network unless a fetcher with a
real implementation is passed in.
"""
from __future__ import annotations

import datetime as _dt
import json
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

# Re-export the shared cache so ``from
# pipeline_check.core.checks.npm.registry_fetcher import
# FileSystemCache`` keeps working.
FileSystemCache = _FileSystemCache


def default_cache_dir() -> Path:
    """Platform cache root + ``npm-registry/``."""
    return _default_cache_dir("npm-registry")


# ── Fetcher protocol + HTTP impl ─────────────────────────────────


class RegistryMetadataFetcher(Protocol):
    """Fetch a package's JSON metadata blob from an npm registry."""

    def fetch(self, name: str) -> bytes | None:
        ...


class HttpRegistryFetcher:
    """Fetch via ``registry.npmjs.org/<name>``.

    Public-only (no auth header) — npm metadata is public for public
    packages. Scoped names (``@scope/foo``) need the ``/``
    URL-encoded.
    """

    BASE_URL = "https://registry.npmjs.org"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._http = _HttpGetFetcher(
            user_agent="pipeline-check-npm-fetcher",
            timeout=timeout,
        )

    def fetch(self, name: str) -> bytes | None:
        encoded = name.replace("/", "%2F")
        return self._http.get(f"{self.BASE_URL}/{encoded}")


# ── Per-version timestamp parser ─────────────────────────────────


def _parse_publish_times(blob: bytes) -> dict[str, _dt.datetime]:
    """Project an npm packument JSON onto ``{version: timestamp}``.

    npm metadata carries a top-level ``time`` object with one
    timestamp per version plus the ``created`` and ``modified``
    bookkeeping entries. Parsed timestamps are returned as
    timezone-aware UTC datetimes; entries that don't parse drop on
    the floor (a partial registry response shouldn't break the
    cooldown computation).
    """
    out: dict[str, _dt.datetime] = {}
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return out
    if not isinstance(doc, dict):
        return out
    time_block = doc.get("time")
    if not isinstance(time_block, dict):
        return out
    for version, ts in time_block.items():
        if version in ("created", "modified") or not isinstance(version, str):
            continue
        if not isinstance(ts, str):
            continue
        try:
            # npm timestamps are ISO 8601 with a ``Z`` suffix
            # (``2024-09-16T12:34:56.789Z``). ``fromisoformat``
            # accepts ``Z`` from Python 3.11+, which the codebase
            # targets.
            out[version] = _dt.datetime.fromisoformat(
                ts.replace("Z", "+00:00"),
            )
        except ValueError:
            continue
    return out


# ── Top-level convenience ────────────────────────────────────────


def fetch_publish_times(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, dict[str, _dt.datetime]], list[str]]:
    """Resolve publish timestamps for every package in *names*.

    Deduplicates *names* internally so the same package isn't
    fetched twice when it appears in both ``dependencies`` and
    ``devDependencies``.
    """
    def _cache_key(name: object) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        return name

    def _fetch_blob(name: object) -> bytes | None:
        assert isinstance(name, str)
        return fetcher.fetch(name)

    return fetch_publish_times_generic(
        names,
        cache_key=_cache_key,
        fetch_blob=_fetch_blob,
        parser=_parse_publish_times,
        cache=cache,
        ecosystem="npm",
    )


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_publish_times",
]
