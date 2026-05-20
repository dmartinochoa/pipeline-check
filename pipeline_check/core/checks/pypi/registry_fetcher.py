"""PyPI registry metadata fetcher.

Thin adapter on top of :mod:`pipeline_check.core.checks._primitives.
registry_fetcher`. PyPI-specific bits:

* ``BASE_URL = https://pypi.org/pypi`` + per-package ``/json`` suffix,
* PEP 503 normalization on the cache key (lowercase + name
  canonicalization),
* :func:`_parse_publish_times` over the per-version ``releases``
  block (one file record per artifact; the per-version timestamp
  is the minimum across that release's file records).

Public surface (``FileSystemCache``, ``HttpRegistryFetcher``,
``RegistryMetadataFetcher``, ``fetch_publish_times``,
``default_cache_dir``) is preserved verbatim so
``core/providers/pypi.py`` doesn't need any import changes.

Threat-model note: this module issues HTTPS requests to
``pypi.org``. It's opt-in via ``--resolve-remote`` at the CLI; this
module never reads the network unless a fetcher with a real
implementation is passed in.
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

FileSystemCache = _FileSystemCache


def default_cache_dir() -> Path:
    """Platform cache root + ``pypi-registry/``."""
    return _default_cache_dir("pypi-registry")


# ── Fetcher protocol + HTTP impl ─────────────────────────────────


class RegistryMetadataFetcher(Protocol):
    """Fetch a package's JSON metadata blob from a PyPI-style index."""

    def fetch(self, name: str) -> bytes | None:
        ...


class HttpRegistryFetcher:
    """Fetch via ``pypi.org/pypi/<name>/json``.

    Public-only — PyPI metadata is open. The fetcher applies a PEP
    503 normalization (lowercased name) before constructing the URL,
    matching the cache-key derivation so a single ``Pillow`` vs
    ``pillow`` vs ``pil_low`` reference resolves to the same on-disk
    cache file.
    """

    BASE_URL = "https://pypi.org/pypi"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._http = _HttpGetFetcher(
            user_agent="pipeline-check-pypi-fetcher",
            timeout=timeout,
        )

    def fetch(self, name: str) -> bytes | None:
        encoded = name.strip().lower()
        return self._http.get(f"{self.BASE_URL}/{encoded}/json")


# ── Per-version timestamp parser ─────────────────────────────────


def _parse_publish_times(blob: bytes) -> dict[str, _dt.datetime]:
    """Project a PyPI JSON packument onto ``{version: timestamp}``.

    PyPI lists per-version file records under ``releases.<version>``;
    each carries an ``upload_time_iso_8601`` string. The per-version
    timestamp is the minimum across the file records (the moment
    the FIRST artifact for that release landed on the index — that's
    what the cooldown window should measure from). Empty release
    lists (the version was yanked) drop on the floor; entries that
    don't parse drop too. A partial registry response never breaks
    the cooldown computation.
    """
    out: dict[str, _dt.datetime] = {}
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return out
    if not isinstance(doc, dict):
        return out
    releases = doc.get("releases")
    if not isinstance(releases, dict):
        return out
    for version, files in releases.items():
        if not isinstance(version, str) or not isinstance(files, list):
            continue
        earliest: _dt.datetime | None = None
        for file_rec in files:
            if not isinstance(file_rec, dict):
                continue
            ts = file_rec.get("upload_time_iso_8601") or file_rec.get(
                "upload_time",
            )
            if not isinstance(ts, str):
                continue
            try:
                parsed = _dt.datetime.fromisoformat(
                    ts.replace("Z", "+00:00"),
                )
            except ValueError:
                continue
            # Normalize tz-naive timestamps (the legacy upload_time
            # field has no tz) to UTC so the min() comparison is
            # well-defined across mixed records.
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=_dt.UTC)
            if earliest is None or parsed < earliest:
                earliest = parsed
        if earliest is not None:
            out[version] = earliest
    return out


# ── Top-level convenience ────────────────────────────────────────


def fetch_publish_times(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, dict[str, _dt.datetime]], list[str]]:
    """Resolve publish timestamps for every package in *names*.

    Deduplicates *names* internally (PEP 503 normalized) so the
    same package isn't fetched twice when it appears under different
    cases in different requirements files.
    """
    def _cache_key(name: object) -> str | None:
        if not isinstance(name, str) or not name:
            return None
        return name.strip().lower()

    def _fetch_blob(name: object) -> bytes | None:
        assert isinstance(name, str)
        return fetcher.fetch(name.strip().lower())

    return fetch_publish_times_generic(
        names,
        cache_key=_cache_key,
        fetch_blob=_fetch_blob,
        parser=_parse_publish_times,
        cache=cache,
        ecosystem="pypi",
    )


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_publish_times",
]
