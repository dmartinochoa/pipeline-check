"""Maven Central registry metadata fetcher.

Mirrors the npm / PyPI registry fetchers (Protocol + HTTP impl +
disk cache + graceful failure) but targets the Maven Central
search API
(``https://search.maven.org/solrsearch/select``) to recover per-
version publish timestamps for MVN-008 (cooldown gate).

The search API exposes a per-coordinate ``gav`` core: a query like
``q=g:org.apache.logging.log4j+AND+a:log4j-core&core=gav&rows=200``
returns one document per version, each carrying a ``timestamp``
field in millisecond Unix epoch (UTC). That's the moment Central
ingested the artifact, which is what the cooldown should measure
from.

Architecture
------------

* :class:`RegistryMetadataFetcher` is a Protocol. Any object with
  a ``fetch(group, artifact) -> bytes | None`` works.
* :class:`HttpRegistryFetcher` hits the Maven Central search API
  via stdlib ``urllib``. Returns ``None`` on 404 / network error
  so the caller records a warning but the scan keeps going.
* :class:`FileSystemCache` caches per-coordinate JSON keyed by
  ``group:artifact`` with a default 7-day TTL.
* :func:`fetch_publish_times` walks a list of coordinates and
  returns ``{"group:artifact": {version: timestamp_utc}}`` for
  every successfully-resolved coordinate. Failures land in the
  warnings.

Threat-model note: this module issues HTTPS requests to
``search.maven.org``. It's opt-in via ``--resolve-remote`` at the
CLI; this module never reads the network unless a fetcher with a
real implementation is passed in.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

_DEFAULT_TTL_SECONDS = 7 * 24 * 3600
_DEFAULT_TIMEOUT = 10.0

#: Hard cap on response body size. A normal Maven Central ``gav``
#: response for a single coordinate is ~10-100 KB; a maliciously
#: large response shouldn't be allowed to balloon scanner memory.
#: 10 MiB is generous for the very largest coordinates (Spring
#: Boot starters with hundreds of releases approach 500 KB).
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024

#: Maven Central caps ``rows=`` at 200 per request. Coordinates with
#: more than 200 versions truncate to the most recent 200 (sorted by
#: descending timestamp by default), which is the slice the cooldown
#: rule cares about anyway.
_DEFAULT_ROWS = 200


# ── Fetcher protocol + implementations ────────────────────────────


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
        timeout: float = _DEFAULT_TIMEOUT,
        rows: int = _DEFAULT_ROWS,
    ) -> None:
        self.timeout = timeout
        self.rows = rows

    def fetch(self, group_id: str, artifact_id: str) -> bytes | None:
        query = f'g:"{group_id}" AND a:"{artifact_id}"'
        params = urllib.parse.urlencode({
            "q": query,
            "core": "gav",
            "rows": str(self.rows),
            "wt": "json",
        })
        url = f"{self.BASE_URL}?{params}"
        req = urllib.request.Request(url)  # noqa: S310, fixed scheme + host
        req.add_header("User-Agent", "pipeline-check-maven-fetcher")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(  # noqa: S310
                req, timeout=self.timeout,
            ) as resp:
                body: bytes = resp.read(_MAX_RESPONSE_BYTES + 1)
                if len(body) > _MAX_RESPONSE_BYTES:
                    return None
                return body
        except urllib.error.HTTPError:
            return None
        except (urllib.error.URLError, TimeoutError, OSError):
            return None


# ── Cache ────────────────────────────────────────────────────────


def _cache_key(group_id: str, artifact_id: str) -> str:
    return f"{group_id}:{artifact_id}"


def _cache_filename(key: str) -> str:
    """Filename-safe key for a Maven coordinate.

    Hashes the coordinate so any weird characters end up on disk as
    a stable, short filename that survives Windows' 260-char limit
    and case-folding.
    """
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    safe = key.replace(":", "_").replace("/", "_")[:64]
    return f"{safe}__{h}.json"


class FileSystemCache:
    """Disk-backed cache for fetcher output.

    Default TTL is 7 days; tune with ``ttl_seconds=0`` to disable
    write-side caching while still allowing reads of unexpired
    entries. Pass ``enabled=False`` to short-circuit both read and
    write — the caller wires that up to ``--no-cache``.
    """

    def __init__(
        self,
        root: Path,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        enabled: bool = True,
    ) -> None:
        self.root = Path(root)
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled

    def _path_for(self, key: str) -> Path:
        return self.root / _cache_filename(key)

    def get(self, key: str) -> bytes | None:
        if not self.enabled:
            return None
        cached = self._path_for(key)
        if not cached.is_file():
            return None
        try:
            mtime = cached.stat().st_mtime
        except OSError:
            return None
        if self.ttl_seconds > 0 and time.time() - mtime > self.ttl_seconds:
            return None
        try:
            return cached.read_bytes()
        except OSError:
            return None

    def put(self, key: str, data: bytes) -> None:
        if not self.enabled:
            return
        cached = self._path_for(key)
        try:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(data)
        except OSError:
            # Cache failures are never fatal — next scan will refetch.
            pass


def default_cache_dir() -> Path:
    """Return the platform-appropriate cache root for Maven metadata.

    Falls back to ``~/.cache/pipeline-check/maven-registry`` when
    ``platformdirs`` is unavailable so we don't take a hard dep
    just for one path.
    """
    try:
        import platformdirs
        base = Path(platformdirs.user_cache_dir("pipeline-check"))
    except ImportError:
        base = Path.home() / ".cache" / "pipeline-check"
    return base / "maven-registry"


# ── Top-level convenience ────────────────────────────────────────


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


def fetch_publish_times(
    coordinates: Iterable[tuple[str, str]],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, dict[str, _dt.datetime]], list[str]]:
    """Resolve publish timestamps for every coordinate in *coordinates*.

    Returns ``({"group:artifact": {version: ts_utc}}, warnings)``. A
    coordinate whose metadata can't be fetched lands as a warning
    string and is omitted from the result dict — the rule reading
    the output skips silently for unresolved coordinates so a
    transient Central outage doesn't trip the cooldown gate on the
    next CI run.

    Deduplicates *coordinates* internally so the same ``group:artifact``
    isn't fetched twice when the same dep appears in multiple POMs.
    """
    seen: set[str] = set()
    out: dict[str, dict[str, _dt.datetime]] = {}
    warnings: list[str] = []
    for coord in coordinates:
        if not isinstance(coord, tuple) or len(coord) != 2:
            continue
        group_id, artifact_id = coord
        if not group_id or not artifact_id:
            continue
        key = _cache_key(group_id, artifact_id)
        if key in seen:
            continue
        seen.add(key)
        blob: bytes | None = (
            cache.get(key) if cache is not None else None
        )
        if blob is None:
            blob = fetcher.fetch(group_id, artifact_id)
            if blob is None:
                warnings.append(
                    f"maven-registry: could not fetch metadata for "
                    f"{key}"
                )
                continue
            if cache is not None:
                cache.put(key, blob)
        per_version = _parse_publish_times(blob)
        if per_version:
            out[key] = per_version
    return out, warnings


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_publish_times",
]
