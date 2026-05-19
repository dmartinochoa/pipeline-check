"""npm registry metadata fetcher.

Mirrors the GHA ``--resolve-remote`` resolver pattern (Protocol +
HTTP impl + disk cache + graceful failure) but targets
``registry.npmjs.org/<package>`` to recover publish timestamps for
NPM-008 (cooldown gate).

Architecture
------------

* :class:`RegistryMetadataFetcher` is a Protocol. Any object with a
  ``fetch(name) -> bytes | None`` works.
* :class:`HttpRegistryFetcher` hits ``registry.npmjs.org/<name>``
  via stdlib ``urllib`` (no extra dep). Returns ``None`` on 404 /
  network error so the caller records a warning but the scan keeps
  going.
* :class:`FileSystemCache` caches per-package JSON by name with a
  default 7-day TTL. Tunable via ``--no-cache``.
* :func:`fetch_publish_times` is the top-level convenience: given a
  list of package names and a fetcher / cache, returns
  ``{name@version: timestamp_utc}`` for every successfully-resolved
  (name, version) tuple. Failures land in the returned warnings.

The module never raises on a network error or a malformed body —
errors surface as ``None`` returns from the fetcher and as warnings
from :func:`fetch_publish_times`. Resolution is strictly additive:
failed fetches don't change the existing scan.

Threat-model note: this module issues HTTPS requests to
``registry.npmjs.org``. It's opt-in via ``--resolve-remote`` at the
CLI; this module never reads the network unless a fetcher with a
real implementation is passed in.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

_DEFAULT_TTL_SECONDS = 7 * 24 * 3600
_DEFAULT_TIMEOUT = 10.0

#: Hard cap on response body size. A normal npm package metadata
#: blob is ~100 KB; a maliciously large response shouldn't be
#: allowed to balloon scanner memory. 10 MiB is generous for the
#: largest real-world packument (a popular package with thousands
#: of versions might approach 5-8 MB) while bounding the worst case.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


# ── Fetcher protocol + implementations ────────────────────────────


class RegistryMetadataFetcher(Protocol):
    """Fetch a package's JSON metadata blob from an npm registry."""

    def fetch(self, name: str) -> bytes | None:
        ...


class HttpRegistryFetcher:
    """Fetch via ``registry.npmjs.org/<name>``.

    Public-only (no auth header) — npm metadata is public for
    public packages. Returns ``None`` on 404 / 401 / network error
    so the caller can record a warning and proceed.
    """

    BASE_URL = "https://registry.npmjs.org"

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    def fetch(self, name: str) -> bytes | None:
        # Scoped names ``@scope/foo`` need the ``/`` URL-encoded.
        encoded = name.replace("/", "%2F")
        url = f"{self.BASE_URL}/{encoded}"
        req = urllib.request.Request(url)  # noqa: S310, fixed scheme + host
        req.add_header("User-Agent", "pipeline-check-npm-fetcher")
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


def _cache_filename(name: str) -> str:
    """Filename-safe key for a package name.

    Hashes the name so scoped packages (``@scope/foo``) and any
    weird characters end up on disk as a stable, short filename
    that survives Windows' 260-char limit and case-folding.
    """
    h = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    safe = name.replace("/", "_").replace("@", "at_")[:64]
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

    def _path_for(self, name: str) -> Path:
        return self.root / _cache_filename(name)

    def get(self, name: str) -> bytes | None:
        if not self.enabled:
            return None
        cached = self._path_for(name)
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

    def put(self, name: str, data: bytes) -> None:
        if not self.enabled:
            return
        cached = self._path_for(name)
        try:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(data)
        except OSError:
            # Cache failures are never fatal — next scan will refetch.
            pass


def default_cache_dir() -> Path:
    """Return the platform-appropriate cache root for npm metadata.

    Falls back to ``~/.cache/pipeline-check/npm-registry`` when
    ``platformdirs`` is unavailable so we don't take a hard dep
    just for one path.
    """
    try:
        import platformdirs
        base = Path(platformdirs.user_cache_dir("pipeline-check"))
    except ImportError:
        base = Path.home() / ".cache" / "pipeline-check"
    return base / "npm-registry"


# ── Top-level convenience ────────────────────────────────────────


def _parse_publish_times(
    blob: bytes,
) -> dict[str, _dt.datetime]:
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
            # only accepts ``Z`` from Python 3.11+, which the
            # codebase targets.
            out[version] = _dt.datetime.fromisoformat(
                ts.replace("Z", "+00:00"),
            )
        except ValueError:
            continue
    return out


def fetch_publish_times(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, dict[str, _dt.datetime]], list[str]]:
    """Resolve publish timestamps for every package in *names*.

    Returns ``({name: {version: ts_utc}}, warnings)``. A package
    whose metadata can't be fetched lands as a warning string and
    is omitted from the result dict — the rule reading the output
    skips silently for unresolved packages so a transient registry
    outage doesn't trip the cooldown gate on the next CI run.

    Deduplicates *names* internally so the same package isn't
    fetched twice when it appears in both ``dependencies`` and
    ``devDependencies``.
    """
    seen: set[str] = set()
    out: dict[str, dict[str, _dt.datetime]] = {}
    warnings: list[str] = []
    for name in names:
        if not isinstance(name, str) or not name or name in seen:
            continue
        seen.add(name)
        blob: bytes | None = (
            cache.get(name) if cache is not None else None
        )
        if blob is None:
            blob = fetcher.fetch(name)
            if blob is None:
                warnings.append(
                    f"npm-registry: could not fetch metadata for {name}"
                )
                continue
            if cache is not None:
                cache.put(name, blob)
        per_version = _parse_publish_times(blob)
        if per_version:
            out[name] = per_version
    return out, warnings


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_publish_times",
]
