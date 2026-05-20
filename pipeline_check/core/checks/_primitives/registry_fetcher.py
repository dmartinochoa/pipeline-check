"""Shared registry-metadata fetcher core.

The npm, PyPI, and Maven Central cooldown gates (``NPM-008`` /
``PYPI-008`` / ``MVN-008``) each need to fetch per-version publish
timestamps from the respective package index. The three modules used
to ship near-verbatim ~280-line copies of the same machinery:

* a ``FileSystemCache`` keyed on a per-package string with a default
  7-day TTL,
* an ``HttpRegistryFetcher`` over stdlib ``urllib`` with a fixed
  scheme+host pair, response-size cap, and graceful return-``None``
  on network / HTTP error,
* a ``fetch_publish_times`` loop that dedup-then-fetch-then-parse
  walks a list of coordinates and returns the per-version timestamp
  table plus a warnings list.

Only three things actually vary between ecosystems:

  * **URL construction**: ``registry.npmjs.org/<name>`` vs
    ``pypi.org/pypi/<name>/json`` vs the Maven Central search-API
    query string.
  * **Cache-key normalization**: raw name for npm,
    PEP 503-lowercased name for PyPI, ``group:artifact`` for Maven.
  * **JSON parsing**: each registry has a different version-table
    shape.

This module owns the shared core; each per-ecosystem
``registry_fetcher.py`` is a thin adapter that plugs in the URL
builder, cache-key normalizer, and parser.

Public surface kept stable: the per-ecosystem modules still export
``FileSystemCache`` / ``HttpRegistryFetcher`` /
``RegistryMetadataFetcher`` / ``fetch_publish_times`` /
``default_cache_dir`` so callers (``core/providers/{npm,pypi,maven}.py``)
import them without changes.

Threat-model note: every HTTP request issued through this module
goes through caller-supplied URL builders. The shared
``HttpGetFetcher`` does not assemble URLs itself; the per-ecosystem
adapter is responsible for keeping the scheme + host pair fixed so
``--resolve-remote`` can't be tricked into fetching attacker-
controlled URLs.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

_DEFAULT_TTL_SECONDS = 7 * 24 * 3600
_DEFAULT_TIMEOUT = 10.0

#: Hard cap on response body size. A normal package-metadata blob is
#: ~50–200 KB; a maliciously large response shouldn't balloon scanner
#: memory. 10 MiB is generous for the largest real-world responses
#: (a popular package with thousands of releases can approach 5-8 MB)
#: while bounding the worst case.
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


# ── HTTP fetcher ─────────────────────────────────────────────────


class HttpGetFetcher:
    """Generic HTTPS GET with response-size cap and graceful failure.

    Per-ecosystem adapters wrap this with a bound URL builder
    (closes over the fixed scheme + host) so the public ``fetch``
    method on each adapter still takes the ecosystem's
    fetch-unit shape (``name`` for npm/pypi, ``(group, artifact)``
    for maven).
    """

    def __init__(
        self,
        *,
        user_agent: str = "pipeline-check-registry-fetcher",
        timeout: float = _DEFAULT_TIMEOUT,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    def get(self, url: str) -> bytes | None:
        """Issue an HTTPS GET and return the body, or ``None`` on failure.

        Caller MUST pass a fully-constructed URL with a fixed scheme
        + host (the per-ecosystem adapter is the gate); this method
        only handles the transport layer.
        """
        req = urllib.request.Request(url)  # noqa: S310, caller-fixed scheme + host
        req.add_header("User-Agent", self.user_agent)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(  # noqa: S310, caller-fixed scheme + host
                req, timeout=self.timeout,
            ) as resp:
                body: bytes = resp.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    return None
                return body
        except urllib.error.HTTPError:
            return None
        except (urllib.error.URLError, TimeoutError, OSError):
            return None


# ── Disk cache ───────────────────────────────────────────────────


def _cache_filename_for(key: str) -> str:
    """Filename-safe + Windows-260-char-safe cache filename for *key*.

    Hashes the key so any awkward characters (``/``, ``:``, ``@``,
    case-folded duplicates on a case-insensitive filesystem) collapse
    to a stable short filename.
    """
    h = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    safe = (
        key.replace("/", "_")
        .replace(":", "_")
        .replace("@", "at_")[:64]
    )
    return f"{safe}__{h}.json"


class FileSystemCache:
    """Disk-backed cache for fetcher output, keyed on a stable string.

    Default TTL is 7 days; tune with ``ttl_seconds=0`` to disable
    write-side caching while still allowing reads of unexpired
    entries. Pass ``enabled=False`` to short-circuit both read and
    write — the caller wires that up to ``--no-cache``.

    The cache is identical across npm / pypi / maven; the only
    per-ecosystem variation is the cache *key* (raw name vs
    lowercased vs ``group:artifact``), which the caller normalizes
    before handing the string in.
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
        return self.root / _cache_filename_for(key)

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


def default_cache_dir(subdir: str) -> Path:
    """Return the platform cache root + *subdir*.

    Falls back to ``~/.cache/pipeline-check/<subdir>`` when
    ``platformdirs`` is unavailable so the runtime dep set stays at
    its current size.
    """
    try:
        import platformdirs
        base = Path(platformdirs.user_cache_dir("pipeline-check"))
    except ImportError:
        base = Path.home() / ".cache" / "pipeline-check"
    return base / subdir


# ── Generic fetch loop ───────────────────────────────────────────


def fetch_publish_times_generic(
    coordinates: Iterable[Any],
    *,
    cache_key: Callable[[Any], str | None],
    fetch_blob: Callable[[Any], bytes | None],
    parser: Callable[[bytes], dict[str, _dt.datetime]],
    cache: FileSystemCache | None,
    ecosystem: str,
) -> tuple[dict[str, dict[str, _dt.datetime]], list[str]]:
    """Shared dedup + cache + fetch + parse loop.

    Returns ``({cache_key: {version: ts_utc}}, warnings)``. A
    coordinate whose metadata can't be fetched lands as a warning
    string and is omitted from the result dict — the rule reading the
    output skips silently for unresolved coordinates so a transient
    registry outage doesn't trip the cooldown gate.

    Adapter parameters:

    * ``cache_key(coordinate) -> str | None``: normalizes the
      ecosystem-specific fetch unit (a ``name`` for npm/pypi, a
      ``(group, artifact)`` tuple for maven) into a stable string
      used both as the deduplication key and as the cache filename
      input. Returning ``None`` skips that coordinate silently
      (input validation: e.g. blank name).
    * ``fetch_blob(coordinate) -> bytes | None``: hits the registry
      for the given coordinate and returns the raw response body.
      Returning ``None`` means "transient failure, surface as a
      warning and continue".
    * ``parser(blob) -> {version: ts_utc}``: projects the raw
      response body onto the per-version timestamp table the rule
      consumes. Per-ecosystem JSON shape differences live here.
    * ``ecosystem``: short label baked into the warning prose
      (``"npm"`` / ``"pypi"`` / ``"maven"``); matches the legacy
      per-module messages so existing test fixtures keep matching.
    """
    seen: set[str] = set()
    out: dict[str, dict[str, _dt.datetime]] = {}
    warnings: list[str] = []
    for coord in coordinates:
        key = cache_key(coord)
        if key is None or key in seen:
            continue
        seen.add(key)
        blob: bytes | None = cache.get(key) if cache is not None else None
        if blob is None:
            blob = fetch_blob(coord)
            if blob is None:
                warnings.append(
                    f"{ecosystem}-registry: could not fetch metadata for {key}"
                )
                continue
            if cache is not None:
                cache.put(key, blob)
        per_version = parser(blob)
        if per_version:
            out[key] = per_version
    return out, warnings


__all__ = [
    "FileSystemCache",
    "HttpGetFetcher",
    "default_cache_dir",
    "fetch_publish_times_generic",
]
