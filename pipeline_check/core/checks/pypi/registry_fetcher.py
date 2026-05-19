"""PyPI registry metadata fetcher.

Mirrors the NPM ``registry_fetcher`` template (Protocol + HTTP
impl + disk cache + graceful failure) but targets the PyPI JSON
API (``https://pypi.org/pypi/<name>/json``) to recover per-version
upload timestamps for PYPI-008 (cooldown gate).

PyPI's JSON shape differs from npm's: per-version metadata lives
under ``releases.<version>`` as a list of file records (sdist +
each wheel), each carrying an ``upload_time_iso_8601`` timestamp.
The per-version timestamp is the minimum across the file records
for that version (the moment the FIRST artifact for that release
landed on the index).

Architecture
------------

* :class:`RegistryMetadataFetcher` is a Protocol. Any object with
  a ``fetch(name) -> bytes | None`` works.
* :class:`HttpRegistryFetcher` hits the PyPI JSON API via stdlib
  ``urllib`` (no extra dep). Returns ``None`` on 404 / network
  error so the caller records a warning but the scan keeps going.
* :class:`FileSystemCache` caches per-package JSON by name with a
  default 7-day TTL. Tunable via ``--no-cache``.
* :func:`fetch_publish_times` walks a list of package names and
  returns ``{name: {version: timestamp_utc}}`` for every
  successfully-resolved package. Failures land in the warnings.

Threat-model note: this module issues HTTPS requests to
``pypi.org``. It's opt-in via ``--resolve-remote`` at the CLI;
this module never reads the network unless a fetcher with a real
implementation is passed in.
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

#: Hard cap on response body size. A normal PyPI JSON blob is
#: ~50–200 KB; a maliciously large response shouldn't be allowed
#: to balloon scanner memory. 10 MiB is generous for the largest
#: real-world packument (a popular package with thousands of file
#: records across many versions might approach 5-8 MB).
_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


# ── Fetcher protocol + implementations ────────────────────────────


class RegistryMetadataFetcher(Protocol):
    """Fetch a package's JSON metadata blob from a PyPI-style index."""

    def fetch(self, name: str) -> bytes | None:
        ...


class HttpRegistryFetcher:
    """Fetch via ``pypi.org/pypi/<name>/json``.

    Public-only — PyPI metadata is open. Returns ``None`` on
    404 / 401 / network error so the caller records a warning
    and proceeds.
    """

    BASE_URL = "https://pypi.org/pypi"

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    def fetch(self, name: str) -> bytes | None:
        # PEP 503 normalization: lowercase, runs of ``_ . -`` collapse
        # to a single ``-``. The PyPI JSON API actually accepts both
        # canonical and original names but normalizing protects the
        # cache key from duplicate fetches for ``Pillow`` vs
        # ``pillow`` vs ``pil_low``.
        encoded = name.strip().lower()
        url = f"{self.BASE_URL}/{encoded}/json"
        req = urllib.request.Request(url)  # noqa: S310, fixed scheme + host
        req.add_header("User-Agent", "pipeline-check-pypi-fetcher")
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
    """Filename-safe key for a PyPI package name.

    Hashes the name so any weird characters end up on disk as a
    stable, short filename that survives Windows' 260-char limit
    and case-folding.
    """
    normalized = name.strip().lower()
    h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    safe = normalized.replace("/", "_")[:64]
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
    """Return the platform-appropriate cache root for PyPI metadata.

    Falls back to ``~/.cache/pipeline-check/pypi-registry`` when
    ``platformdirs`` is unavailable so we don't take a hard dep
    just for one path.
    """
    try:
        import platformdirs
        base = Path(platformdirs.user_cache_dir("pipeline-check"))
    except ImportError:
        base = Path.home() / ".cache" / "pipeline-check"
    return base / "pypi-registry"


# ── Top-level convenience ────────────────────────────────────────


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


def fetch_publish_times(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, dict[str, _dt.datetime]], list[str]]:
    """Resolve publish timestamps for every package in *names*.

    Returns ``({name: {version: ts_utc}}, warnings)``. A package
    whose metadata can't be fetched lands as a warning string and
    is omitted from the result dict — the rule reading the output
    skips silently for unresolved packages so a transient PyPI
    outage doesn't trip the cooldown gate on the next CI run.

    Deduplicates *names* internally (PEP 503 normalized) so the
    same package isn't fetched twice when it appears under
    different cases in different requirements files.
    """
    seen: set[str] = set()
    out: dict[str, dict[str, _dt.datetime]] = {}
    warnings: list[str] = []
    for name in names:
        if not isinstance(name, str) or not name:
            continue
        normalized = name.strip().lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        blob: bytes | None = (
            cache.get(normalized) if cache is not None else None
        )
        if blob is None:
            blob = fetcher.fetch(normalized)
            if blob is None:
                warnings.append(
                    f"pypi-registry: could not fetch metadata for "
                    f"{normalized}"
                )
                continue
            if cache is not None:
                cache.put(normalized, blob)
        per_version = _parse_publish_times(blob)
        if per_version:
            out[normalized] = per_version
    return out, warnings


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_publish_times",
]
