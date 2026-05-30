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
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol, TypeVar

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


# ── Shared per-package field fetch loop ──────────────────────────

_T = TypeVar("_T")


def _fetch_field(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    parser: Callable[[bytes], _T | None],
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, _T], list[str]]:
    """Dedup (PEP 503 lowercase) + cache + fetch + parse one field out
    of each PyPI JSON document.

    Shared by the provenance and repo-slug passes. Every pass reads the
    same ``pypi.org/pypi/<name>/json`` document, so running them together
    in one ``--resolve-remote`` scan (alongside the publish-time pass)
    fetches each package only once, later passes hit the disk cache.
    A package whose metadata can't be fetched lands as a warning and is
    omitted; a parser returning ``None`` (field absent / can't tell) is
    omitted so the consuming rule skips it, a parser returning ``False``
    is recorded (a meaningful "no provenance").
    """
    seen: set[str] = set()
    out: dict[str, _T] = {}
    warnings: list[str] = []
    for raw in names:
        if not isinstance(raw, str) or not raw:
            continue
        name = raw.strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        blob = cache.get(name) if cache is not None else None
        if blob is None:
            blob = fetcher.fetch(name)
            if blob is None:
                warnings.append(
                    f"pypi-registry: could not fetch metadata for {name}"
                )
                continue
            if cache is not None:
                cache.put(name, blob)
        parsed = parser(blob)
        if parsed is not None:
            out[name] = parsed
    return out, warnings


# ── PEP 740 build-provenance parser ──────────────────────────────


def _parse_has_provenance(blob: bytes) -> bool | None:
    """Whether the latest release's files carry a PEP 740 attestation.

    PyPI's JSON API lists the latest release's files under the
    top-level ``urls`` array; each file record gains a ``provenance``
    field (a URL to the provenance object) once attestations are
    published. Returns ``True`` when any file carries a populated
    ``provenance``, ``False`` when the field is present but empty on
    every file (the index exposes attestations and this release has
    none), and ``None`` when no file record carries the field at all
    (the index doesn't expose it / can't tell) so the rule skips the
    package rather than flagging an unknown as missing.
    """
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    urls = doc.get("urls")
    if not isinstance(urls, list) or not urls:
        return None
    saw_field = False
    for file_rec in urls:
        if not isinstance(file_rec, dict):
            continue
        if "provenance" in file_rec:
            saw_field = True
            if file_rec.get("provenance"):
                return True
    return False if saw_field else None


def fetch_provenance(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, bool], list[str]]:
    """Resolve PEP 740 provenance presence for every package in *names*.

    Returns ``({name: has_provenance}, warnings)``; ``False`` entries
    are the ones PYPI-019 flags, unresolved packages are omitted.
    """
    return _fetch_field(names, fetcher, _parse_has_provenance, cache)


# ── GitHub repository-slug parser ────────────────────────────────


_GITHUB_REPO_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)"
)
#: First-segment values on ``github.com/<seg>/<x>`` that are NOT a
#: repository owner (sponsor / marketplace / docs links commonly
#: appear in ``project_urls``).
_NON_OWNER_SEGMENTS = frozenset({
    "sponsors", "marketplace", "apps", "orgs", "about", "features",
})


def _parse_repo_slug(blob: bytes) -> str | None:
    """Return the ``owner/repo`` GitHub slug from a PyPI JSON document.

    Reads ``info.project_urls`` (preferring source / repository / code
    keys) plus ``info.home_page`` and searches for a
    ``github.com/owner/repo`` URL. Only GitHub is recognized (the
    OpenSSF Scorecard API is GitHub-scoped); sponsor / marketplace
    links and non-GitHub or unparseable URLs return ``None`` so the
    rule skips the package.
    """
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    info = doc.get("info") if isinstance(doc, dict) else None
    if not isinstance(info, dict):
        return None
    candidates: list[str] = []
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        preferred: list[str] = []
        other: list[str] = []
        for key, value in project_urls.items():
            if not isinstance(value, str):
                continue
            label = key.lower() if isinstance(key, str) else ""
            if any(
                tag in label
                for tag in ("source", "repository", "repo", "code", "github")
            ):
                preferred.append(value)
            else:
                other.append(value)
        candidates.extend(preferred)
        candidates.extend(other)
    for key in ("home_page", "project_url", "download_url"):
        value = info.get(key)
        if isinstance(value, str):
            candidates.append(value)
    for url in candidates:
        m = _GITHUB_REPO_RE.search(url)
        if m is None:
            continue
        owner, name = m.group(1), m.group(2).removesuffix(".git")
        if owner and name and owner.lower() not in _NON_OWNER_SEGMENTS:
            return f"{owner}/{name}"
    return None


def fetch_repo_slugs(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Resolve the GitHub ``owner/repo`` slug for every package in *names*.

    Returns ``({name: "owner/repo"}, warnings)``; packages with no
    GitHub repository in their PyPI metadata are omitted. PYPI-020
    feeds these slugs to the OpenSSF Scorecard API.
    """
    return _fetch_field(names, fetcher, _parse_repo_slug, cache)


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_provenance",
    "fetch_publish_times",
    "fetch_repo_slugs",
]
