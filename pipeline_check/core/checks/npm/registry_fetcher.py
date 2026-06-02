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
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Protocol, TypeVar

from .._primitives.provenance_ref import source_ref_from_npm_attestations
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

#: Generic value type for :func:`_fetch_packument_field`.
_T = TypeVar("_T")


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

    def fetch_attestations(self, name: str, version: str) -> bytes | None:
        """Fetch the attestation bundle for ``<name>@<version>``.

        npm serves it from ``/-/npm/v1/attestations/<name>@<version>``,
        separate from the packument. Used by NPM-017 to read the build
        provenance's source ref.
        """
        encoded = name.replace("/", "%2F")
        return self._http.get(
            f"{self.BASE_URL}/-/npm/v1/attestations/{encoded}@{version}"
        )


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


# ── Shared packument-field fetch loop ────────────────────────────


def _fetch_packument_field(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    parser: Callable[[bytes], _T | None],
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, _T], list[str]]:
    """Dedup + cache + fetch + parse one field out of each packument.

    Shared by the maintainer-count, provenance, and repo-slug passes.
    Every pass reads the same ``registry.npmjs.org/<name>`` document, so
    running them together in one ``--resolve-remote`` scan fetches each
    package only once (the second and later passes hit the disk cache
    the first one populated). A package whose metadata can't be fetched
    lands as a warning and is omitted; a package whose *parser* returns
    ``None`` (field absent / unparseable) is omitted silently so the
    consuming rule skips it rather than guessing. A parser returning
    ``False`` is recorded (that's a meaningful value, e.g. "no
    provenance"), only ``None`` is treated as "unknown".
    """
    seen: set[str] = set()
    out: dict[str, _T] = {}
    warnings: list[str] = []
    for name in names:
        if not isinstance(name, str) or not name or name in seen:
            continue
        seen.add(name)
        blob = cache.get(name) if cache is not None else None
        if blob is None:
            blob = fetcher.fetch(name)
            if blob is None:
                warnings.append(
                    f"npm-registry: could not fetch metadata for {name}"
                )
                continue
            if cache is not None:
                cache.put(name, blob)
        parsed = parser(blob)
        if parsed is not None:
            out[name] = parsed
    return out, warnings


# ── Publisher (maintainer-account) count parser ──────────────────


def _parse_maintainer_count(blob: bytes) -> int | None:
    """Count the npm accounts with publish access in a packument.

    The top-level ``maintainers`` array on an npm packument lists the
    npm accounts that can publish the package (npm's own
    ``maintainers`` field, distinct from a repo's GitHub contributor
    list). A length of one is the single-publisher / single-point-of-
    compromise signal NPM-014 flags. Returns ``None`` when the array
    is absent or unparseable so the rule skips the package rather than
    treating "unknown" as "single".
    """
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    maintainers = doc.get("maintainers")
    if not isinstance(maintainers, list):
        return None
    count = sum(
        1 for m in maintainers
        if isinstance(m, dict) and isinstance(m.get("name"), str) and m["name"]
    )
    return count or None


def fetch_maintainer_counts(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, int], list[str]]:
    """Resolve the publisher count for every package in *names*.

    Reads the ``maintainers`` array from each packument (shared cache,
    so it adds no fetch when run alongside the publish-time pass).
    Returns ``({name: publisher_count}, warnings)``; an unresolved
    package is omitted so NPM-014 skips it silently.
    """
    return _fetch_packument_field(
        names, fetcher, _parse_maintainer_count, cache,
    )


# ── Build-provenance parser ──────────────────────────────────────


def _parse_has_provenance(blob: bytes) -> bool | None:
    """Whether the package's latest version ships a provenance attestation.

    npm records a build-provenance attestation under
    ``versions[<v>].dist.attestations`` for any version published with
    ``--provenance``. We read the ``dist-tags.latest`` version as the
    package's current provenance posture: ``True`` when that version
    carries an attestation, ``False`` when it doesn't, ``None`` when the
    packument doesn't let us tell (so the rule skips it rather than
    flagging an unknown as missing).
    """
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    dist_tags = doc.get("dist-tags")
    if not isinstance(dist_tags, dict):
        return None
    latest = dist_tags.get("latest")
    if not isinstance(latest, str) or not latest:
        return None
    versions = doc.get("versions")
    if not isinstance(versions, dict):
        return None
    version = versions.get(latest)
    if not isinstance(version, dict):
        return None
    dist = version.get("dist")
    if not isinstance(dist, dict):
        return None
    return bool(dist.get("attestations"))


def fetch_provenance(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, bool], list[str]]:
    """Resolve build-provenance presence for every package in *names*.

    Reads ``dist.attestations`` on the latest version from each
    packument (shared cache, no extra fetch alongside the other passes).
    Returns ``({name: has_provenance}, warnings)``; ``False`` entries
    are the ones NPM-015 flags, unresolved packages are omitted.
    """
    return _fetch_packument_field(
        names, fetcher, _parse_has_provenance, cache,
    )


# ── GitHub repository-slug parser ────────────────────────────────


_GITHUB_REPO_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)"
)


def _parse_repo_slug(blob: bytes) -> str | None:
    """Return the ``owner/repo`` GitHub slug from a packument, or None.

    Reads the packument ``repository`` field (a string or a ``{url}``
    dict) and handles the ``git+https`` / ``git+ssh`` / ``https`` URL
    shapes plus the ``github:owner/repo`` shorthand. Only GitHub is
    recognized (the OpenSSF Scorecard API NPM-016 queries is
    GitHub-scoped); a non-GitHub or unparseable repository returns None
    so the rule skips the package.
    """
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    repo = doc.get("repository")
    if isinstance(repo, str):
        url = repo
    elif isinstance(repo, dict) and isinstance(repo.get("url"), str):
        url = repo["url"]
    else:
        return None
    url = url.strip()
    if url.startswith("github:"):
        rest = url[len("github:"):].strip().strip("/")
        parts = rest.split("/")
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"{parts[0]}/{parts[1].removesuffix('.git')}"
        return None
    m = _GITHUB_REPO_RE.search(url)
    if m is None:
        return None
    owner, name = m.group(1), m.group(2).removesuffix(".git")
    if not owner or not name:
        return None
    return f"{owner}/{name}"


def fetch_repo_slugs(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Resolve the GitHub ``owner/repo`` slug for every package in *names*.

    Reads the ``repository`` field from each packument (shared cache, so
    no extra fetch alongside the other passes). Returns
    ``({name: "owner/repo"}, warnings)``; packages with no GitHub
    repository are omitted. NPM-016 feeds these slugs to the OpenSSF
    Scorecard API.
    """
    return _fetch_packument_field(
        names, fetcher, _parse_repo_slug, cache,
    )


def _parse_latest_attested_version(blob: bytes) -> str | None:
    """Return the ``dist-tags.latest`` version IFF it ships provenance.

    Mirrors :func:`_parse_has_provenance` but returns the version string
    (so the attestation bundle can be fetched) only when that version
    carries a ``dist.attestations`` entry; ``None`` otherwise.
    """
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    dist_tags = doc.get("dist-tags")
    if not isinstance(dist_tags, dict):
        return None
    latest = dist_tags.get("latest")
    if not isinstance(latest, str) or not latest:
        return None
    versions = doc.get("versions")
    if not isinstance(versions, dict):
        return None
    version = versions.get(latest)
    if not isinstance(version, dict):
        return None
    dist = version.get("dist")
    if not isinstance(dist, dict):
        return None
    if not dist.get("attestations"):
        return None
    return latest


def fetch_provenance_refs(
    names: Iterable[str],
    fetcher: RegistryMetadataFetcher,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, str], list[str]]:
    """Resolve the build-provenance *source ref* for packages that ship one.

    Two-stage: read each packument (shared name-keyed cache, so no extra
    fetch alongside the other ``--resolve-remote`` passes) to find the
    latest attested version, then fetch that version's attestation bundle
    and parse the SLSA source ref. Only packages whose latest version
    both ships provenance AND exposes a parseable ref are returned;
    everything else is omitted so NPM-017 skips unknowns rather than
    flagging them. Needs a fetcher exposing ``fetch_attestations``;
    without it the pass is a no-op. Packages with no provenance are
    NPM-015's concern and are silently skipped here.
    """
    fetch_att = getattr(fetcher, "fetch_attestations", None)
    seen: set[str] = set()
    out: dict[str, str] = {}
    warnings: list[str] = []
    for name in names:
        if not isinstance(name, str) or not name or name in seen:
            continue
        seen.add(name)
        blob = cache.get(name) if cache is not None else None
        if blob is None:
            blob = fetcher.fetch(name)
            if blob is None:
                continue  # unfetchable metadata: NPM-015 already warns
            if cache is not None:
                cache.put(name, blob)
        version = _parse_latest_attested_version(blob)
        if version is None or fetch_att is None:
            continue
        att_key = f"{name}@{version}::attestations"
        att_blob = cache.get(att_key) if cache is not None else None
        if att_blob is None:
            att_blob = fetch_att(name, version)
            if att_blob is None:
                warnings.append(
                    f"npm-registry: could not fetch attestations for "
                    f"{name}@{version}"
                )
                continue
            if cache is not None:
                cache.put(att_key, att_blob)
        try:
            bundle = json.loads(att_blob)
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(bundle, dict):
            continue
        ref = source_ref_from_npm_attestations(bundle)
        if ref:
            out[name] = ref
    return out, warnings


__all__ = [
    "FileSystemCache",
    "HttpRegistryFetcher",
    "RegistryMetadataFetcher",
    "default_cache_dir",
    "fetch_maintainer_counts",
    "fetch_provenance",
    "fetch_provenance_refs",
    "fetch_publish_times",
    "fetch_repo_slugs",
]
