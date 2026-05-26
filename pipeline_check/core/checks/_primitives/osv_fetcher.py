"""OSV.dev API client for live vulnerability lookup.

Queries ``https://api.osv.dev/v1/querybatch`` for known advisories
affecting exact ``(package, version, ecosystem)`` tuples. Gated on
``--resolve-remote`` so the default scan is hermetic.

Reuses the :class:`FileSystemCache` from :mod:`registry_fetcher`
for 24-hour advisory caching. Clean hits (no advisories) are cached
as empty lists so a package with zero advisories is not re-queried
on every run.
"""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any

from .registry_fetcher import FileSystemCache

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_TIMEOUT_S = 30
_MAX_BATCH = 1000
_EMPTY_SENTINEL = "[]"


@dataclass(frozen=True, slots=True)
class OsvAdvisory:
    id: str
    summary: str
    severity: str
    aliases: tuple[str, ...]


def query_osv_batch(
    queries: list[tuple[str, str, str]],
    cache: FileSystemCache | None = None,
    warnings: list[str] | None = None,
) -> dict[tuple[str, str], list[OsvAdvisory]]:
    """Query OSV for a batch of (name, version, ecosystem) tuples.

    Deduplicates input, checks the cache, batches uncached queries,
    caches all results (including clean hits). Returns a dict keyed
    by ``(name, version)`` with lists of matching advisories.
    """
    results: dict[tuple[str, str], list[OsvAdvisory]] = {}

    seen: set[tuple[str, str, str]] = set()
    unique: list[tuple[str, str, str]] = []
    for q in queries:
        if q not in seen:
            seen.add(q)
            unique.append(q)

    uncached: list[tuple[str, str, str]] = []
    for name, version, ecosystem in unique:
        key = _cache_key(name, version, ecosystem)
        if cache is not None:
            cached = cache.get(key)
            if cached is not None:
                advisories = _parse_vulns(cached.decode("utf-8"))
                if advisories:
                    results[(name, version)] = advisories
                continue
        uncached.append((name, version, ecosystem))

    for batch_start in range(0, len(uncached), _MAX_BATCH):
        batch = uncached[batch_start:batch_start + _MAX_BATCH]
        batch_results, error = _fetch_batch(batch)
        if error and warnings is not None:
            warnings.append(
                f"[osv] batch query failed ({error}); "
                f"{len(batch)} package(s) not checked"
            )
        if error:
            continue
        for i, (name, version, ecosystem) in enumerate(batch):
            vulns = batch_results.get(i, [])
            raw = json.dumps(vulns) if vulns else _EMPTY_SENTINEL
            if cache is not None:
                cache.put(_cache_key(name, version, ecosystem), raw.encode("utf-8"))
            advisories = _parse_vulns(raw)
            if advisories:
                results[(name, version)] = advisories

    return results


def _cache_key(name: str, version: str, ecosystem: str) -> str:
    return f"osv:{ecosystem}:{name}:{version}"


def _fetch_batch(
    queries: list[tuple[str, str, str]],
) -> tuple[dict[int, list[dict[str, Any]]], str | None]:
    """POST a batch to OSV. Returns (results_by_index, error_msg_or_None)."""
    payload = {
        "queries": [
            {
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version,
            }
            for name, version, ecosystem in queries
        ]
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        _OSV_BATCH_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310
            body = json.loads(resp.read(10 * 1024 * 1024))
    except Exception as exc:  # noqa: BLE001
        return {}, str(exc)

    results: dict[int, list[dict[str, Any]]] = {}
    for i, entry in enumerate(body.get("results", [])):
        vulns = entry.get("vulns", [])
        if vulns:
            results[i] = vulns
    return results, None


def _parse_vulns(raw: str) -> list[OsvAdvisory]:
    try:
        vulns = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(vulns, list):
        return []
    advisories: list[OsvAdvisory] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        osv_id = v.get("id", "")
        summary = v.get("summary", "")
        aliases = tuple(v.get("aliases", []))
        severity = _extract_severity(v)
        advisories.append(OsvAdvisory(
            id=osv_id, summary=summary,
            severity=severity, aliases=aliases,
        ))
    return advisories


def _extract_severity(vuln: dict[str, Any]) -> str:
    for sev in vuln.get("severity", []):
        if isinstance(sev, dict) and sev.get("type") == "CVSS_V3":
            score_val = sev.get("score", "")
            if isinstance(score_val, (int, float)):
                return _cvss_rating(float(score_val))
            if isinstance(score_val, str):
                # OSV stores the CVSS vector string (e.g.
                # "CVSS:3.1/AV:N/AC:L/..."), not a numeric score.
                # The version prefix ("3.1") is NOT the base score.
                # Try to parse a plain float first (some feeds use
                # a numeric string); otherwise fall through.
                if "/" not in score_val:
                    try:
                        return _cvss_rating(float(score_val))
                    except ValueError:
                        pass
    db_sev = vuln.get("database_specific", {})
    if isinstance(db_sev, dict):
        raw = db_sev.get("severity")
        if isinstance(raw, str):
            normalized = raw.upper()
            if normalized in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return normalized
            if normalized == "MODERATE":
                return "MEDIUM"
    return "HIGH"


def _cvss_rating(base: float) -> str:
    if base >= 9.0:
        return "CRITICAL"
    if base >= 7.0:
        return "HIGH"
    if base >= 4.0:
        return "MEDIUM"
    return "LOW"
