"""OpenSSF Scorecard API client.

Read-only, cached lookups of a GitHub repository's OpenSSF Scorecard
from ``https://api.securityscorecards.dev``, used by NPM-016 to surface
direct dependencies whose upstream repo scores poorly or fails the
Dangerous-Workflow check.

Opt-in: callers only reach the network when the CLI is run with
``--resolve-remote``. Every failure mode (network error, 404 for a repo
the Scorecard project hasn't indexed, malformed body) degrades to
"return nothing" so a transient outage never fails a scan, the same
strictly-additive contract the npm registry and OSV fetchers use.

Public surface: :class:`ScorecardResult`, :func:`fetch_scorecards`,
:func:`scorecard_cache_dir`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .registry_fetcher import (
    FileSystemCache,
    HttpGetFetcher,
    default_cache_dir,
)

_BASE_URL = "https://api.securityscorecards.dev/projects/github.com"


@dataclass(frozen=True, slots=True)
class ScorecardResult:
    """A repository's OpenSSF Scorecard, reduced to what NPM-016 needs.

    ``score`` is the aggregate 0.0-10.0 score. ``dangerous_workflow_failed``
    is True when the Dangerous-Workflow check scored 0 (an exploitable
    ``pull_request_target`` / script-injection pattern was found in the
    repo's own workflows).
    """

    score: float
    dangerous_workflow_failed: bool


def scorecard_cache_dir() -> Path:
    """Platform cache root + ``openssf-scorecard/``."""
    return default_cache_dir("openssf-scorecard")


def _parse_scorecard(blob: bytes) -> ScorecardResult | None:
    """Project a Scorecard API JSON body onto a :class:`ScorecardResult`.

    Returns ``None`` when the body has no numeric aggregate ``score`` so
    the caller skips the package rather than recording a bogus zero.
    """
    try:
        doc = json.loads(blob)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    score = doc.get("score")
    if not isinstance(score, (int, float)):
        return None
    dangerous_workflow_failed = False
    checks = doc.get("checks")
    if isinstance(checks, list):
        for check in checks:
            if not isinstance(check, dict):
                continue
            if check.get("name") != "Dangerous-Workflow":
                continue
            cscore = check.get("score")
            # Scorecard checks score 0-10; 0 means the check failed
            # (a dangerous pattern was found). -1 is inconclusive and
            # is not treated as a failure.
            if isinstance(cscore, (int, float)) and cscore == 0:
                dangerous_workflow_failed = True
    return ScorecardResult(
        score=float(score),
        dangerous_workflow_failed=dangerous_workflow_failed,
    )


def fetch_scorecards(
    slugs_by_package: dict[str, str],
    http: HttpGetFetcher | None = None,
    cache: FileSystemCache | None = None,
) -> tuple[dict[str, ScorecardResult], list[str]]:
    """Fetch the Scorecard for each ``{package_name: "owner/repo"}`` entry.

    Deduplicates by slug so two packages that share a monorepo repository
    hit the API once. Returns ``({package_name: ScorecardResult},
    warnings)``; a package whose repo can't be fetched or parsed is
    omitted so NPM-016 skips it silently.
    """
    http = http or HttpGetFetcher(user_agent="pipeline-check-scorecard")
    out: dict[str, ScorecardResult] = {}
    warnings: list[str] = []
    by_slug: dict[str, ScorecardResult | None] = {}
    for package, slug in slugs_by_package.items():
        if not isinstance(slug, str) or slug.count("/") != 1:
            continue
        if slug not in by_slug:
            blob = cache.get(slug) if cache is not None else None
            if blob is None:
                blob = http.get(f"{_BASE_URL}/{slug}")
                if blob is None:
                    warnings.append(
                        f"openssf-scorecard: could not fetch {slug}"
                    )
                    by_slug[slug] = None
                    continue
                if cache is not None:
                    cache.put(slug, blob)
            by_slug[slug] = _parse_scorecard(blob)
        result = by_slug[slug]
        if result is not None:
            out[package] = result
    return out, warnings


__all__ = [
    "ScorecardResult",
    "fetch_scorecards",
    "scorecard_cache_dir",
]
