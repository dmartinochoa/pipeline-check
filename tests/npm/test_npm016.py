"""Per-rule tests for NPM-016 (low OpenSSF Scorecard).

Covers three layers:

1. ``_parse_repo_slug`` (npm registry_fetcher): extracts the GitHub
   owner/repo from the packument's ``repository`` field across URL shapes.
2. ``scorecard`` primitive: ``_parse_scorecard`` + ``fetch_scorecards``
   dedup/cache/graceful paths (no network — stub HTTP).
3. ``check`` behavior: silent pass with no metadata, fires on a low
   score and on a dangerous-workflow failure, passes a healthy repo,
   skips unresolved packages.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline_check.core.checks._primitives.scorecard import (
    ScorecardResult,
    _parse_scorecard,
    fetch_scorecards,
)
from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.npm.base import NpmContext, NpmManifest
from pipeline_check.core.checks.npm.pipelines import NpmChecks
from pipeline_check.core.checks.npm.registry_fetcher import _parse_repo_slug


def _manifest(deps: dict[str, str]) -> NpmManifest:
    data: dict = {"name": "synthetic", "version": "0.0.0", "dependencies": deps}
    return NpmManifest(
        path="package.json", text=json.dumps(data, indent=2), data=data,
    )


# ── _parse_repo_slug ─────────────────────────────────────────────


class TestParseRepoSlug:
    def test_git_https_url_with_suffix(self) -> None:
        blob = json.dumps({
            "repository": {"type": "git", "url": "git+https://github.com/sindresorhus/chalk.git"},
        }).encode("utf-8")
        assert _parse_repo_slug(blob) == "sindresorhus/chalk"

    def test_plain_https_string(self) -> None:
        blob = json.dumps({
            "repository": "https://github.com/owner/repo",
        }).encode("utf-8")
        assert _parse_repo_slug(blob) == "owner/repo"

    def test_github_shorthand(self) -> None:
        blob = json.dumps({"repository": "github:owner/repo"}).encode("utf-8")
        assert _parse_repo_slug(blob) == "owner/repo"

    def test_git_ssh_url(self) -> None:
        blob = json.dumps({
            "repository": {"url": "git+ssh://git@github.com/owner/repo.git"},
        }).encode("utf-8")
        assert _parse_repo_slug(blob) == "owner/repo"

    def test_non_github_returns_none(self) -> None:
        blob = json.dumps({
            "repository": "https://gitlab.com/owner/repo",
        }).encode("utf-8")
        assert _parse_repo_slug(blob) is None

    def test_missing_repository_returns_none(self) -> None:
        assert _parse_repo_slug(json.dumps({"name": "x"}).encode("utf-8")) is None


# ── _parse_scorecard ─────────────────────────────────────────────


def _scorecard_blob(score: float, dw_score: float | None = None) -> bytes:
    doc: dict = {"score": score, "checks": []}
    if dw_score is not None:
        doc["checks"].append({"name": "Dangerous-Workflow", "score": dw_score})
    return json.dumps(doc).encode("utf-8")


class TestParseScorecard:
    def test_score_and_no_dangerous_workflow(self) -> None:
        r = _parse_scorecard(_scorecard_blob(7.8, dw_score=10))
        assert r == ScorecardResult(score=7.8, dangerous_workflow_failed=False)

    def test_dangerous_workflow_failed(self) -> None:
        r = _parse_scorecard(_scorecard_blob(6.0, dw_score=0))
        assert r is not None and r.dangerous_workflow_failed is True

    def test_inconclusive_dangerous_workflow_not_failed(self) -> None:
        r = _parse_scorecard(_scorecard_blob(6.0, dw_score=-1))
        assert r is not None and r.dangerous_workflow_failed is False

    def test_missing_score_returns_none(self) -> None:
        assert _parse_scorecard(b'{"checks": []}') is None

    def test_non_json_returns_none(self) -> None:
        assert _parse_scorecard(b"{not json") is None


# ── fetch_scorecards (stub HTTP) ─────────────────────────────────


class _StubHttp:
    def __init__(self, payloads: dict[str, bytes | None]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def get(self, url: str) -> bytes | None:
        self.calls.append(url)
        slug = url.rsplit("/projects/github.com/", 1)[-1]
        return self.payloads.get(slug)


class TestFetchScorecards:
    def test_maps_package_to_result(self) -> None:
        http = _StubHttp({"o/r": _scorecard_blob(4.2)})
        out, warnings = fetch_scorecards({"foo": "o/r"}, http=http)
        assert out["foo"].score == 4.2
        assert warnings == []

    def test_dedups_shared_slug(self) -> None:
        http = _StubHttp({"o/r": _scorecard_blob(8.0)})
        fetch_scorecards({"foo": "o/r", "bar": "o/r"}, http=http)
        assert len(http.calls) == 1  # one API hit for two packages

    def test_failure_surfaces_warning(self) -> None:
        http = _StubHttp({"o/r": None})
        out, warnings = fetch_scorecards({"foo": "o/r"}, http=http)
        assert out == {}
        assert warnings and "o/r" in warnings[0]

    def test_cache_short_circuits(self, tmp_path: Path) -> None:
        from pipeline_check.core.checks._primitives.scorecard import (
            FileSystemCache,
        )
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("o/r", _scorecard_blob(2.0))
        http = _StubHttp({})  # would fail if called
        out, _ = fetch_scorecards({"foo": "o/r"}, http=http, cache=cache)
        assert out["foo"].score == 2.0
        assert http.calls == []


# ── NPM-016 rule via NpmChecks dispatch ──────────────────────────


def _run_npm016(ctx: NpmContext):
    findings = [f for f in NpmChecks(ctx).run() if f.check_id == "NPM-016"]
    assert len(findings) == 1, "exactly one NPM-016 finding per manifest"
    return findings[0]


class TestNpm016Rule:
    def test_silent_pass_when_no_metadata(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        f = _run_npm016(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_low_score(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.scorecards = {"foo": ScorecardResult(score=3.1, dangerous_workflow_failed=False)}
        f = _run_npm016(ctx)
        assert f.passed is False
        assert "dependencies.foo" in f.description
        assert f.severity is Severity.LOW

    def test_fires_on_dangerous_workflow_even_if_score_ok(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.scorecards = {"foo": ScorecardResult(score=8.0, dangerous_workflow_failed=True)}
        f = _run_npm016(ctx)
        assert f.passed is False

    def test_passes_healthy_repo(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.scorecards = {"foo": ScorecardResult(score=8.5, dangerous_workflow_failed=False)}
        f = _run_npm016(ctx)
        assert f.passed is True

    def test_unresolved_package_skipped(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.scorecards = {"bar": ScorecardResult(score=1.0, dangerous_workflow_failed=False)}
        f = _run_npm016(ctx)
        assert f.passed is True

    def test_confidence_default_high(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.scorecards = {"foo": ScorecardResult(score=2.0, dangerous_workflow_failed=False)}
        f = _run_npm016(ctx)
        assert f.confidence is Confidence.HIGH
        assert f.severity is Severity.LOW
