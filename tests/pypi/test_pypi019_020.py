"""Tests for PYPI-019 (PEP 740 provenance gap) and PYPI-020 (Scorecard).

Three layers, no network:

1. ``registry_fetcher`` unit tests: ``_parse_has_provenance`` and
   ``_parse_repo_slug`` over PyPI JSON blobs; ``fetch_provenance`` /
   ``fetch_repo_slugs`` dedup / cache / 404 paths with a stub fetcher.
2. ``check`` behavior for both rules: silent pass with no metadata,
   fires on the offending signal, passes the clean case, skips
   unresolved packages.
"""
from __future__ import annotations

import json

from pipeline_check.core.checks._primitives.scorecard import ScorecardResult
from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.pypi.base import (
    PypiContext,
    RequirementsFile,
    _parse_requirements,
)
from pipeline_check.core.checks.pypi.pipelines import PypiChecks
from pipeline_check.core.checks.pypi.registry_fetcher import (
    FileSystemCache,
    _parse_has_provenance,
    _parse_repo_slug,
    fetch_provenance,
    fetch_repo_slugs,
)


def _ctx_from(text: str) -> PypiContext:
    lines, options = _parse_requirements(text)
    return PypiContext([RequirementsFile(
        path="requirements.txt", text=text, lines=lines, options=options,
    )])


def _run(ctx: PypiContext, check_id: str):
    findings = [f for f in PypiChecks(ctx).run() if f.check_id == check_id]
    assert len(findings) == 1, f"exactly one {check_id} finding"
    return findings[0]


def _blob(doc: dict) -> bytes:
    return json.dumps(doc).encode("utf-8")


# ── _parse_has_provenance ────────────────────────────────────────


class TestParseHasProvenance:
    def test_true_when_a_file_has_provenance(self):
        blob = _blob({"urls": [
            {"filename": "x.whl", "provenance": "https://pypi.org/p"},
        ]})
        assert _parse_has_provenance(blob) is True

    def test_false_when_field_present_but_empty(self):
        blob = _blob({"urls": [{"filename": "x.whl", "provenance": None}]})
        assert _parse_has_provenance(blob) is False

    def test_none_when_field_absent(self):
        # Index doesn't expose attestations — don't flag everything.
        blob = _blob({"urls": [{"filename": "x.whl"}]})
        assert _parse_has_provenance(blob) is None

    def test_none_when_no_files(self):
        assert _parse_has_provenance(_blob({"urls": []})) is None

    def test_none_on_garbage(self):
        assert _parse_has_provenance(b"{not json") is None


# ── _parse_repo_slug ─────────────────────────────────────────────


class TestParseRepoSlug:
    def test_project_urls_source_key(self):
        blob = _blob({"info": {"project_urls": {
            "Source": "https://github.com/owner/repo",
        }}})
        assert _parse_repo_slug(blob) == "owner/repo"

    def test_home_page_fallback(self):
        blob = _blob({"info": {
            "home_page": "https://github.com/owner/repo",
            "project_urls": {"Docs": "https://example.com"},
        }})
        assert _parse_repo_slug(blob) == "owner/repo"

    def test_sponsors_link_excluded(self):
        blob = _blob({"info": {"project_urls": {
            "Funding": "https://github.com/sponsors/owner",
        }}})
        assert _parse_repo_slug(blob) is None

    def test_non_github_returns_none(self):
        blob = _blob({"info": {"project_urls": {
            "Homepage": "https://gitlab.com/o/r",
        }}})
        assert _parse_repo_slug(blob) is None

    def test_strips_git_suffix(self):
        blob = _blob({"info": {"project_urls": {
            "Repository": "https://github.com/owner/repo.git",
        }}})
        assert _parse_repo_slug(blob) == "owner/repo"


# ── fetch_provenance / fetch_repo_slugs (stub fetcher) ───────────


class _StubFetcher:
    def __init__(self, payloads: dict[str, bytes | None]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def fetch(self, name: str) -> bytes | None:
        self.calls.append(name)
        return self.payloads.get(name.strip().lower())


class TestFetchHelpers:
    def test_fetch_provenance_records_false(self):
        f = _StubFetcher({"foo": _blob({"urls": [{"provenance": None}]})})
        out, warnings = fetch_provenance(["foo"], f)
        assert out == {"foo": False}
        assert warnings == []

    def test_fetch_provenance_dedups_case(self):
        f = _StubFetcher({"foo": _blob({"urls": [{"provenance": "u"}]})})
        fetch_provenance(["Foo", "foo", "FOO"], f)
        assert f.calls == ["foo"]  # one fetch for case variants

    def test_fetch_provenance_404_warns(self):
        f = _StubFetcher({"foo": None})
        out, warnings = fetch_provenance(["foo"], f)
        assert out == {} and warnings and "foo" in warnings[0]

    def test_fetch_repo_slugs_maps(self):
        f = _StubFetcher({"foo": _blob({"info": {"project_urls": {
            "Source": "https://github.com/o/r",
        }}})})
        out, _ = fetch_repo_slugs(["foo"], f)
        assert out == {"foo": "o/r"}

    def test_cache_short_circuits(self, tmp_path):
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("foo", _blob({"urls": [{"provenance": "u"}]}))
        f = _StubFetcher({})  # would 404 if fetched
        out, _ = fetch_provenance(["foo"], f, cache=cache)
        assert out == {"foo": True} and f.calls == []


# ── PYPI-019 rule ────────────────────────────────────────────────


class TestPypi019:
    def test_silent_pass_when_no_metadata(self):
        f = _run(_ctx_from("foo==1.0.0\n"), "PYPI-019")
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_missing_provenance(self):
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.provenance = {"foo": False}
        f = _run(ctx, "PYPI-019")
        assert f.passed is False
        assert "foo" in f.description
        assert f.severity is Severity.LOW

    def test_passes_with_provenance(self):
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.provenance = {"foo": True}
        f = _run(ctx, "PYPI-019")
        assert f.passed is True

    def test_skips_unresolved(self):
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.provenance = {"bar": False}
        f = _run(ctx, "PYPI-019")
        assert f.passed is True


# ── PYPI-020 rule ────────────────────────────────────────────────


class TestPypi020:
    def test_silent_pass_when_no_metadata(self):
        f = _run(_ctx_from("foo==1.0.0\n"), "PYPI-020")
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_low_score(self):
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.scorecards = {"foo": ScorecardResult(score=3.1, dangerous_workflow_failed=False)}
        f = _run(ctx, "PYPI-020")
        assert f.passed is False
        assert "foo" in f.description

    def test_fires_on_dangerous_workflow(self):
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.scorecards = {"foo": ScorecardResult(score=8.0, dangerous_workflow_failed=True)}
        f = _run(ctx, "PYPI-020")
        assert f.passed is False

    def test_passes_healthy_repo(self):
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.scorecards = {"foo": ScorecardResult(score=8.5, dangerous_workflow_failed=False)}
        f = _run(ctx, "PYPI-020")
        assert f.passed is True

    def test_skips_unresolved(self):
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.scorecards = {"bar": ScorecardResult(score=1.0, dangerous_workflow_failed=False)}
        f = _run(ctx, "PYPI-020")
        assert f.passed is True
