"""Per-rule tests for NPM-014 (single-publisher supply-chain risk).

Covers both layers:

1. ``registry_fetcher`` unit tests: ``_parse_maintainer_count`` happy /
   malformed paths and ``fetch_maintainer_counts`` dedup + cache +
   warning surfacing.
2. ``check`` behavior: silent pass when ``maintainer_counts`` is empty
   (no ``--resolve-remote``), fires on a single-publisher direct dep,
   passes for a multi-publisher one, skips unresolved packages, and
   covers devDependencies.

No network — every test uses a stub fetcher or sets the context map
directly.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.npm.base import NpmContext, NpmManifest
from pipeline_check.core.checks.npm.pipelines import NpmChecks
from pipeline_check.core.checks.npm.registry_fetcher import (
    FileSystemCache,
    _parse_maintainer_count,
    fetch_maintainer_counts,
)


def _manifest(
    deps: dict[str, str], dev_deps: dict[str, str] | None = None,
) -> NpmManifest:
    data: dict = {"name": "synthetic", "version": "0.0.0"}
    if deps:
        data["dependencies"] = deps
    if dev_deps:
        data["devDependencies"] = dev_deps
    return NpmManifest(
        path="package.json",
        text=json.dumps(data, indent=2),
        data=data,
    )


# ── _parse_maintainer_count ──────────────────────────────────────


class TestParseMaintainerCount:
    def test_counts_named_maintainers(self) -> None:
        blob = json.dumps({
            "name": "foo",
            "maintainers": [
                {"name": "alice", "email": "a@x.com"},
                {"name": "bob", "email": "b@x.com"},
            ],
        }).encode("utf-8")
        assert _parse_maintainer_count(blob) == 2

    def test_single_publisher(self) -> None:
        blob = json.dumps({
            "maintainers": [{"name": "solo", "email": "s@x.com"}],
        }).encode("utf-8")
        assert _parse_maintainer_count(blob) == 1

    def test_missing_array_returns_none(self) -> None:
        blob = json.dumps({"name": "foo"}).encode("utf-8")
        assert _parse_maintainer_count(blob) is None

    def test_empty_array_returns_none(self) -> None:
        # An empty (or all-nameless) maintainers array reads as "unknown",
        # not "single", so the rule skips it.
        assert _parse_maintainer_count(b'{"maintainers": []}') is None
        assert _parse_maintainer_count(b'{"maintainers": [{}]}') is None

    def test_non_json_returns_none(self) -> None:
        assert _parse_maintainer_count(b"{not json") is None

    def test_top_level_non_dict_returns_none(self) -> None:
        assert _parse_maintainer_count(b"[]") is None


# ── fetch_maintainer_counts (with stub fetcher) ──────────────────


class _StubFetcher:
    def __init__(self, payloads: dict[str, bytes | None]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def fetch(self, name: str) -> bytes | None:
        self.calls.append(name)
        return self.payloads.get(name)


class TestFetchMaintainerCounts:
    def test_happy_path(self) -> None:
        blob = json.dumps({
            "maintainers": [{"name": "solo"}],
        }).encode("utf-8")
        fetcher = _StubFetcher({"foo": blob})
        out, warnings = fetch_maintainer_counts(["foo"], fetcher)
        assert out == {"foo": 1}
        assert warnings == []

    def test_dedups_names(self) -> None:
        fetcher = _StubFetcher(
            {"foo": b'{"maintainers":[{"name":"a"}]}'},
        )
        fetch_maintainer_counts(["foo", "foo", "foo"], fetcher)
        assert fetcher.calls == ["foo"]  # one HTTP hit for three refs

    def test_404_surfaces_as_warning(self) -> None:
        fetcher = _StubFetcher({"foo": None})
        out, warnings = fetch_maintainer_counts(["foo"], fetcher)
        assert out == {}
        assert warnings and "foo" in warnings[0]

    def test_cache_short_circuits_fetch(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("foo", b'{"maintainers":[{"name":"a"},{"name":"b"}]}')
        fetcher = _StubFetcher({})  # would 404 if called
        out, warnings = fetch_maintainer_counts(
            ["foo"], fetcher, cache=cache,
        )
        assert out == {"foo": 2}
        assert fetcher.calls == []
        assert warnings == []


# ── NPM-014 rule via NpmChecks dispatch ──────────────────────────


def _run_npm014(ctx: NpmContext):
    findings = [f for f in NpmChecks(ctx).run() if f.check_id == "NPM-014"]
    assert len(findings) == 1, "exactly one NPM-014 finding per manifest"
    return findings[0]


class TestNpm014Rule:
    def test_silent_pass_when_no_metadata(self) -> None:
        # Default path: --resolve-remote not passed, so the provider's
        # post_filter didn't populate maintainer_counts.
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        f = _run_npm014(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_single_publisher(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.maintainer_counts = {"foo": 1}
        f = _run_npm014(ctx)
        assert f.passed is False
        assert "dependencies.foo" in f.description
        assert f.severity is Severity.LOW

    def test_passes_for_multi_publisher(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.maintainer_counts = {"foo": 3}
        f = _run_npm014(ctx)
        assert f.passed is True

    def test_unresolved_package_silently_skipped(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.maintainer_counts = {"bar": 1}  # data for a different dep
        f = _run_npm014(ctx)
        assert f.passed is True

    def test_dev_deps_covered(self) -> None:
        m = _manifest({}, dev_deps={"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.maintainer_counts = {"foo": 1}
        f = _run_npm014(ctx)
        assert f.passed is False
        assert "devDependencies.foo" in f.description

    def test_confidence_default_high(self) -> None:
        # The publisher count is a registry-confirmed structural fact,
        # so the finding keeps the framework's HIGH confidence; the
        # low-actionability concern is carried by LOW severity instead.
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.maintainer_counts = {"foo": 1}
        f = _run_npm014(ctx)
        assert f.confidence is Confidence.HIGH
        assert f.severity is Severity.LOW
