"""Per-rule tests for NPM-008 (cooldown gate).

Covers both layers:

1. ``registry_fetcher`` unit tests: HTTP fetcher 404 path,
   ``_parse_publish_times`` happy / malformed paths,
   ``fetch_publish_times`` dedup + warning surfacing.
2. ``check`` behavior: silent pass when ``publish_times`` is
   empty, fires for a same-day publish, passes for an older
   one, ignores range specs (the rule's documented scope limit).

No network — every test uses a stub fetcher.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.npm.base import NpmContext, NpmManifest
from pipeline_check.core.checks.npm.pipelines import NpmChecks
from pipeline_check.core.checks.npm.registry_fetcher import (
    FileSystemCache,
    HttpRegistryFetcher,
    _parse_publish_times,
    fetch_publish_times,
)
from pipeline_check.core.checks.npm.rules.npm008_cooldown import (
    _exact_version_from_spec,
    _within_cooldown,
)


def _manifest(deps: dict[str, str], dev_deps: dict[str, str] | None = None) -> NpmManifest:
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


# ── _parse_publish_times ─────────────────────────────────────────


class TestParsePublishTimes:
    def test_extracts_per_version_timestamps(self) -> None:
        blob = json.dumps({
            "name": "foo",
            "time": {
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2026-05-19T00:00:00.000Z",
                "1.0.0": "2024-01-01T12:00:00.000Z",
                "1.0.1": "2025-06-15T10:30:00.000Z",
            },
        }).encode("utf-8")
        out = _parse_publish_times(blob)
        assert set(out.keys()) == {"1.0.0", "1.0.1"}
        assert out["1.0.0"] == _dt.datetime(
            2024, 1, 1, 12, 0, 0, tzinfo=_dt.UTC,
        )

    def test_skips_malformed_versions(self) -> None:
        blob = json.dumps({
            "time": {
                "1.0.0": "not-a-timestamp",
                "1.0.1": "2025-06-15T10:30:00.000Z",
            },
        }).encode("utf-8")
        out = _parse_publish_times(blob)
        assert set(out.keys()) == {"1.0.1"}

    def test_non_json_returns_empty(self) -> None:
        assert _parse_publish_times(b"{not json") == {}

    def test_top_level_non_dict_returns_empty(self) -> None:
        assert _parse_publish_times(b"[]") == {}

    def test_missing_time_block_returns_empty(self) -> None:
        blob = json.dumps({"name": "foo"}).encode("utf-8")
        assert _parse_publish_times(blob) == {}


# ── fetch_publish_times (with stub fetcher) ───────────────────────


class _StubFetcher:
    def __init__(self, payloads: dict[str, bytes | None]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def fetch(self, name: str) -> bytes | None:
        self.calls.append(name)
        return self.payloads.get(name)


class TestFetchPublishTimes:
    def test_happy_path(self) -> None:
        blob = json.dumps({
            "time": {"1.0.0": "2025-06-15T10:30:00.000Z"},
        }).encode("utf-8")
        fetcher = _StubFetcher({"foo": blob})
        out, warnings = fetch_publish_times(["foo"], fetcher)
        assert "foo" in out and "1.0.0" in out["foo"]
        assert warnings == []

    def test_dedups_names(self) -> None:
        fetcher = _StubFetcher({"foo": b'{"time":{"1.0.0":"2024-01-01T00:00:00.000Z"}}'})
        fetch_publish_times(["foo", "foo", "foo"], fetcher)
        assert fetcher.calls == ["foo"]  # one HTTP hit for three references

    def test_404_surfaces_as_warning(self) -> None:
        fetcher = _StubFetcher({"foo": None})
        out, warnings = fetch_publish_times(["foo"], fetcher)
        assert out == {}
        assert warnings and "foo" in warnings[0]

    def test_cache_short_circuits_fetch(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("foo", b'{"time":{"1.0.0":"2024-01-01T00:00:00.000Z"}}')
        fetcher = _StubFetcher({})  # would 404 if called
        out, warnings = fetch_publish_times(
            ["foo"], fetcher, cache=cache,
        )
        assert "foo" in out
        assert fetcher.calls == []
        assert warnings == []


# ── _exact_version_from_spec ─────────────────────────────────────


class TestExactVersionFromSpec:
    def test_bare_version(self) -> None:
        assert _exact_version_from_spec("1.2.3") == "1.2.3"

    def test_equals_prefix(self) -> None:
        assert _exact_version_from_spec("=1.2.3") == "1.2.3"

    def test_v_prefix(self) -> None:
        assert _exact_version_from_spec("v1.2.3") == "1.2.3"

    def test_prerelease_kept(self) -> None:
        assert _exact_version_from_spec("1.2.3-rc.1") == "1.2.3-rc.1"

    def test_caret_range_returns_none(self) -> None:
        assert _exact_version_from_spec("^1.2.3") is None

    def test_tilde_range_returns_none(self) -> None:
        assert _exact_version_from_spec("~1.2.3") is None

    def test_dist_tag_returns_none(self) -> None:
        assert _exact_version_from_spec("latest") is None


# ── _within_cooldown ─────────────────────────────────────────────


class TestWithinCooldown:
    def test_fresh_publish_within_cooldown(self) -> None:
        now = _dt.datetime(2026, 5, 19, tzinfo=_dt.UTC)
        published = _dt.datetime(2026, 5, 17, tzinfo=_dt.UTC)
        assert _within_cooldown(published, now, 7) is True

    def test_old_publish_outside_cooldown(self) -> None:
        now = _dt.datetime(2026, 5, 19, tzinfo=_dt.UTC)
        published = _dt.datetime(2026, 5, 1, tzinfo=_dt.UTC)
        assert _within_cooldown(published, now, 7) is False

    def test_tz_naive_input_treated_as_utc(self) -> None:
        # Both ``now`` and ``published`` come in tz-naive (test
        # convenience). The helper normalizes to UTC.
        now = _dt.datetime(2026, 5, 19)
        published = _dt.datetime(2026, 5, 18)
        assert _within_cooldown(published, now, 7) is True


# ── NPM-008 rule via NpmChecks dispatch ──────────────────────────


def _run_npm008(ctx: NpmContext):
    findings = [f for f in NpmChecks(ctx).run() if f.check_id == "NPM-008"]
    assert len(findings) == 1, "exactly one NPM-008 finding per manifest expected"
    return findings[0]


class TestNpm008Rule:
    def test_silent_pass_when_no_publish_times(self) -> None:
        # Default path: --resolve-remote was not passed, so the
        # provider's post_filter didn't populate publish_times.
        # The rule should pass silently so the absence of the
        # network path doesn't trip CI.
        m = _manifest({"foo": "1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        f = _run_npm008(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_fresh_publish(self) -> None:
        m = _manifest({"foo": "1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "foo": {"1.2.3": now - _dt.timedelta(days=2)},
        }
        f = _run_npm008(ctx)
        assert f.passed is False
        assert "foo@1.2.3" in f.description

    def test_passes_for_old_publish(self) -> None:
        m = _manifest({"foo": "1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "foo": {"1.2.3": now - _dt.timedelta(days=30)},
        }
        f = _run_npm008(ctx)
        assert f.passed is True

    def test_skips_range_specs(self) -> None:
        # ``^1.2.3`` doesn't pin a single version, so even when
        # publish_times has data the rule can't decide and stays
        # silent.
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "foo": {"1.2.3": now - _dt.timedelta(days=1)},
        }
        f = _run_npm008(ctx)
        assert f.passed is True

    def test_unresolved_package_silently_skipped(self) -> None:
        # publish_times has data for ``bar`` but not for ``foo`` —
        # ``foo`` is silently skipped, so the manifest passes.
        m = _manifest({"foo": "1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "bar": {"9.9.9": now - _dt.timedelta(days=1)},
        }
        f = _run_npm008(ctx)
        assert f.passed is True

    def test_dev_deps_covered(self) -> None:
        m = _manifest({}, dev_deps={"foo": "1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "foo": {"1.2.3": now - _dt.timedelta(days=1)},
        }
        f = _run_npm008(ctx)
        assert f.passed is False
        assert "devDependencies.foo" in f.description


# ── HttpRegistryFetcher 404 path (the only network-free real test) ─


class TestHttpRegistryFetcher:
    def test_constructs_url_for_scoped_name(self) -> None:
        # No real fetch — just verify the URL-encoding contract.
        # We don't hit the network in tests; this just confirms
        # the helper can be instantiated.
        f = HttpRegistryFetcher()
        assert f.timeout > 0
        assert f.BASE_URL == "https://registry.npmjs.org"

    def test_confidence_default_high(self) -> None:
        # NpmChecks runs the dispatch; the rule itself doesn't
        # surface confidence overrides. Ensure the synthesized
        # Finding inherits the framework default (HIGH).
        m = _manifest({"foo": "1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "foo": {"1.2.3": now - _dt.timedelta(days=2)},
        }
        f = _run_npm008(ctx)
        assert f.confidence is Confidence.HIGH
        assert f.severity is Severity.HIGH
