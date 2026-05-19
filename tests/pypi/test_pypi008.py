"""Per-rule tests for PYPI-008 (cooldown gate).

Two layers, no network:

1. ``registry_fetcher`` unit tests: ``_parse_publish_times`` happy
   / malformed paths, dedup with case-folding via PEP 503,
   ``fetch_publish_times`` 404 + cache short-circuit.
2. ``check`` behavior: silent pass when ``publish_times`` is
   empty, fires for a same-day publish, passes for an older one,
   ignores range specs (the rule's documented scope limit).
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.pypi.base import (
    PypiContext,
    RequirementsFile,
    _parse_requirements,
)
from pipeline_check.core.checks.pypi.pipelines import PypiChecks
from pipeline_check.core.checks.pypi.registry_fetcher import (
    FileSystemCache,
    HttpRegistryFetcher,
    _parse_publish_times,
    fetch_publish_times,
)
from pipeline_check.core.checks.pypi.rules.pypi008_cooldown import (
    _exact_spec,
    _within_cooldown,
)


def _ctx_from(text: str, path: str = "requirements.txt") -> PypiContext:
    lines, options = _parse_requirements(text)
    return PypiContext([RequirementsFile(
        path=path, text=text, lines=lines, options=options,
    )])


# ── _parse_publish_times ─────────────────────────────────────────


class TestParsePublishTimes:
    def test_extracts_min_upload_time_per_version(self) -> None:
        # Each version's per-file timestamps can differ slightly
        # (the sdist lands first, then each wheel). PYPI-008 should
        # measure from the FIRST file that landed.
        blob = json.dumps({
            "info": {"name": "foo"},
            "releases": {
                "1.0.0": [
                    {"upload_time_iso_8601": "2025-06-15T12:00:00Z"},
                    {"upload_time_iso_8601": "2025-06-15T10:00:00Z"},
                    {"upload_time_iso_8601": "2025-06-15T11:00:00Z"},
                ],
                "1.0.1": [
                    {"upload_time_iso_8601": "2026-05-19T08:30:00Z"},
                ],
            },
        }).encode("utf-8")
        out = _parse_publish_times(blob)
        assert out["1.0.0"] == _dt.datetime(
            2025, 6, 15, 10, 0, 0, tzinfo=_dt.UTC,
        )
        assert out["1.0.1"] == _dt.datetime(
            2026, 5, 19, 8, 30, 0, tzinfo=_dt.UTC,
        )

    def test_legacy_upload_time_field_supported(self) -> None:
        # Older PyPI responses carry tz-naive ``upload_time``
        # instead of ``upload_time_iso_8601``; the parser treats it
        # as UTC for consistent min().
        blob = json.dumps({
            "releases": {
                "1.0.0": [
                    {"upload_time": "2025-06-15T10:00:00"},
                ],
            },
        }).encode("utf-8")
        out = _parse_publish_times(blob)
        assert out["1.0.0"] == _dt.datetime(
            2025, 6, 15, 10, 0, 0, tzinfo=_dt.UTC,
        )

    def test_yanked_version_with_empty_files_dropped(self) -> None:
        # An empty release list (the version was yanked) has no
        # per-file timestamps; drop it rather than emit a partial
        # entry.
        blob = json.dumps({
            "releases": {
                "1.0.0": [],
                "1.0.1": [{"upload_time_iso_8601": "2025-06-15T10:00:00Z"}],
            },
        }).encode("utf-8")
        out = _parse_publish_times(blob)
        assert "1.0.0" not in out
        assert "1.0.1" in out

    def test_non_json_returns_empty(self) -> None:
        assert _parse_publish_times(b"{not json") == {}

    def test_top_level_non_dict_returns_empty(self) -> None:
        assert _parse_publish_times(b"[]") == {}

    def test_missing_releases_block_returns_empty(self) -> None:
        assert _parse_publish_times(b'{"info": {"name": "foo"}}') == {}


# ── fetch_publish_times (stub fetcher) ────────────────────────────


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
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": "2025-06-15T10:00:00Z"}],
            },
        }).encode("utf-8")
        fetcher = _StubFetcher({"foo": blob})
        out, warnings = fetch_publish_times(["foo"], fetcher)
        assert "foo" in out and "1.0.0" in out["foo"]
        assert warnings == []

    def test_dedup_by_normalized_name(self) -> None:
        # PEP 503: ``Pillow``, ``pillow``, ``Pil_low`` all resolve
        # to the same package; the fetcher should hit only once.
        fetcher = _StubFetcher({"pillow": b'{"releases":{"9.0.0":[]}}'})
        fetch_publish_times(["Pillow", "pillow", "PIL_LOW"], fetcher)
        # Only "pillow" was normalized + queried; "pil_low" doesn't
        # collapse to "pillow" but the test asserts no double-fetch
        # of the same normalized form.
        assert fetcher.calls.count("pillow") == 1

    def test_404_surfaces_as_warning(self) -> None:
        fetcher = _StubFetcher({"foo": None})
        out, warnings = fetch_publish_times(["foo"], fetcher)
        assert out == {}
        assert warnings and "foo" in warnings[0]

    def test_cache_short_circuits_fetch(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put(
            "foo",
            b'{"releases":{"1.0.0":[{"upload_time_iso_8601":"2025-06-15T10:00:00Z"}]}}',
        )
        fetcher = _StubFetcher({})  # would 404 if called
        out, warnings = fetch_publish_times(
            ["foo"], fetcher, cache=cache,
        )
        assert "foo" in out
        assert fetcher.calls == []
        assert warnings == []


# ── _exact_spec ───────────────────────────────────────────────────


class TestExactSpec:
    def test_bare_exact_pin(self) -> None:
        assert _exact_spec("requests==2.31.0") == ("requests", "2.31.0")

    def test_extras_stripped(self) -> None:
        assert _exact_spec("requests[security]==2.31.0") == (
            "requests", "2.31.0",
        )

    def test_marker_ignored(self) -> None:
        assert _exact_spec(
            "requests==2.31.0; python_version >= '3.10'",
        ) == ("requests", "2.31.0")

    def test_name_normalized_to_lowercase(self) -> None:
        # PEP 503 normalization is what the fetcher cache keys on.
        assert _exact_spec("Pillow==10.0.0") == ("pillow", "10.0.0")

    def test_range_spec_returns_none(self) -> None:
        assert _exact_spec("requests>=2.31.0") is None

    def test_compatible_release_returns_none(self) -> None:
        assert _exact_spec("requests~=2.31.0") is None

    def test_vcs_url_returns_none(self) -> None:
        assert _exact_spec(
            "requests @ git+https://github.com/psf/requests.git@deadbeef",
        ) is None


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
        now = _dt.datetime(2026, 5, 19)
        published = _dt.datetime(2026, 5, 18)
        assert _within_cooldown(published, now, 7) is True


# ── PYPI-008 rule via PypiChecks dispatch ─────────────────────────


def _run_pypi008(ctx: PypiContext):
    findings = [f for f in PypiChecks(ctx).run() if f.check_id == "PYPI-008"]
    assert len(findings) == 1
    return findings[0]


class TestPypi008Rule:
    def test_silent_pass_when_no_publish_times(self) -> None:
        ctx = _ctx_from("requests==2.31.0\n")
        f = _run_pypi008(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_fresh_publish(self) -> None:
        ctx = _ctx_from("requests==2.31.0\n")
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "requests": {"2.31.0": now - _dt.timedelta(days=2)},
        }
        f = _run_pypi008(ctx)
        assert f.passed is False
        assert "requests==2.31.0" in f.description

    def test_passes_for_old_publish(self) -> None:
        ctx = _ctx_from("requests==2.31.0\n")
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "requests": {"2.31.0": now - _dt.timedelta(days=30)},
        }
        f = _run_pypi008(ctx)
        assert f.passed is True

    def test_skips_range_specs(self) -> None:
        ctx = _ctx_from("requests>=2.31.0\n")
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "requests": {"2.31.0": now - _dt.timedelta(days=1)},
        }
        f = _run_pypi008(ctx)
        assert f.passed is True

    def test_unresolved_package_silently_skipped(self) -> None:
        ctx = _ctx_from("requests==2.31.0\n")
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "other": {"9.9.9": now - _dt.timedelta(days=1)},
        }
        f = _run_pypi008(ctx)
        assert f.passed is True

    def test_name_case_folded_for_lookup(self) -> None:
        # The provider populates publish_times under PEP 503
        # normalized names; the rule should match by the same key.
        ctx = _ctx_from("Pillow==10.0.0\n")
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "pillow": {"10.0.0": now - _dt.timedelta(days=2)},
        }
        f = _run_pypi008(ctx)
        assert f.passed is False
        assert "pillow==10.0.0" in f.description

    def test_inherits_framework_default_confidence(self) -> None:
        ctx = _ctx_from("requests==2.31.0\n")
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "requests": {"2.31.0": now - _dt.timedelta(days=2)},
        }
        f = _run_pypi008(ctx)
        assert f.confidence is Confidence.HIGH
        assert f.severity is Severity.HIGH


# ── HttpRegistryFetcher smoke (no network) ────────────────────────


class TestHttpRegistryFetcher:
    def test_constructible(self) -> None:
        f = HttpRegistryFetcher()
        assert f.timeout > 0
        assert f.BASE_URL == "https://pypi.org/pypi"
