"""Per-rule tests for MVN-008 (Maven Central cooldown gate).

Two layers, no network:

1. ``registry_fetcher`` unit tests: ``_parse_publish_times`` happy
   / malformed paths, ``fetch_publish_times`` dedup + cache.
2. ``check`` behavior: silent pass when ``publish_times`` is empty,
   fires for a fresh publish, passes for an older one, ignores
   ``-SNAPSHOT`` / range / unresolved-property versions (the rule's
   documented scope limits).
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.maven.base import MavenContext, _parse_pom
from pipeline_check.core.checks.maven.pipelines import MavenChecks
from pipeline_check.core.checks.maven.registry_fetcher import (
    FileSystemCache,
    HttpRegistryFetcher,
    _parse_publish_times,
    fetch_publish_times,
)
from pipeline_check.core.checks.maven.rules.mvn008_cooldown import (
    _is_concrete_release,
    _within_cooldown,
)

from .conftest import pom_with_dep


def _ctx_from(text: str, path: str = "pom.xml") -> MavenContext:
    pom = _parse_pom(path, text)
    return MavenContext([pom])


def _run_mvn008(ctx: MavenContext):
    findings = [
        f for f in MavenChecks(ctx).run() if f.check_id == "MVN-008"
    ]
    assert len(findings) == 1, (
        "exactly one MVN-008 finding per pom expected"
    )
    return findings[0]


# ── _parse_publish_times ─────────────────────────────────────────


class TestParsePublishTimes:
    def test_extracts_timestamps_from_gav_docs(self) -> None:
        blob = json.dumps({
            "response": {
                "docs": [
                    {"id": "g:a:1.0", "g": "g", "a": "a", "v": "1.0",
                     "timestamp": 1700000000000},
                    {"id": "g:a:1.1", "g": "g", "a": "a", "v": "1.1",
                     "timestamp": 1747600000000},
                ],
            },
        }).encode("utf-8")
        out = _parse_publish_times(blob)
        assert set(out.keys()) == {"1.0", "1.1"}
        # 1.7e12 ms = 2023-11-14T22:13:20Z
        assert out["1.0"] == _dt.datetime(
            2023, 11, 14, 22, 13, 20, tzinfo=_dt.UTC,
        )

    def test_keeps_earliest_when_version_double_listed(self) -> None:
        # Same version appearing twice (rare but possible across
        # snapshots) should fold to the earliest timestamp.
        blob = json.dumps({
            "response": {
                "docs": [
                    {"v": "1.0", "timestamp": 1700000000000},
                    {"v": "1.0", "timestamp": 1690000000000},
                ],
            },
        }).encode("utf-8")
        out = _parse_publish_times(blob)
        assert out["1.0"] == _dt.datetime.fromtimestamp(
            1690000000.0, tz=_dt.UTC,
        )

    def test_rejects_negative_timestamp(self) -> None:
        blob = json.dumps({
            "response": {
                "docs": [{"v": "1.0", "timestamp": -1}],
            },
        }).encode("utf-8")
        assert _parse_publish_times(blob) == {}

    def test_non_json_returns_empty(self) -> None:
        assert _parse_publish_times(b"{not json") == {}

    def test_top_level_non_dict_returns_empty(self) -> None:
        assert _parse_publish_times(b"[]") == {}

    def test_missing_response_block_returns_empty(self) -> None:
        assert _parse_publish_times(b'{"responseHeader": {}}') == {}

    def test_missing_v_field_dropped(self) -> None:
        blob = json.dumps({
            "response": {
                "docs": [{"timestamp": 1700000000000}],
            },
        }).encode("utf-8")
        assert _parse_publish_times(blob) == {}


# ── fetch_publish_times (with stub fetcher) ──────────────────────


class _StubFetcher:
    def __init__(
        self, payloads: dict[tuple[str, str], bytes | None],
    ) -> None:
        self.payloads = payloads
        self.calls: list[tuple[str, str]] = []

    def fetch(self, group_id: str, artifact_id: str) -> bytes | None:
        self.calls.append((group_id, artifact_id))
        return self.payloads.get((group_id, artifact_id))


class TestFetchPublishTimes:
    def test_happy_path(self) -> None:
        blob = json.dumps({
            "response": {"docs": [
                {"v": "1.0", "timestamp": 1700000000000},
            ]},
        }).encode("utf-8")
        fetcher = _StubFetcher({("g", "a"): blob})
        out, warnings = fetch_publish_times([("g", "a")], fetcher)
        assert "g:a" in out and "1.0" in out["g:a"]
        assert warnings == []

    def test_dedup_by_coordinate(self) -> None:
        fetcher = _StubFetcher({
            ("g", "a"): json.dumps({
                "response": {"docs": [{"v": "1.0", "timestamp": 1700000000000}]},
            }).encode("utf-8"),
        })
        fetch_publish_times(
            [("g", "a"), ("g", "a"), ("g", "a")], fetcher,
        )
        assert fetcher.calls == [("g", "a")]

    def test_404_surfaces_as_warning(self) -> None:
        fetcher = _StubFetcher({("g", "a"): None})
        out, warnings = fetch_publish_times([("g", "a")], fetcher)
        assert out == {}
        assert warnings and "g:a" in warnings[0]

    def test_cache_short_circuits_fetch(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put(
            "g:a",
            json.dumps({
                "response": {"docs": [{"v": "1.0", "timestamp": 1700000000000}]},
            }).encode("utf-8"),
        )
        fetcher = _StubFetcher({})  # would 404 if called
        out, warnings = fetch_publish_times(
            [("g", "a")], fetcher, cache=cache,
        )
        assert "g:a" in out
        assert fetcher.calls == []
        assert warnings == []

    def test_empty_group_or_artifact_skipped(self) -> None:
        fetcher = _StubFetcher({})
        out, warnings = fetch_publish_times(
            [("", "a"), ("g", "")], fetcher,
        )
        assert out == {}
        assert warnings == []
        assert fetcher.calls == []


# ── _is_concrete_release ─────────────────────────────────────────


class TestIsConcreteRelease:
    def test_plain_version_is_concrete(self) -> None:
        assert _is_concrete_release("1.2.3") is True

    def test_snapshot_rejected(self) -> None:
        assert _is_concrete_release("1.2.3-SNAPSHOT") is False

    def test_range_rejected(self) -> None:
        assert _is_concrete_release("[1.0,2.0)") is False

    def test_latest_literal_rejected(self) -> None:
        assert _is_concrete_release("LATEST") is False

    def test_release_literal_rejected(self) -> None:
        assert _is_concrete_release("RELEASE") is False

    def test_gradle_wildcard_rejected(self) -> None:
        assert _is_concrete_release("+") is False
        assert _is_concrete_release("1.2.+") is False

    def test_empty_rejected(self) -> None:
        assert _is_concrete_release("") is False
        assert _is_concrete_release("   ") is False


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


# ── MVN-008 rule via MavenChecks dispatch ────────────────────────


class TestMVN008:
    def test_silent_pass_when_no_publish_times(self) -> None:
        ctx = _ctx_from(pom_with_dep(
            group_id="g", artifact_id="a", version="1.0.0",
        ))
        f = _run_mvn008(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_fresh_publish(self) -> None:
        ctx = _ctx_from(pom_with_dep(
            group_id="g", artifact_id="a", version="1.0.0",
        ))
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"1.0.0": now - _dt.timedelta(days=2)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is False
        assert "g:a:1.0.0" in f.description

    def test_passes_for_old_publish(self) -> None:
        ctx = _ctx_from(pom_with_dep(
            group_id="g", artifact_id="a", version="1.0.0",
        ))
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"1.0.0": now - _dt.timedelta(days=30)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is True

    def test_skips_snapshot_versions(self) -> None:
        # SNAPSHOT is mutable (MVN-002's territory) and out of scope
        # for the cooldown rule even when publish_times has data.
        ctx = _ctx_from(pom_with_dep(
            group_id="g", artifact_id="a", version="1.0.0-SNAPSHOT",
        ))
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"1.0.0-SNAPSHOT": now - _dt.timedelta(days=1)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is True

    def test_skips_range_specs(self) -> None:
        ctx = _ctx_from(pom_with_dep(
            group_id="g", artifact_id="a", version="[1.0,2.0)",
        ))
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"1.0.0": now - _dt.timedelta(days=1)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is True

    def test_property_resolved_before_lookup(self) -> None:
        # ${log4j.version} -> 2.14.1 (which is "fresh" in this
        # test's publish_times). The cooldown lookup should hit
        # the resolved version.
        text = pom_with_dep(
            group_id="org.apache.logging.log4j",
            artifact_id="log4j-core",
            version="${log4j.version}",
            properties="\n    <log4j.version>2.14.1</log4j.version>",
        )
        ctx = _ctx_from(text)
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "org.apache.logging.log4j:log4j-core": {
                "2.14.1": now - _dt.timedelta(days=2),
            },
        }
        f = _run_mvn008(ctx)
        assert f.passed is False
        assert "log4j-core:2.14.1" in f.description

    def test_unresolved_property_silently_skipped(self) -> None:
        # No matching <properties> entry: resolve_version returns
        # the raw ``${...}`` literal. The cooldown rule should
        # skip rather than guess.
        text = pom_with_dep(
            group_id="g", artifact_id="a", version="${missing}",
        )
        ctx = _ctx_from(text)
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"${missing}": now - _dt.timedelta(days=1)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is True

    def test_unresolved_coordinate_silently_skipped(self) -> None:
        # publish_times has data for a different coordinate; the
        # POM's actual dep isn't in the registry and gets skipped.
        ctx = _ctx_from(pom_with_dep(
            group_id="g", artifact_id="a", version="1.0.0",
        ))
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "other:lib": {"9.9.9": now - _dt.timedelta(days=1)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is True

    def test_dependency_management_skipped(self) -> None:
        # Coordinate appears in <dependencyManagement> only — the
        # rule must skip managed entries (they're version-management
        # declarations, not real consumption).
        text = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<project xmlns='http://maven.apache.org/POM/4.0.0'>\n"
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>app</artifactId>\n"
            "  <version>1.0.0</version>\n"
            "  <dependencyManagement>\n"
            "    <dependencies>\n"
            "      <dependency>\n"
            "        <groupId>g</groupId>\n"
            "        <artifactId>a</artifactId>\n"
            "        <version>1.0.0</version>\n"
            "      </dependency>\n"
            "    </dependencies>\n"
            "  </dependencyManagement>\n"
            "</project>\n"
        )
        ctx = _ctx_from(text)
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"1.0.0": now - _dt.timedelta(days=1)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is True

    def test_settings_xml_short_circuits(self) -> None:
        settings = (
            "<?xml version='1.0' encoding='UTF-8'?>\n"
            "<settings xmlns='http://maven.apache.org/SETTINGS/1.0.0'>\n"
            "</settings>\n"
        )
        ctx = _ctx_from(settings, path="settings.xml")
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"1.0.0": now - _dt.timedelta(days=1)},
        }
        f = _run_mvn008(ctx)
        assert f.passed is True

    def test_inherits_framework_default_confidence(self) -> None:
        ctx = _ctx_from(pom_with_dep(
            group_id="g", artifact_id="a", version="1.0.0",
        ))
        now = _dt.datetime.now(_dt.UTC)
        ctx.publish_times = {
            "g:a": {"1.0.0": now - _dt.timedelta(days=2)},
        }
        f = _run_mvn008(ctx)
        assert f.confidence is Confidence.HIGH
        assert f.severity is Severity.HIGH


# ── HttpRegistryFetcher smoke (no network) ───────────────────────


class TestHttpRegistryFetcher:
    def test_constructible(self) -> None:
        f = HttpRegistryFetcher()
        assert f.timeout > 0
        assert f.BASE_URL == (
            "https://search.maven.org/solrsearch/select"
        )
