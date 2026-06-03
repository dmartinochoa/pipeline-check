"""Per-rule tests for NPM-018 (latest release from a new publisher).

Covers both layers:

1. ``registry_fetcher`` unit tests: ``_parse_latest_publisher_is_new``
   over the new-publisher / established / insufficient-history / absent-
   field paths, plus ``fetch_new_publisher`` dedup + cache.
2. ``check`` behavior: silent pass when ``new_publisher`` is empty (no
   ``--resolve-remote``), fires on a flagged direct dep, passes for an
   established-publisher one, skips unresolved packages, covers
   devDependencies, and carries the MEDIUM confidence the central
   registry assigns.

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
    _parse_latest_publisher_is_new,
    fetch_new_publisher,
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


def _packument(latest: str, version_publishers: dict[str, str | None]) -> bytes:
    """Build a packument blob with a per-version ``_npmUser`` publisher.

    ``version_publishers`` maps each version to its publisher name, or
    ``None`` to omit the ``_npmUser`` field for that version.
    """
    versions: dict = {}
    for ver, pub in version_publishers.items():
        entry: dict = {"dist": {}}
        if pub is not None:
            entry["_npmUser"] = {"name": pub, "email": f"{pub}@x.com"}
        versions[ver] = entry
    return json.dumps({
        "dist-tags": {"latest": latest},
        "versions": versions,
    }).encode("utf-8")


# ── _parse_latest_publisher_is_new ───────────────────────────────


class TestParseLatestPublisherIsNew:
    def test_new_publisher_on_latest(self) -> None:
        blob = _packument("5.0.0", {
            "1.0.0": "alice", "2.0.0": "alice",
            "3.0.0": "alice", "4.0.0": "alice", "5.0.0": "mallory",
        })
        assert _parse_latest_publisher_is_new(blob) is True

    def test_established_publisher(self) -> None:
        blob = _packument("5.0.0", {
            "1.0.0": "alice", "2.0.0": "alice",
            "3.0.0": "alice", "4.0.0": "bob", "5.0.0": "alice",
        })
        assert _parse_latest_publisher_is_new(blob) is False

    def test_insufficient_history_returns_none(self) -> None:
        # Only two prior versions with a known publisher — too little
        # history to call a change meaningful.
        blob = _packument("3.0.0", {
            "1.0.0": "alice", "2.0.0": "alice", "3.0.0": "mallory",
        })
        assert _parse_latest_publisher_is_new(blob) is None

    def test_latest_publisher_unknown_returns_none(self) -> None:
        blob = _packument("5.0.0", {
            "1.0.0": "alice", "2.0.0": "alice",
            "3.0.0": "alice", "4.0.0": "alice", "5.0.0": None,
        })
        assert _parse_latest_publisher_is_new(blob) is None

    def test_no_latest_returns_none(self) -> None:
        blob = json.dumps({"versions": {}}).encode("utf-8")
        assert _parse_latest_publisher_is_new(blob) is None

    def test_non_json_returns_none(self) -> None:
        assert _parse_latest_publisher_is_new(b"{not json") is None

    def test_top_level_non_dict_returns_none(self) -> None:
        assert _parse_latest_publisher_is_new(b"[]") is None


# ── fetch_new_publisher (with stub fetcher) ──────────────────────


class _StubFetcher:
    def __init__(self, payloads: dict[str, bytes | None]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def fetch(self, name: str) -> bytes | None:
        self.calls.append(name)
        return self.payloads.get(name)


class TestFetchNewPublisher:
    def test_happy_path(self) -> None:
        blob = _packument("5.0.0", {
            "1.0.0": "alice", "2.0.0": "alice",
            "3.0.0": "alice", "4.0.0": "alice", "5.0.0": "mallory",
        })
        out, warnings = fetch_new_publisher(["foo"], _StubFetcher({"foo": blob}))
        assert out == {"foo": True}
        assert warnings == []

    def test_dedups_names(self) -> None:
        blob = _packument("5.0.0", {
            "1.0.0": "a", "2.0.0": "a", "3.0.0": "a", "4.0.0": "a", "5.0.0": "a",
        })
        fetcher = _StubFetcher({"foo": blob})
        fetch_new_publisher(["foo", "foo"], fetcher)
        assert fetcher.calls == ["foo"]  # one HTTP hit for two refs

    def test_404_surfaces_as_warning(self) -> None:
        out, warnings = fetch_new_publisher(["foo"], _StubFetcher({"foo": None}))
        assert out == {}
        assert warnings and "foo" in warnings[0]

    def test_cache_short_circuits_fetch(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("foo", _packument("5.0.0", {
            "1.0.0": "alice", "2.0.0": "alice",
            "3.0.0": "alice", "4.0.0": "alice", "5.0.0": "mallory",
        }))
        fetcher = _StubFetcher({})  # would 404 if called
        out, _ = fetch_new_publisher(["foo"], fetcher, cache=cache)
        assert out == {"foo": True}
        assert fetcher.calls == []


# ── NPM-018 rule via NpmChecks dispatch ──────────────────────────


def _run_npm018(ctx: NpmContext):
    findings = [f for f in NpmChecks(ctx).run() if f.check_id == "NPM-018"]
    assert len(findings) == 1, "exactly one NPM-018 finding per manifest"
    return findings[0]


class TestNpm018Rule:
    def test_silent_pass_when_no_metadata(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        f = _run_npm018(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_new_publisher(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.new_publisher = {"foo": True}
        f = _run_npm018(ctx)
        assert f.passed is False
        assert "dependencies.foo" in f.description
        assert f.severity is Severity.MEDIUM

    def test_passes_for_established_publisher(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.new_publisher = {"foo": False}
        f = _run_npm018(ctx)
        assert f.passed is True

    def test_unresolved_package_silently_skipped(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.new_publisher = {"bar": True}  # data for a different dep
        f = _run_npm018(ctx)
        assert f.passed is True

    def test_dev_deps_covered(self) -> None:
        m = _manifest({}, dev_deps={"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.new_publisher = {"foo": True}
        f = _run_npm018(ctx)
        assert f.passed is False
        assert "devDependencies.foo" in f.description

    def test_confidence_medium_from_registry(self) -> None:
        # The new-publisher signal can't tell a legit hand-off from a
        # takeover, so the central _confidence.py registry demotes it to
        # MEDIUM. The rule itself doesn't set confidence inline (it stays
        # HIGH at the dispatch layer; the Scanner applies the demotion),
        # so assert the registry mapping directly.
        from pipeline_check.core.checks._confidence import confidence_for
        assert confidence_for("NPM-018") is Confidence.MEDIUM
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.new_publisher = {"foo": True}
        f = _run_npm018(ctx)
        assert f.severity is Severity.MEDIUM
