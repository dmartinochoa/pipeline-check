"""Per-rule tests for NPM-015 (build-provenance gap).

Covers both layers:

1. ``registry_fetcher`` unit tests: ``_parse_has_provenance`` happy /
   absent / malformed paths and ``fetch_provenance`` records ``False``
   (the flagged value) while sharing the packument cache.
2. ``check`` behavior: silent pass when ``provenance`` is empty (no
   ``--resolve-remote``), fires on a no-provenance direct dep, passes
   when provenance is present, skips unresolved packages, devDeps.

No network — every test uses a stub fetcher or sets the context map.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.npm.base import NpmContext, NpmManifest
from pipeline_check.core.checks.npm.pipelines import NpmChecks
from pipeline_check.core.checks.npm.registry_fetcher import (
    FileSystemCache,
    _parse_has_provenance,
    fetch_provenance,
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


def _packument(latest: str, *, with_attestations: bool) -> bytes:
    dist: dict = {"tarball": "https://registry.npmjs.org/foo/-/foo.tgz"}
    if with_attestations:
        dist["attestations"] = {
            "url": "https://registry.npmjs.org/-/npm/v1/attestations/foo",
            "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
        }
    return json.dumps({
        "dist-tags": {"latest": latest},
        "versions": {latest: {"dist": dist}},
    }).encode("utf-8")


# ── _parse_has_provenance ────────────────────────────────────────


class TestParseHasProvenance:
    def test_latest_with_attestations(self) -> None:
        assert _parse_has_provenance(
            _packument("1.2.3", with_attestations=True),
        ) is True

    def test_latest_without_attestations(self) -> None:
        assert _parse_has_provenance(
            _packument("1.2.3", with_attestations=False),
        ) is False

    def test_missing_dist_tags_returns_none(self) -> None:
        blob = json.dumps({"versions": {}}).encode("utf-8")
        assert _parse_has_provenance(blob) is None

    def test_latest_version_absent_returns_none(self) -> None:
        blob = json.dumps({
            "dist-tags": {"latest": "9.9.9"},
            "versions": {"1.0.0": {"dist": {}}},
        }).encode("utf-8")
        assert _parse_has_provenance(blob) is None

    def test_non_json_returns_none(self) -> None:
        assert _parse_has_provenance(b"{not json") is None


# ── fetch_provenance (with stub fetcher) ─────────────────────────


class _StubFetcher:
    def __init__(self, payloads: dict[str, bytes | None]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    def fetch(self, name: str) -> bytes | None:
        self.calls.append(name)
        return self.payloads.get(name)


class TestFetchProvenance:
    def test_records_true_and_false(self) -> None:
        fetcher = _StubFetcher({
            "good": _packument("1.0.0", with_attestations=True),
            "bad": _packument("2.0.0", with_attestations=False),
        })
        out, warnings = fetch_provenance(["good", "bad"], fetcher)
        assert out == {"good": True, "bad": False}
        assert warnings == []

    def test_404_surfaces_as_warning(self) -> None:
        fetcher = _StubFetcher({"foo": None})
        out, warnings = fetch_provenance(["foo"], fetcher)
        assert out == {}
        assert warnings and "foo" in warnings[0]

    def test_cache_short_circuits_fetch(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("foo", _packument("1.0.0", with_attestations=False))
        fetcher = _StubFetcher({})  # would 404 if called
        out, warnings = fetch_provenance(["foo"], fetcher, cache=cache)
        assert out == {"foo": False}
        assert fetcher.calls == []


# ── NPM-015 rule via NpmChecks dispatch ──────────────────────────


def _run_npm015(ctx: NpmContext):
    findings = [f for f in NpmChecks(ctx).run() if f.check_id == "NPM-015"]
    assert len(findings) == 1, "exactly one NPM-015 finding per manifest"
    return findings[0]


class TestNpm015Rule:
    def test_silent_pass_when_no_metadata(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        f = _run_npm015(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_missing_provenance(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.provenance = {"foo": False}
        f = _run_npm015(ctx)
        assert f.passed is False
        assert "dependencies.foo" in f.description
        assert f.severity is Severity.LOW

    def test_passes_when_provenance_present(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.provenance = {"foo": True}
        f = _run_npm015(ctx)
        assert f.passed is True

    def test_unresolved_package_silently_skipped(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.provenance = {"bar": False}  # data for a different dep
        f = _run_npm015(ctx)
        assert f.passed is True

    def test_dev_deps_covered(self) -> None:
        m = _manifest({}, dev_deps={"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.provenance = {"foo": False}
        f = _run_npm015(ctx)
        assert f.passed is False
        assert "devDependencies.foo" in f.description

    def test_confidence_default_high(self) -> None:
        m = _manifest({"foo": "^1.2.3"})
        ctx = NpmContext(manifests=[m], locks=[])
        ctx.provenance = {"foo": False}
        f = _run_npm015(ctx)
        assert f.confidence is Confidence.HIGH
        assert f.severity is Severity.LOW
