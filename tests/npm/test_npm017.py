"""Per-rule tests for NPM-017 (provenance built from a non-release ref).

Two layers, no network:

1. ``fetch_provenance_refs`` unit tests with a stub fetcher (``fetch``
   for the packument + ``fetch_attestations`` for the bundle): pulls the
   SLSA source ref, skips packages with no provenance, warns on a bundle
   404, shares the packument cache.
2. ``check`` behavior: silent pass with no metadata, fires on a
   non-default branch ref, passes on a tag / default branch, skips
   unresolved deps, devDeps, MEDIUM confidence.

The attestation bytes are synthetic (no real bundles checked in); they
match the documented npm sigstore-bundle shape.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from pipeline_check.core.checks.base import Confidence, Severity
from pipeline_check.core.checks.npm.base import NpmContext, NpmManifest
from pipeline_check.core.checks.npm.pipelines import NpmChecks
from pipeline_check.core.checks.npm.registry_fetcher import (
    FileSystemCache,
    fetch_provenance_refs,
)


def _manifest(deps: dict[str, str], dev_deps: dict[str, str] | None = None) -> NpmManifest:
    data: dict = {"name": "synthetic", "version": "0.0.0"}
    if deps:
        data["dependencies"] = deps
    if dev_deps:
        data["devDependencies"] = dev_deps
    return NpmManifest(path="package.json", text=json.dumps(data, indent=2), data=data)


def _packument(latest: str, *, with_attestations: bool) -> bytes:
    dist: dict = {"tarball": "https://registry.npmjs.org/foo/-/foo.tgz"}
    if with_attestations:
        dist["attestations"] = {"url": "https://registry.npmjs.org/-/npm/v1/attestations/foo"}
    return json.dumps({
        "dist-tags": {"latest": latest},
        "versions": {latest: {"dist": dist}},
    }).encode("utf-8")


def _attestation_bundle(ref: str) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"buildDefinition": {"externalParameters": {
            "workflow": {"ref": ref, "repository": "https://github.com/a/b"}
        }}},
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return json.dumps({"attestations": [
        {"predicateType": "https://slsa.dev/provenance/v1",
         "bundle": {"dsseEnvelope": {"payload": payload}}},
    ]}).encode("utf-8")


class _StubFetcher:
    def __init__(self, packuments: dict[str, bytes | None],
                 bundles: dict[tuple[str, str], bytes | None]) -> None:
        self.packuments = packuments
        self.bundles = bundles
        self.att_calls: list[tuple[str, str]] = []

    def fetch(self, name: str) -> bytes | None:
        return self.packuments.get(name)

    def fetch_attestations(self, name: str, version: str) -> bytes | None:
        self.att_calls.append((name, version))
        return self.bundles.get((name, version))


# ── fetch_provenance_refs ────────────────────────────────────────


class TestFetchProvenanceRefs:
    def test_extracts_ref_for_attested_package(self) -> None:
        fetcher = _StubFetcher(
            {"widget": _packument("3.0.0", with_attestations=True)},
            {("widget", "3.0.0"): _attestation_bundle("refs/heads/oidc-b67eedca")},
        )
        out, warnings = fetch_provenance_refs(["widget"], fetcher)
        assert out == {"widget": "refs/heads/oidc-b67eedca"}
        assert warnings == []

    def test_skips_package_without_provenance(self) -> None:
        fetcher = _StubFetcher(
            {"plain": _packument("1.0.0", with_attestations=False)}, {},
        )
        out, warnings = fetch_provenance_refs(["plain"], fetcher)
        assert out == {}
        assert fetcher.att_calls == []  # no bundle fetch attempted

    def test_bundle_404_warns(self) -> None:
        fetcher = _StubFetcher(
            {"widget": _packument("3.0.0", with_attestations=True)},
            {("widget", "3.0.0"): None},
        )
        out, warnings = fetch_provenance_refs(["widget"], fetcher)
        assert out == {}
        assert warnings and "widget@3.0.0" in warnings[0]

    def test_packument_cache_short_circuits(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("widget", _packument("3.0.0", with_attestations=True))
        fetcher = _StubFetcher(
            {},  # packument would be a miss if fetched
            {("widget", "3.0.0"): _attestation_bundle("refs/tags/v3.0.0")},
        )
        out, _ = fetch_provenance_refs(["widget"], fetcher, cache=cache)
        assert out == {"widget": "refs/tags/v3.0.0"}


# ── NPM-017 rule via NpmChecks dispatch ──────────────────────────


def _run_npm017(ctx: NpmContext):
    findings = [f for f in NpmChecks(ctx).run() if f.check_id == "NPM-017"]
    assert len(findings) == 1, "exactly one NPM-017 finding per manifest"
    return findings[0]


class TestNpm017Rule:
    def test_silent_pass_when_no_metadata(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        f = _run_npm017(ctx)
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_throwaway_branch_ref(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.provenance_ref = {"foo": "refs/heads/oidc-b67eedca"}
        f = _run_npm017(ctx)
        assert f.passed is False
        assert "dependencies.foo" in f.description
        assert "refs/heads/oidc-b67eedca" in f.description
        assert f.severity is Severity.LOW

    def test_passes_on_tag_ref(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.provenance_ref = {"foo": "refs/tags/v1.0.0"}
        assert _run_npm017(ctx).passed is True

    def test_passes_on_default_branch_ref(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.provenance_ref = {"foo": "refs/heads/main"}
        assert _run_npm017(ctx).passed is True

    def test_unresolved_dep_skipped(self) -> None:
        ctx = NpmContext(manifests=[_manifest({"foo": "^1.0.0"})], locks=[])
        ctx.provenance_ref = {"bar": "refs/heads/oidc-x"}
        assert _run_npm017(ctx).passed is True

    def test_dev_deps_covered(self) -> None:
        ctx = NpmContext(manifests=[_manifest({}, dev_deps={"foo": "^1.0.0"})], locks=[])
        ctx.provenance_ref = {"foo": "refs/heads/feature-x"}
        f = _run_npm017(ctx)
        assert f.passed is False
        assert "devDependencies.foo" in f.description

    def test_confidence_demoted_to_medium(self) -> None:
        # The demotion lives in the _confidence registry (the Scanner
        # applies it after the check runs, not NpmChecks.run()).
        from pipeline_check.core.checks._confidence import confidence_for
        assert confidence_for("NPM-017") is Confidence.MEDIUM
