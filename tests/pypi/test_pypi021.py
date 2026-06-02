"""Per-rule tests for PYPI-021 (provenance built from a non-release ref).

The PyPI / PEP 740 analog of NPM-017. Two layers, no network:

1. ``fetch_provenance_refs`` unit tests with a stub fetcher (``fetch``
   for the packument + ``fetch_provenance_object`` for the PEP 740
   object): pulls the SLSA source ref, skips packages with no
   provenance URL, warns on a fetch miss, shares the packument cache.
   Plus ``fetch_provenance_object``'s host pin and ``_parse_latest_
   provenance_url``.
2. ``check`` behavior: silent pass with no metadata, fires on a
   non-default branch ref, passes on a tag / default branch, skips
   unresolved deps, MEDIUM confidence.

The provenance bytes are synthetic (no real PEP 740 bundles checked
in); they match the documented PyPI ``/provenance`` shape.
"""
from __future__ import annotations

import base64
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
    _parse_latest_provenance_url,
    fetch_provenance_refs,
)

_PROV_URL = "https://pypi.org/integrity/widget/3.0.0/widget-3.0.0.tar.gz/provenance"


def _ctx_from(text: str) -> PypiContext:
    lines, options = _parse_requirements(text)
    return PypiContext([RequirementsFile(
        path="requirements.txt", text=text, lines=lines, options=options,
    )])


def _run(ctx: PypiContext):
    findings = [f for f in PypiChecks(ctx).run() if f.check_id == "PYPI-021"]
    assert len(findings) == 1, "exactly one PYPI-021 finding"
    return findings[0]


def _packument(*, with_provenance_url: bool) -> bytes:
    file_rec: dict = {"filename": "widget-3.0.0.tar.gz", "url": "https://files/x"}
    if with_provenance_url:
        file_rec["provenance"] = _PROV_URL
    return json.dumps({"urls": [file_rec]}).encode("utf-8")


def _provenance_object(ref: str) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"buildDefinition": {"externalParameters": {
            "workflow": {"ref": ref, "repository": "https://github.com/a/b"}
        }}},
    }
    stmt = base64.b64encode(json.dumps(statement).encode()).decode()
    return json.dumps({"attestation_bundles": [
        {"attestations": [{"envelope": {"statement": stmt}}]},
    ]}).encode("utf-8")


class _StubFetcher:
    def __init__(self, packuments: dict[str, bytes | None],
                 objects: dict[str, bytes | None]) -> None:
        self.packuments = packuments
        self.objects = objects
        self.obj_calls: list[str] = []

    def fetch(self, name: str) -> bytes | None:
        return self.packuments.get(name.strip().lower())

    def fetch_provenance_object(self, url: str) -> bytes | None:
        self.obj_calls.append(url)
        return self.objects.get(url)


# ── _parse_latest_provenance_url ─────────────────────────────────


class TestParseLatestProvenanceUrl:
    def test_returns_first_populated_url(self) -> None:
        blob = _packument(with_provenance_url=True)
        assert _parse_latest_provenance_url(blob) == _PROV_URL

    def test_none_when_no_provenance_field(self) -> None:
        blob = _packument(with_provenance_url=False)
        assert _parse_latest_provenance_url(blob) is None

    def test_none_when_field_empty(self) -> None:
        blob = json.dumps({"urls": [{"provenance": None}]}).encode()
        assert _parse_latest_provenance_url(blob) is None

    def test_none_on_garbage(self) -> None:
        assert _parse_latest_provenance_url(b"{not json") is None


# ── fetch_provenance_object host pin ─────────────────────────────


class TestFetchProvenanceObjectHostPin:
    def test_rejects_off_host_url(self) -> None:
        # No network: an off-host URL is refused before any GET.
        f = HttpRegistryFetcher()
        assert f.fetch_provenance_object("https://evil.example/p") is None

    def test_rejects_non_https(self) -> None:
        f = HttpRegistryFetcher()
        assert f.fetch_provenance_object("http://pypi.org/p") is None

    def test_rejects_lookalike_host(self) -> None:
        f = HttpRegistryFetcher()
        assert f.fetch_provenance_object("https://pypi.org.evil.com/p") is None


# ── fetch_provenance_refs ────────────────────────────────────────


class TestFetchProvenanceRefs:
    def test_extracts_ref_for_attested_package(self) -> None:
        fetcher = _StubFetcher(
            {"widget": _packument(with_provenance_url=True)},
            {_PROV_URL: _provenance_object("refs/heads/oidc-b67eedca")},
        )
        out, warnings = fetch_provenance_refs(["widget"], fetcher)
        assert out == {"widget": "refs/heads/oidc-b67eedca"}
        assert warnings == []

    def test_skips_package_without_provenance(self) -> None:
        fetcher = _StubFetcher(
            {"plain": _packument(with_provenance_url=False)}, {},
        )
        out, _ = fetch_provenance_refs(["plain"], fetcher)
        assert out == {}
        assert fetcher.obj_calls == []  # no object fetch attempted

    def test_dedups_case(self) -> None:
        fetcher = _StubFetcher(
            {"widget": _packument(with_provenance_url=True)},
            {_PROV_URL: _provenance_object("refs/tags/v3.0.0")},
        )
        out, _ = fetch_provenance_refs(["Widget", "widget", "WIDGET"], fetcher)
        assert out == {"widget": "refs/tags/v3.0.0"}
        assert fetcher.obj_calls == [_PROV_URL]  # one object fetch

    def test_object_fetch_miss_warns(self) -> None:
        fetcher = _StubFetcher(
            {"widget": _packument(with_provenance_url=True)},
            {_PROV_URL: None},
        )
        out, warnings = fetch_provenance_refs(["widget"], fetcher)
        assert out == {}
        assert warnings and "widget" in warnings[0]

    def test_packument_cache_short_circuits(self, tmp_path: Path) -> None:
        cache = FileSystemCache(tmp_path, enabled=True)
        cache.put("widget", _packument(with_provenance_url=True))
        fetcher = _StubFetcher(
            {},  # packument would be a miss if fetched
            {_PROV_URL: _provenance_object("refs/tags/v3.0.0")},
        )
        out, _ = fetch_provenance_refs(["widget"], fetcher, cache=cache)
        assert out == {"widget": "refs/tags/v3.0.0"}


# ── PYPI-021 rule via PypiChecks dispatch ────────────────────────


class TestPypi021Rule:
    def test_silent_pass_when_no_metadata(self) -> None:
        f = _run(_ctx_from("foo==1.0.0\n"))
        assert f.passed is True
        assert "resolve-remote" in f.description

    def test_fires_on_throwaway_branch_ref(self) -> None:
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.provenance_ref = {"foo": "refs/heads/oidc-b67eedca"}
        f = _run(ctx)
        assert f.passed is False
        assert "foo" in f.description
        assert "refs/heads/oidc-b67eedca" in f.description
        assert f.severity is Severity.LOW

    def test_passes_on_tag_ref(self) -> None:
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.provenance_ref = {"foo": "refs/tags/v1.0.0"}
        assert _run(ctx).passed is True

    def test_passes_on_default_branch_ref(self) -> None:
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.provenance_ref = {"foo": "refs/heads/main"}
        assert _run(ctx).passed is True

    def test_unresolved_dep_skipped(self) -> None:
        ctx = _ctx_from("foo==1.0.0\n")
        ctx.provenance_ref = {"bar": "refs/heads/oidc-x"}
        assert _run(ctx).passed is True

    def test_confidence_demoted_to_medium(self) -> None:
        # The demotion lives in the _confidence registry (the Scanner
        # applies it after the check runs, not PypiChecks.run()).
        from pipeline_check.core.checks._confidence import confidence_for
        assert confidence_for("PYPI-021") is Confidence.MEDIUM
