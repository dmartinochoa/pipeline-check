"""End-to-end tests for the OCI provider plumbing.

Covers ``OCIContext.from_path`` (file + directory loading, JSON
parse-error handling, non-manifest skipping), ``OCIManifestChecks``
orchestrator, the ``OCIProvider`` adapter, and the Scanner round-trip
through ``--pipeline oci``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pipeline_check.core.checks.oci.base import OCIContext
from pipeline_check.core.checks.oci.manifests import OCIManifestChecks
from pipeline_check.core.providers.oci import OCIProvider
from pipeline_check.core.scanner import Scanner


def _write_index(
    path: Path,
    *,
    annotations: dict[str, str] | None = None,
    entries: list[dict[str, Any]] | None = None,
) -> None:
    doc: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": entries or [],
    }
    if annotations is not None:
        doc["annotations"] = annotations
    path.write_text(json.dumps(doc), encoding="utf-8")


class TestOCIContextLoading:
    def test_loads_single_index_file(self, tmp_path: Path) -> None:
        idx = tmp_path / "index.json"
        _write_index(idx, annotations={
            "org.opencontainers.image.source": "https://github.com/x/y",
            "org.opencontainers.image.revision": "abc",
        })
        ctx = OCIContext.from_path(idx)
        assert ctx.files_scanned == 1
        assert ctx.files_skipped == 0
        assert len(ctx.manifests) == 1
        assert ctx.manifests[0].is_index

    def test_loads_directory_prefers_index_json(self, tmp_path: Path) -> None:
        # ``index.json`` takes priority over arbitrary other ``*.json``
        # files in the same directory.
        _write_index(tmp_path / "index.json")
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        ctx = OCIContext.from_path(tmp_path)
        assert len(ctx.manifests) == 1
        assert ctx.manifests[0].path.endswith("index.json")
        # ``package.json`` and other unrelated JSON should be skipped,
        # not warn-spamming the output.
        assert ctx.files_skipped >= 1

    def test_skips_unrelated_json(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            '{"name": "x", "version": "1.0"}', encoding="utf-8"
        )
        ctx = OCIContext.from_path(tmp_path)
        assert ctx.manifests == []
        assert ctx.files_skipped >= 1

    def test_warns_on_invalid_json(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not-json{", encoding="utf-8")
        ctx = OCIContext.from_path(bad)
        assert ctx.manifests == []
        assert any("JSON parse error" in w for w in ctx.warnings)

    def test_raises_when_path_missing(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            OCIContext.from_path(tmp_path / "missing.json")


class TestOCIManifestChecksOrchestrator:
    def test_runs_every_rule_per_manifest(self, tmp_path: Path) -> None:
        idx = tmp_path / "index.json"
        _write_index(idx, annotations={
            "org.opencontainers.image.source": "https://github.com/x/y",
            "org.opencontainers.image.revision": "abc",
            "org.opencontainers.image.created": "2025-05-09T12:00:00Z",
            "org.opencontainers.image.licenses": "Apache-2.0",
        }, entries=[
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:amd64",
                "size": 100,
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:att",
                "size": 100,
                "platform": {"architecture": "unknown", "os": "unknown"},
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": "sha256:amd64",
                },
            },
        ])
        ctx = OCIContext.from_path(idx)
        findings = OCIManifestChecks(ctx).run()
        ids = sorted(f.check_id for f in findings)
        assert ids == [
            "ATTEST-001", "ATTEST-002",
            "OCI-001", "OCI-002", "OCI-003",
            "OCI-004", "OCI-005", "OCI-006",
            "OCI-007", "OCI-008",
        ]
        # Every rule passes on this fully-stamped index (foreign-layer
        # / layer-count rules pass-by-default on indexes since they
        # have no layers of their own).
        assert all(f.passed for f in findings), [
            (f.check_id, f.description) for f in findings if not f.passed
        ]


class TestOCIProvider:
    def test_build_context_requires_path(self) -> None:
        provider = OCIProvider()
        with pytest.raises(ValueError, match="--oci-manifest"):
            provider.build_context()

    def test_inventory_index_records_attestations(self, tmp_path: Path) -> None:
        idx = tmp_path / "index.json"
        _write_index(idx, annotations={
            "org.opencontainers.image.source": "https://github.com/x/y",
        }, entries=[
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:amd64",
                "size": 100,
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:att",
                "size": 100,
                "platform": {"architecture": "unknown", "os": "unknown"},
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": "sha256:amd64",
                },
            },
        ])
        provider = OCIProvider()
        ctx = provider.build_context(oci_manifest=str(idx))
        components = provider.inventory(ctx)
        assert len(components) == 1
        c = components[0]
        assert c.type == "image_index"
        assert c.metadata["entry_count"] == 2
        assert c.metadata["attestation_count"] == 1
        assert c.metadata["platforms"] == ["linux/amd64"]
        assert (
            c.metadata["org.opencontainers.image.source"]
            == "https://github.com/x/y"
        )


class TestScannerWiring:
    def test_scanner_runs_oci_pipeline(self, tmp_path: Path) -> None:
        # End-to-end: Scanner picks up the OCI provider and routes
        # the path kwarg via ``--oci-manifest`` semantics.
        idx = tmp_path / "index.json"
        _write_index(idx, entries=[{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:a",
            "size": 100,
            "platform": {"architecture": "amd64", "os": "linux"},
        }])
        scanner = Scanner(pipeline="oci", oci_manifest=str(idx))
        findings = scanner.run()
        ids = sorted(f.check_id for f in findings)
        assert ids == [
            "ATTEST-001", "ATTEST-002",
            "OCI-001", "OCI-002", "OCI-003",
            "OCI-004", "OCI-005", "OCI-006",
            "OCI-007", "OCI-008",
        ]
        # OCI-001..003 + OCI-005 fire on a bare index (no
        # provenance / attestation / created / licenses annotations).
        # OCI-004 (foreign-layer) and OCI-006 (excessive layer count)
        # pass-by-default on indexes since the index has no layers.
        failed_ids = sorted(f.check_id for f in findings if not f.passed)
        assert failed_ids == [
            "OCI-001", "OCI-002", "OCI-003", "OCI-005",
        ]
