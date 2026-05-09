"""Per-rule tests for the OCI provider.

Each rule has its own ``Test<RULE_ID>...`` class. Inputs are built
inline as Python dicts and parsed through ``_parse_manifest`` so
the tests don't have to round-trip through JSON-on-disk; that
shape matches what every other ``rules/`` provider does.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.oci.base import (
    OCIManifest,
    _parse_manifest,
)
from pipeline_check.core.checks.oci.rules import (
    oci001_missing_provenance_annotations as r1,
)
from pipeline_check.core.checks.oci.rules import (
    oci002_missing_build_attestation as r2,
)
from pipeline_check.core.checks.oci.rules import (
    oci003_image_creation_unknown as r3,
)
from pipeline_check.core.checks.oci.rules import (
    oci004_foreign_layer_url as r4,
)
from pipeline_check.core.checks.oci.rules import (
    oci005_missing_license_annotation as r5,
)
from pipeline_check.core.checks.oci.rules import (
    oci006_excessive_layer_count as r6,
)
from pipeline_check.core.checks.oci.rules import (
    oci007_legacy_schema_v1 as r7,
)
from pipeline_check.core.checks.oci.rules import (
    oci008_weak_digest_algorithm as r8,
)


def _index(
    *,
    annotations: dict[str, str] | None = None,
    entries: list[dict[str, Any]] | None = None,
) -> OCIManifest:
    """Build an OCI image index with the given annotations / entries."""
    doc: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": entries or [],
    }
    if annotations is not None:
        doc["annotations"] = annotations
    parsed = _parse_manifest("index.json", doc)
    assert parsed is not None
    return parsed


def _single(
    *,
    annotations: dict[str, str] | None = None,
    layers: list[dict[str, Any]] | None = None,
) -> OCIManifest:
    """Build a single-platform OCI image manifest."""
    doc: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:cfg",
            "size": 100,
        },
        "layers": layers if layers is not None else [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:lyr",
                "size": 200,
            },
        ],
    }
    if annotations is not None:
        doc["annotations"] = annotations
    parsed = _parse_manifest("manifest.json", doc)
    assert parsed is not None
    return parsed


def _platform_entry(
    arch: str = "amd64", os_name: str = "linux",
) -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": f"sha256:{arch}",
        "size": 100,
        "platform": {"architecture": arch, "os": os_name},
    }


def _attestation_entry(target_digest: str = "sha256:amd64") -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": "sha256:att",
        "size": 100,
        "platform": {"architecture": "unknown", "os": "unknown"},
        "annotations": {
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": target_digest,
        },
    }


# ── OCI-001 ───────────────────────────────────────────────────────────


class TestOCI001MissingProvenanceAnnotations:
    def test_passes_when_both_annotations_set_on_index(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.source": "https://github.com/x/y",
            "org.opencontainers.image.revision": "abc",
        })
        f = r1.check(m)
        assert f.passed

    def test_passes_when_annotations_carried_on_per_platform_entry(
        self,
    ) -> None:
        # BuildKit copies the OCI image-spec annotations onto each
        # per-platform sub-manifest. ``primary_image_annotations``
        # unions across the index + entries, so a rule that only
        # checked the top-level would miss this case.
        entry = _platform_entry()
        entry["annotations"] = {
            "org.opencontainers.image.source": "https://github.com/x/y",
            "org.opencontainers.image.revision": "abc",
        }
        m = _index(entries=[entry])
        f = r1.check(m)
        assert f.passed

    def test_fails_when_annotations_absent_entirely(self) -> None:
        m = _index()
        f = r1.check(m)
        assert not f.passed
        assert "image.source" in f.description
        assert "image.revision" in f.description

    def test_fails_when_only_source_set(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.source": "https://github.com/x/y",
        })
        f = r1.check(m)
        assert not f.passed
        assert "image.revision" in f.description

    def test_fails_when_revision_blank_string(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.source": "https://github.com/x/y",
            "org.opencontainers.image.revision": "",
        })
        f = r1.check(m)
        assert not f.passed

    def test_fails_when_attestation_entry_carries_annotations_but_image_does_not(
        self,
    ) -> None:
        # Annotations on the attestation sub-manifest don't count as
        # runtime-image annotations; the helper should skip them.
        att = _attestation_entry()
        att["annotations"] = {
            **att["annotations"],
            "org.opencontainers.image.source": "https://github.com/x/y",
            "org.opencontainers.image.revision": "abc",
        }
        m = _index(entries=[_platform_entry(), att])
        f = r1.check(m)
        assert not f.passed

    def test_passes_on_single_image_manifest_with_annotations(self) -> None:
        m = _single(annotations={
            "org.opencontainers.image.source": "https://github.com/x/y",
            "org.opencontainers.image.revision": "abc",
        })
        f = r1.check(m)
        assert f.passed


# ── OCI-002 ───────────────────────────────────────────────────────────


class TestOCI002MissingBuildAttestation:
    def test_passes_when_index_has_attestation_entry(self) -> None:
        m = _index(entries=[_platform_entry(), _attestation_entry()])
        f = r2.check(m)
        assert f.passed
        assert "1 attestation" in f.description

    def test_passes_with_multiple_attestation_entries(self) -> None:
        # buildx with both ``--attest=type=provenance`` and
        # ``--attest=type=sbom`` produces two attestation manifests
        # (one per platform).
        m = _index(entries=[
            _platform_entry("amd64"),
            _platform_entry("arm64"),
            _attestation_entry("sha256:amd64"),
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:att2",
                "size": 100,
                "platform": {"architecture": "unknown", "os": "unknown"},
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": "sha256:arm64",
                },
            },
        ])
        f = r2.check(m)
        assert f.passed
        assert "2 attestation" in f.description

    def test_fails_when_index_has_no_attestation_entry(self) -> None:
        m = _index(entries=[_platform_entry()])
        f = r2.check(m)
        assert not f.passed
        assert "no attestation" in f.description.lower()

    def test_fails_on_single_image_manifest(self) -> None:
        # A single-image manifest can't carry attestations, the
        # contract requires the image-index shape.
        m = _single()
        f = r2.check(m)
        assert not f.passed
        assert "single-platform manifest" in f.description

    def test_fails_when_only_unrelated_sub_manifest_annotations(self) -> None:
        # An entry with annotations that don't include the
        # ``vnd.docker.reference.type: attestation-manifest`` key
        # is NOT an attestation manifest, even if it has other
        # annotations. Make sure the rule doesn't false-positive
        # on those.
        platform = _platform_entry()
        platform["annotations"] = {"some.other.key": "value"}
        m = _index(entries=[platform])
        f = r2.check(m)
        assert not f.passed


# ── OCI-003 ───────────────────────────────────────────────────────────


class TestOCI003ImageCreationUnknown:
    def test_passes_when_created_set_on_index(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.created": "2025-05-09T12:00:00Z",
        })
        f = r3.check(m)
        assert f.passed
        assert "2025-05-09T12:00:00Z" in f.description

    def test_passes_when_created_carried_on_per_platform_entry(self) -> None:
        entry = _platform_entry()
        entry["annotations"] = {
            "org.opencontainers.image.created": "2025-05-09T12:00:00Z",
        }
        m = _index(entries=[entry])
        f = r3.check(m)
        assert f.passed

    def test_fails_when_created_absent(self) -> None:
        m = _index()
        f = r3.check(m)
        assert not f.passed
        assert "image.created" in f.description

    def test_fails_when_created_blank(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.created": "  ",
        })
        f = r3.check(m)
        assert not f.passed

    def test_passes_on_single_image_manifest_with_created(self) -> None:
        m = _single(annotations={
            "org.opencontainers.image.created": "2025-05-09T12:00:00Z",
        })
        f = r3.check(m)
        assert f.passed


# ── OCI-004 ───────────────────────────────────────────────────────────


class TestOCI004ForeignLayerUrl:
    def test_passes_on_single_image_with_no_foreign_layers(self) -> None:
        m = _single()
        f = r4.check(m)
        assert f.passed

    def test_fails_when_layer_has_urls_field(self) -> None:
        m = _single(layers=[
            {
                "mediaType": (
                    "application/vnd.oci.image.layer.v1.tar+gzip"
                ),
                "digest": "sha256:" + "a" * 64,
                "size": 1234,
                "urls": ["https://example.com/blob.tar.gz"],
            },
        ])
        f = r4.check(m)
        assert not f.passed
        assert "foreign-URL" in f.description

    def test_fails_when_layer_uses_foreign_media_type(self) -> None:
        m = _single(layers=[
            {
                "mediaType": (
                    "application/vnd.docker.image.rootfs."
                    "foreign.diff.tar.gzip"
                ),
                "digest": "sha256:" + "b" * 64,
                "size": 1234,
            },
        ])
        f = r4.check(m)
        assert not f.passed

    def test_fails_when_oci_nondistributable_layer(self) -> None:
        m = _single(layers=[
            {
                "mediaType": (
                    "application/vnd.oci.image.layer."
                    "nondistributable.v1.tar+gzip"
                ),
                "digest": "sha256:" + "c" * 64,
                "size": 1234,
            },
        ])
        f = r4.check(m)
        assert not f.passed

    def test_passes_when_urls_field_is_empty_list(self) -> None:
        # Empty ``urls: []`` is technically present but doesn't
        # actually fetch from any URL, treat it as not-foreign.
        m = _single(layers=[
            {
                "mediaType": (
                    "application/vnd.oci.image.layer.v1.tar+gzip"
                ),
                "digest": "sha256:" + "d" * 64,
                "size": 1234,
                "urls": [],
            },
        ])
        f = r4.check(m)
        assert f.passed

    def test_passes_on_index(self) -> None:
        # Index has no layers itself, the rule passes (a downstream
        # scan of each per-platform manifest would catch sprawl).
        m = _index()
        f = r4.check(m)
        assert f.passed

    def test_lists_only_first_three_offenders(self) -> None:
        layers = [
            {
                "mediaType": (
                    "application/vnd.oci.image.layer.v1.tar+gzip"
                ),
                "digest": f"sha256:{i:064d}",
                "size": 100,
                "urls": [f"https://example.com/{i}.tar"],
            }
            for i in range(5)
        ]
        m = _single(layers=layers)
        f = r4.check(m)
        assert not f.passed
        # Truncation marker for >3 offenders.
        assert "..." in f.description
        assert "5 layer(s)" in f.description


# ── OCI-005 ───────────────────────────────────────────────────────────


class TestOCI005MissingLicenseAnnotation:
    def test_passes_when_licenses_set_on_index(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.licenses": "Apache-2.0",
        })
        f = r5.check(m)
        assert f.passed
        assert "Apache-2.0" in f.description

    def test_passes_with_compound_spdx_expression(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.licenses": "MIT AND Apache-2.0",
        })
        f = r5.check(m)
        assert f.passed

    def test_passes_when_carried_on_per_platform_entry(self) -> None:
        entry = _platform_entry()
        entry["annotations"] = {
            "org.opencontainers.image.licenses": "Apache-2.0",
        }
        m = _index(entries=[entry])
        f = r5.check(m)
        assert f.passed

    def test_fails_when_annotation_absent(self) -> None:
        m = _index()
        f = r5.check(m)
        assert not f.passed
        assert "image.licenses" in f.description

    def test_fails_when_annotation_blank(self) -> None:
        m = _index(annotations={
            "org.opencontainers.image.licenses": "  ",
        })
        f = r5.check(m)
        assert not f.passed

    def test_passes_on_single_image_manifest_with_license(self) -> None:
        m = _single(annotations={
            "org.opencontainers.image.licenses": "Apache-2.0",
        })
        f = r5.check(m)
        assert f.passed


# ── OCI-006 ───────────────────────────────────────────────────────────


def _layer(idx: int) -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": f"sha256:{idx:064d}",
        "size": 100,
    }


class TestOCI006ExcessiveLayerCount:
    def test_passes_at_default_layer_count(self) -> None:
        # The default ``_single()`` factory produces one layer.
        f = r6.check(_single())
        assert f.passed

    def test_passes_at_ceiling(self) -> None:
        # 40 layers exactly is OK; only above the ceiling fires.
        m = _single(layers=[_layer(i) for i in range(40)])
        f = r6.check(m)
        assert f.passed
        assert "40 layers" in f.description

    def test_fails_above_ceiling(self) -> None:
        m = _single(layers=[_layer(i) for i in range(41)])
        f = r6.check(m)
        assert not f.passed
        assert "41 layers" in f.description
        assert "ceiling" in f.description

    def test_fails_at_extreme_count(self) -> None:
        m = _single(layers=[_layer(i) for i in range(100)])
        f = r6.check(m)
        assert not f.passed
        assert "100 layers" in f.description

    def test_passes_on_index(self) -> None:
        # Index has no layers of its own.
        m = _index(entries=[_platform_entry()])
        f = r6.check(m)
        assert f.passed


# ── OCI-007 ───────────────────────────────────────────────────────────


class TestOCI007LegacySchemaV1:
    def test_passes_on_v2_index(self) -> None:
        f = r7.check(_index())
        assert f.passed

    def test_passes_on_v2_single_image(self) -> None:
        f = r7.check(_single())
        assert f.passed

    def test_fails_on_schema_v1(self) -> None:
        # Build a manifest with schemaVersion: 1, parsed via the
        # public path so the dataclass reflects what _parse_manifest
        # would produce on a real v1 doc.
        doc: dict[str, Any] = {
            "schemaVersion": 1,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:cfg",
                "size": 100,
            },
            "layers": [],
        }
        parsed = _parse_manifest("manifest.json", doc)
        assert parsed is not None
        f = r7.check(parsed)
        assert not f.passed
        assert "schemaVersion: 1" in f.description

    def test_fails_on_schema_v0_garbage(self) -> None:
        # ``schemaVersion: 0`` (or absent) lands on the rule too —
        # anything that isn't strictly 2 fails.
        doc: dict[str, Any] = {
            "schemaVersion": 0,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:cfg",
                "size": 100,
            },
            "layers": [],
        }
        parsed = _parse_manifest("manifest.json", doc)
        assert parsed is not None
        f = r7.check(parsed)
        assert not f.passed


# ── OCI-008 ───────────────────────────────────────────────────────────


class TestOCI008WeakDigestAlgorithm:
    def test_passes_on_default_sha256_single_image(self) -> None:
        f = r8.check(_single())
        assert f.passed

    def test_passes_on_sha512(self) -> None:
        m = _single(layers=[
            {
                "mediaType":
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha512:" + "0" * 128,
                "size": 100,
            },
        ])
        f = r8.check(m)
        assert f.passed

    def test_fails_on_sha1_layer(self) -> None:
        m = _single(layers=[
            {
                "mediaType":
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha1:" + "0" * 40,
                "size": 100,
            },
        ])
        f = r8.check(m)
        assert not f.passed
        assert "sha1" in f.description

    def test_fails_on_md5_config(self) -> None:
        # Build a manifest whose config uses md5 (impossible per
        # spec; the test exercises the detection).
        doc: dict[str, Any] = {
            "schemaVersion": 2,
            "mediaType":
                "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType":
                    "application/vnd.oci.image.config.v1+json",
                "digest": "md5:abcd1234",
                "size": 100,
            },
            "layers": [],
        }
        parsed = _parse_manifest("manifest.json", doc)
        assert parsed is not None
        f = r8.check(parsed)
        assert not f.passed
        assert "md5" in f.description

    def test_fails_on_index_entry_with_weak_digest(self) -> None:
        m = _index(entries=[
            {
                "mediaType":
                    "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha1:" + "0" * 40,
                "size": 100,
                "platform": {"architecture": "amd64", "os": "linux"},
            },
        ])
        f = r8.check(m)
        assert not f.passed

    def test_passes_on_empty_layers(self) -> None:
        # Single-image manifest with no layers, just a sha256 config:
        # nothing to flag.
        m = _single(layers=[])
        f = r8.check(m)
        assert f.passed
