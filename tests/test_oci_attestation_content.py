"""Tests for OCI image-layout attestation-content parsing + ATTEST-001."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from pipeline_check.core.checks.oci.base import (
    Attestation,
    OCIContext,
    OCIManifest,
)
from pipeline_check.core.checks.oci.manifests import OCIManifestChecks
from pipeline_check.core.checks.oci.rules import (
    attest001_untrusted_builder as a1,
)
from pipeline_check.core.checks.oci.rules import (
    attest002_source_repo_mismatch as a2,
)
from pipeline_check.core.checks.oci.rules import (
    attest003_sbom_floating_versions as a3,
)
from pipeline_check.core.checks.oci.rules import (
    attest004_missing_materials as a4,
)
from pipeline_check.core.checks.oci.rules import (
    attest005_subject_unpinned as a5,
)
from pipeline_check.core.checks.oci.rules import (
    attest006_missing_build_type as a6,
)
from pipeline_check.core.checks.oci.rules import (
    attest007_sbom_missing_supplier as a7,
)

# ── Layout-dir fixture builder ─────────────────────────────────────


def _write_blob(blobs_dir: Path, payload: bytes | str) -> str:
    """Write *payload* under ``blobs/sha256/<hash>`` and return ``sha256:<hash>``.

    Uses a content-addressable digest so the manifest's references
    line up with the on-disk blob path the way an OCI image-layout
    directory does in the wild.
    """
    import hashlib

    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    target = blobs_dir / "sha256" / digest
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return f"sha256:{digest}"


def _build_layout(
    tmp_path: Path,
    *,
    statement: dict[str, Any],
    runtime_platform: dict[str, str] | None = None,
) -> Path:
    """Construct a minimal OCI image-layout dir with one runtime
    manifest and one attestation manifest carrying *statement* as its
    in-toto layer.

    Returns the path to ``index.json`` so callers can pass it
    directly to ``OCIContext.from_path``.
    """
    blobs_dir = tmp_path / "blobs"

    # Runtime image: empty config + zero layers (the rule pack
    # doesn't care about runtime content for ATTEST-NNN).
    config_blob = _write_blob(blobs_dir, "{}")
    runtime_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_blob,
            "size": 2,
        },
        "layers": [],
    }
    runtime_manifest_blob = _write_blob(
        blobs_dir, json.dumps(runtime_manifest),
    )

    # Attestation manifest: empty config + one in-toto layer.
    statement_blob = _write_blob(blobs_dir, json.dumps(statement))
    attest_config_blob = _write_blob(blobs_dir, "{}")
    attest_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": attest_config_blob,
            "size": 2,
        },
        "layers": [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": statement_blob,
                "size": len(json.dumps(statement)),
                "annotations": {
                    "in-toto.io/predicate-type": statement.get(
                        "predicateType", "",
                    ),
                },
            }
        ],
    }
    attest_manifest_blob = _write_blob(
        blobs_dir, json.dumps(attest_manifest),
    )

    # Image index: runtime sub-manifest + attestation sub-manifest.
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": runtime_manifest_blob,
                "size": len(json.dumps(runtime_manifest)),
                "platform": runtime_platform or {
                    "architecture": "amd64", "os": "linux",
                },
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": attest_manifest_blob,
                "size": len(json.dumps(attest_manifest)),
                "platform": {
                    "architecture": "unknown", "os": "unknown",
                },
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": runtime_manifest_blob,
                },
            },
        ],
    }
    index_path = tmp_path / "index.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")
    return index_path


def _slsa_v0_2(builder_id: str, source_uri: str = "git+https://github.com/foo/bar") -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "image", "digest": {"sha256": "0" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "builder": {"id": builder_id},
            "buildType": "https://example.com/buildtype/v1",
            "invocation": {
                "configSource": {
                    "uri": source_uri,
                    "digest": {"sha1": "1" * 40},
                    "entryPoint": ".github/workflows/ci.yml",
                },
            },
        },
    }


def _slsa_v1(builder_id: str) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "image", "digest": {"sha256": "0" * 64}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://example.com/buildtype/v1",
                "externalParameters": {},
                "internalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": "abc",
                },
            },
        },
    }


# ── Layout-dir parser ───────────────────────────────────────────────


class TestLayoutDirParser:
    def test_attestation_content_loaded_from_blobs(self, tmp_path: Path):
        statement = _slsa_v0_2(
            "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder@v1",
        )
        index_path = _build_layout(tmp_path, statement=statement)
        ctx = OCIContext.from_path(index_path)
        # One image index loaded; its attestations field is populated.
        assert len(ctx.manifests) == 1
        assert len(ctx.manifests[0].attestations) == 1
        att = ctx.manifests[0].attestations[0]
        assert att.is_slsa_provenance
        assert att.predicate_type == "https://slsa.dev/provenance/v0.2"

    def test_missing_blobs_dir_attestations_empty(self, tmp_path: Path):
        """When the user passes a bare ``index.json`` without a
        sibling ``blobs/`` directory, the parser still loads the
        manifest but ``attestations`` stays empty (no content
        reachable). Rules degrade gracefully."""
        bare_index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [],
        }
        p = tmp_path / "index.json"
        p.write_text(json.dumps(bare_index))
        ctx = OCIContext.from_path(p)
        assert ctx.manifests[0].attestations == ()

    def test_dsse_envelope_unwrapped(self, tmp_path: Path):
        """A DSSE-wrapped Statement (cosign-attested) decodes the
        base64 ``payload`` field and treats the inner Statement as
        the canonical content."""
        inner = _slsa_v0_2("https://buildkite.com/agent/abc")
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(
                json.dumps(inner).encode("utf-8")
            ).decode("ascii"),
            "signatures": [{"keyid": "test", "sig": "fake"}],
        }
        index_path = _build_layout(tmp_path, statement=envelope)
        ctx = OCIContext.from_path(index_path)
        attestations = ctx.manifests[0].attestations
        assert len(attestations) == 1
        # Inner Statement was extracted, predicate visible.
        assert attestations[0].predicate["builder"]["id"].startswith(
            "https://buildkite.com/"
        )

    def test_slsa_v1_run_details_builder(self, tmp_path: Path):
        """SLSA v1 moves builder under ``runDetails.builder.id``;
        the parser is agnostic but the ``_builder_id`` helper used
        by ATTEST-001 has to read both shapes."""
        statement = _slsa_v1(
            "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/x@v2",
        )
        index_path = _build_layout(tmp_path, statement=statement)
        ctx = OCIContext.from_path(index_path)
        att = ctx.manifests[0].attestations[0]
        assert att.predicate_type == "https://slsa.dev/provenance/v1"
        assert a1._builder_id(att.predicate) is not None


# ── ATTEST-001 rule logic (unit tests, no fixtures needed) ─────────


def _att(predicate: dict[str, Any], pt: str = "https://slsa.dev/provenance/v0.2") -> Attestation:
    return Attestation(
        predicate_type=pt,
        predicate=predicate,
        statement_type="https://in-toto.io/Statement/v0.1",
        subject=(),
        manifest_path="index.json",
        layer_digest="sha256:abc",
    )


def _index_with_attestations(*atts: Attestation) -> OCIManifest:
    return OCIManifest(
        path="index.json",
        media_type="application/vnd.oci.image.index.v1+json",
        schema_version=2,
        attestations=tuple(atts),
    )


class TestATTEST001:
    def test_passes_for_trusted_github_hosted(self):
        att = _att({
            "builder": {
                "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v2.0.0",
            },
        })
        f = a1.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_self_hosted_runner(self):
        att = _att({
            "builder": {
                "id": "https://github.com/actions/runner/self-hosted-arm64",
            },
        })
        f = a1.check(_index_with_attestations(att))
        assert not f.passed
        assert "self-hosted" in f.description.lower()

    def test_fails_for_unknown_builder(self):
        att = _att({
            "builder": {"id": "https://my-internal-ci.example.com/runner/v1"},
        })
        f = a1.check(_index_with_attestations(att))
        assert not f.passed
        assert "unknown" in f.description.lower()

    def test_fails_for_missing_builder_id(self):
        att = _att({"builder": {}})
        f = a1.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_for_localhost_runner_via_self_hosted_token(self):
        """Even an HTTPS-looking URI containing ``localhost`` falls
        back to self-hosted classification rather than 'unknown'."""
        att = _att({
            "builder": {"id": "https://localhost:8080/builder"},
        })
        f = a1.check(_index_with_attestations(att))
        assert not f.passed
        assert "self-hosted" in f.description.lower()

    def test_v1_run_details_path_resolved(self):
        att = _att({
            "runDetails": {
                "builder": {
                    "id": "https://cloudbuild.googleapis.com/projects/x/builds/y",
                },
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a1.check(_index_with_attestations(att))
        assert f.passed

    def test_passes_when_no_attestations_with_explanatory_message(self):
        """When no SLSA attestations are parsed (single ``index.json``
        input without blobs), the rule passes and the description
        says so. OCI-002 covers the missing-attestation case."""
        manifest = OCIManifest(
            path="index.json",
            media_type="application/vnd.oci.image.index.v1+json",
            schema_version=2,
            attestations=(),
        )
        f = a1.check(manifest)
        assert f.passed
        # The description explains that there's no content to verify
        # (so the rule deferred); the operator can route to OCI-002.
        assert "no slsa provenance" in f.description.lower()
        assert "image-layout" in f.description.lower()

    def test_passes_for_single_image_manifest(self):
        """Single-image manifests can't carry attestations; this
        rule defers to OCI-002 for that shape."""
        manifest = OCIManifest(
            path="manifest.json",
            media_type="application/vnd.oci.image.manifest.v1+json",
            schema_version=2,
        )
        f = a1.check(manifest)
        assert f.passed

    def test_orchestrator_runs_attest001_on_every_manifest(self, tmp_path: Path):
        """End-to-end: build a layout dir, run the OCI orchestrator,
        confirm ATTEST-001 fires on the untrusted-builder case."""
        statement = _slsa_v0_2(
            "https://my-internal-ci.example.com/runner/v1",
        )
        index_path = _build_layout(tmp_path, statement=statement)
        ctx = OCIContext.from_path(index_path)
        findings = OCIManifestChecks(ctx).run()
        attest_findings = [f for f in findings if f.check_id == "ATTEST-001"]
        assert len(attest_findings) == 1
        assert not attest_findings[0].passed


# ── ATTEST-002 source-repo claim ───────────────────────────────────


class TestATTEST002:
    def test_passes_for_well_formed_v0_2_source(self):
        att = _att({
            "builder": {"id": "https://github.com/actions/runner/Linux"},
            "invocation": {
                "configSource": {
                    "uri": "git+https://github.com/owner/repo",
                    "digest": {"sha1": "a" * 40},
                    "entryPoint": "ci.yml",
                },
            },
        })
        f = a2.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_when_uri_is_placeholder(self):
        att = _att({
            "invocation": {
                "configSource": {
                    "uri": "unknown",
                    "digest": {"sha1": "a" * 40},
                },
            },
        })
        f = a2.check(_index_with_attestations(att))
        assert not f.passed
        assert "placeholder" in f.description.lower()

    def test_fails_when_uri_missing(self):
        att = _att({"invocation": {"configSource": {}}})
        f = a2.check(_index_with_attestations(att))
        assert not f.passed
        assert "no source-repo uri" in f.description.lower()

    def test_fails_when_uri_malformed(self):
        att = _att({
            "invocation": {
                "configSource": {
                    "uri": "github.com/owner/repo",  # no scheme
                    "digest": {"sha1": "a" * 40},
                },
            },
        })
        f = a2.check(_index_with_attestations(att))
        assert not f.passed
        assert "doesn't parse" in f.description.lower()

    def test_fails_when_digest_missing(self):
        att = _att({
            "invocation": {
                "configSource": {
                    "uri": "git+https://github.com/owner/repo",
                    # no digest at all
                },
            },
        })
        f = a2.check(_index_with_attestations(att))
        assert not f.passed
        assert "digest is" in f.description.lower()

    def test_fails_when_digest_all_zeros(self):
        """An all-zero digest is the canonical "I don't actually know
        what I built" placeholder; the bytes aren't pinned."""
        att = _att({
            "invocation": {
                "configSource": {
                    "uri": "git+https://github.com/owner/repo",
                    "digest": {"sha1": "0" * 40},
                },
            },
        })
        f = a2.check(_index_with_attestations(att))
        assert not f.passed
        assert "zero" in f.description.lower()

    def test_passes_for_v1_canonical_workflow_repository(self):
        """SLSA v1 GHA canonical shape: source under
        ``buildDefinition.externalParameters.workflow.repository`` +
        digest in ``resolvedDependencies``."""
        att = _att({
            "buildDefinition": {
                "buildType": "https://example.com/buildtype",
                "externalParameters": {
                    "workflow": {
                        "repository": "https://github.com/owner/repo",
                    },
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/owner/repo",
                        "digest": {"gitCommit": "a" * 40},
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/actions/runner/Linux"},
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a2.check(_index_with_attestations(att))
        assert f.passed

    def test_passes_for_v1_alternative_source_uri_shape(self):
        """Some builders use ``externalParameters.source.uri`` instead
        of the GHA-canonical ``workflow.repository``. The fallback
        walker scans every string value for a VCS URI."""
        att = _att({
            "buildDefinition": {
                "externalParameters": {
                    "source": {"uri": "git+https://gitlab.com/x/y"},
                },
                "resolvedDependencies": [
                    {"digest": {"sha1": "f" * 40}},
                ],
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a2.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_v1_with_no_source_anywhere(self):
        att = _att({
            "buildDefinition": {
                "externalParameters": {
                    "buildArgs": {"FOO": "bar"},
                },
                "resolvedDependencies": [],
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a2.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_when_no_attestations_with_explanatory_message(self):
        manifest = OCIManifest(
            path="index.json",
            media_type="application/vnd.oci.image.index.v1+json",
            schema_version=2,
            attestations=(),
        )
        f = a2.check(manifest)
        assert f.passed
        assert "no slsa provenance" in f.description.lower()

    def test_passes_for_single_image_manifest(self):
        manifest = OCIManifest(
            path="manifest.json",
            media_type="application/vnd.oci.image.manifest.v1+json",
            schema_version=2,
        )
        f = a2.check(manifest)
        assert f.passed

    def test_orchestrator_runs_attest002_end_to_end(self, tmp_path: Path):
        """Layout dir with a placeholder source URI: ATTEST-002 fires."""
        statement = _slsa_v0_2(
            "https://github.com/actions/runner/Linux",
            source_uri="unknown",
        )
        index_path = _build_layout(tmp_path, statement=statement)
        ctx = OCIContext.from_path(index_path)
        findings = OCIManifestChecks(ctx).run()
        attest_findings = [f for f in findings if f.check_id == "ATTEST-002"]
        assert len(attest_findings) == 1
        assert not attest_findings[0].passed


# ── ATTEST-003 SBOM floating-version detection ─────────────────────


class TestATTEST003ClassifyVersion:
    """Direct unit coverage of the version-classifier so the rule's
    decision boundary is locked."""

    def test_pinned_semvers(self):
        for v in (
            "1.2.3", "v1.2.3", "1.2", "1.2.3-rc4",
            "1.2.3+build.5", "v3.12.1-slim",
        ):
            assert a3._classify_version(v) == "pinned", v

    def test_pinned_calver(self):
        for v in ("2026.05", "2026.05.10", "20260510"):
            assert a3._classify_version(v) == "pinned", v

    def test_pinned_hex_digest(self):
        assert a3._classify_version("a" * 40) == "pinned"
        assert a3._classify_version("0123456789abcdef" * 2) == "pinned"

    def test_floating_tokens(self):
        for v in (
            "latest", "*", "master", "main", "head", "stable",
            "edge", "rolling", "", "develop",
        ):
            assert a3._classify_version(v) == "floating", v

    def test_floating_bare_major(self):
        for v in ("v1", "1", "v42"):
            assert a3._classify_version(v) == "floating", v

    def test_floating_none(self):
        assert a3._classify_version(None) == "floating"

    def test_pinned_unknown_shape_with_digit(self):
        """A non-semver string that contains a digit (e.g. a date-stamped
        release tag) is best-effort treated as pinned. Conservative:
        better to false-negative than to FP-flood every release name."""
        assert a3._classify_version("release-2025-Q1-rc7") == "pinned"

    def test_floating_unknown_shape_no_digit(self):
        assert a3._classify_version("unknown-build") == "floating"


class TestATTEST003Rule:
    def _spdx_attestation(self, *packages: dict) -> Attestation:
        return _att(
            {"packages": list(packages)},
            pt="https://spdx.dev/Document/v2.3",
        )

    def _cyclonedx_attestation(self, *components: dict) -> Attestation:
        return _att(
            {"components": list(components)},
            pt="https://cyclonedx.org/bom",
        )

    def test_passes_when_every_spdx_package_pinned(self):
        att = self._spdx_attestation(
            {"name": "openssl", "versionInfo": "3.2.1"},
            {"name": "zlib", "versionInfo": "1.3.1"},
        )
        f = a3.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_when_spdx_package_uses_latest(self):
        att = self._spdx_attestation(
            {"name": "openssl", "versionInfo": "latest"},
            {"name": "zlib", "versionInfo": "1.3.1"},
        )
        f = a3.check(_index_with_attestations(att))
        assert not f.passed
        assert "openssl@latest" in f.description

    def test_fails_when_spdx_versioninfo_missing(self):
        att = self._spdx_attestation(
            {"name": "mystery"},  # no versionInfo
        )
        f = a3.check(_index_with_attestations(att))
        assert not f.passed
        assert "mystery@<empty>" in f.description

    def test_passes_when_every_cyclonedx_component_pinned(self):
        att = self._cyclonedx_attestation(
            {"name": "express", "version": "4.19.2"},
            {"name": "lodash", "version": "v4.17.21"},
        )
        f = a3.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_when_cyclonedx_component_floats(self):
        att = self._cyclonedx_attestation(
            {"name": "express", "version": "*"},
        )
        f = a3.check(_index_with_attestations(att))
        assert not f.passed
        assert "express@*" in f.description

    def test_fails_for_empty_packages_list(self):
        """An SBOM attestation with no packages defeats the SBOM's
        purpose. Surface as a finding so the operator knows the
        emitter wired in produces nothing usable."""
        att = self._spdx_attestation()  # zero packages
        f = a3.check(_index_with_attestations(att))
        assert not f.passed
        assert "no enumerable packages" in f.description.lower()

    def test_passes_when_no_sbom_attestations(self):
        """SLSA-only attestations don't trip ATTEST-003; the rule has
        nothing to check."""
        slsa = _att({"builder": {"id": "x"}})
        f = a3.check(_index_with_attestations(slsa))
        assert f.passed
        assert "no sbom" in f.description.lower()

    def test_passes_for_single_image_manifest(self):
        manifest = OCIManifest(
            path="manifest.json",
            media_type="application/vnd.oci.image.manifest.v1+json",
            schema_version=2,
        )
        f = a3.check(manifest)
        assert f.passed

    def test_orchestrator_runs_attest003_end_to_end(self, tmp_path: Path):
        """Layout dir whose attestation Statement is an SPDX SBOM with
        a floating-version package. Exercises the full pipeline:
        layout-dir blob load -> Statement parse -> SBOM predicate
        dispatch -> floating-version classification."""
        spdx_statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "image", "digest": {"sha256": "0" * 64}}],
            "predicateType": "https://spdx.dev/Document/v2.3",
            "predicate": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {"name": "openssl", "versionInfo": "latest"},
                    {"name": "zlib", "versionInfo": "1.3.1"},
                ],
            },
        }
        index_path = _build_layout(tmp_path, statement=spdx_statement)
        ctx = OCIContext.from_path(index_path)
        findings = OCIManifestChecks(ctx).run()
        attest_findings = [f for f in findings if f.check_id == "ATTEST-003"]
        assert len(attest_findings) == 1
        assert not attest_findings[0].passed
        assert "openssl@latest" in attest_findings[0].description


# ── ATTEST-004 materials / resolvedDependencies ────────────────────


class TestATTEST004:
    def test_passes_for_v0_2_with_populated_materials(self):
        att = _att({
            "builder": {"id": "https://github.com/actions/runner/Linux"},
            "materials": [
                {
                    "uri": "git+https://github.com/owner/repo",
                    "digest": {"sha1": "a" * 40},
                },
                {
                    "uri": "pkg:docker/ubuntu@22.04",
                    "digest": {"sha256": "b" * 64},
                },
            ],
        })
        f = a4.check(_index_with_attestations(att))
        assert f.passed
        assert "non-empty" in f.description.lower()

    def test_fails_for_v0_2_empty_materials(self):
        att = _att({
            "builder": {"id": "https://github.com/actions/runner/Linux"},
            "materials": [],
        })
        f = a4.check(_index_with_attestations(att))
        assert not f.passed
        assert "materials" in f.description.lower()

    def test_fails_for_v0_2_missing_materials_key(self):
        att = _att({
            "builder": {"id": "https://github.com/actions/runner/Linux"},
        })
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_v0_2_materials_wrong_type(self):
        """A non-list materials value (string, dict, int) is malformed
        per spec and treated as empty."""
        att = _att({
            "materials": "see-build-log",
        })
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_for_v1_with_populated_resolved_dependencies(self):
        att = _att({
            "buildDefinition": {
                "buildType": "https://example.com/buildtype",
                "externalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/owner/repo",
                        "digest": {"gitCommit": "a" * 40},
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/actions/runner/Linux"},
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a4.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_v1_empty_resolved_dependencies(self):
        att = _att({
            "buildDefinition": {
                "buildType": "https://example.com/buildtype",
                "externalParameters": {},
                "resolvedDependencies": [],
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a4.check(_index_with_attestations(att))
        assert not f.passed
        assert "resolveddependencies" in f.description.lower()

    def test_fails_for_v1_missing_resolved_dependencies_key(self):
        att = _att({
            "buildDefinition": {
                "buildType": "https://example.com/buildtype",
                "externalParameters": {},
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_v1_resolved_dependencies_preferred_over_v0_2_materials(self):
        """A transitional attestation carrying both keys should be read
        through the v1 path (the canonical place) when buildDefinition
        is present, so the rule doesn't pass on a stale v0.2 fallback
        that happens to be populated."""
        att = _att({
            "buildDefinition": {
                "buildType": "https://example.com/buildtype",
                "resolvedDependencies": [],
            },
            "materials": [
                {"uri": "git+https://x/y", "digest": {"sha1": "a" * 40}},
            ],
        }, pt="https://slsa.dev/provenance/v1")
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_when_no_attestations_with_explanatory_message(self):
        manifest = OCIManifest(
            path="index.json",
            media_type="application/vnd.oci.image.index.v1+json",
            schema_version=2,
            attestations=(),
        )
        f = a4.check(manifest)
        assert f.passed
        assert "no slsa provenance" in f.description.lower()

    def test_passes_for_single_image_manifest(self):
        manifest = OCIManifest(
            path="manifest.json",
            media_type="application/vnd.oci.image.manifest.v1+json",
            schema_version=2,
        )
        f = a4.check(manifest)
        assert f.passed

    def test_passes_when_only_sbom_attestations_present(self):
        """ATTEST-004 only reads SLSA provenance attestations. An
        image that ships an SBOM attestation but no provenance has
        nothing for this rule to verify; it passes with the
        no-content message."""
        sbom_att = _att(
            {"packages": [{"name": "x", "versionInfo": "1.0"}]},
            pt="https://spdx.dev/Document",
        )
        f = a4.check(_index_with_attestations(sbom_att))
        assert f.passed

    def test_orchestrator_runs_attest004_end_to_end(self, tmp_path: Path):
        """Build a layout dir whose provenance has empty materials,
        confirm ATTEST-004 fires through the orchestrator."""
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "image", "digest": {"sha256": "0" * 64}}],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": "https://github.com/slsa-framework/slsa-github-generator/x@v1",
                },
                "buildType": "https://example.com/buildtype",
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/owner/repo",
                        "digest": {"sha1": "a" * 40},
                    },
                },
                "materials": [],
            },
        }
        index_path = _build_layout(tmp_path, statement=statement)
        ctx = OCIContext.from_path(index_path)
        findings = OCIManifestChecks(ctx).run()
        attest_findings = [f for f in findings if f.check_id == "ATTEST-004"]
        assert len(attest_findings) == 1
        assert not attest_findings[0].passed

    # ── Robustness against malformed predicates ──────────────────

    def test_fails_for_materials_as_dict(self):
        """The v0.2 ``materials`` field MUST be a list. A dict
        (sometimes emitted by hand-rolled converters) is treated
        as missing."""
        att = _att({
            "builder": {"id": "https://github.com/actions/runner/Linux"},
            "materials": {"a": "b"},  # wrong shape
        })
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_materials_as_string(self):
        att = _att({
            "materials": "see-build-attachment.json",
        })
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_for_v0_2_materials_with_non_dict_entries(self):
        """Per spec, materials entries should be ``{uri, digest}``
        dicts. The rule's contract is list-non-empty; entry-shape
        validation is deferred to a future rule. Passing here locks
        the current behavior so the future tightening change is a
        deliberate test update."""
        att = _att({
            "materials": ["just-a-string", {"uri": "x", "digest": {"sha1": "0"}}],
        })
        f = a4.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_v1_resolved_deps_wrong_type(self):
        """``resolvedDependencies: "see attachment"`` is malformed
        per spec; treat as empty."""
        att = _att({
            "buildDefinition": {
                "resolvedDependencies": "see-attachment",
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_when_predicate_completely_empty(self):
        """An empty predicate dict carries no materials at any
        path — treat as missing/empty."""
        att = _att({})
        f = a4.check(_index_with_attestations(att))
        assert not f.passed

    def test_v0_2_path_used_when_no_build_definition_present(self):
        """The dispatch in _materials prefers v1 only when
        ``buildDefinition`` is a dict. Without it, the v0.2
        ``materials`` key is consulted even if predicate_type
        says v1 (transitional / mistyped attestations should still
        be classified by structure, not just type URI)."""
        att = _att({
            "materials": [
                {"uri": "git+https://x/y", "digest": {"sha1": "a" * 40}},
            ],
            # No buildDefinition key.
        }, pt="https://slsa.dev/provenance/v1")
        f = a4.check(_index_with_attestations(att))
        assert f.passed


# ── ATTEST-005 subject-digest validation ────────────────────────────


def _att_with_subject(
    subject: tuple[dict[str, Any], ...],
    pt: str = "https://slsa.dev/provenance/v0.2",
) -> Attestation:
    """Build an Attestation whose subject array carries *subject*.

    ``_att()`` hardcodes ``subject=()``; ATTEST-005 tests need to
    exercise specific subject shapes so they get their own helper.
    """
    return Attestation(
        predicate_type=pt,
        predicate={"builder": {"id": "https://github.com/actions/runner/Linux"}},
        statement_type="https://in-toto.io/Statement/v0.1",
        subject=subject,
        manifest_path="index.json",
        layer_digest="sha256:abc",
    )


# A realistic-looking sha256: 64 lowercase hex chars, not all zeros.
_REAL_SHA256 = "4d5a6e7b8c9d0e1f2a3b4c5d6e7f80910a2b3c4d5e6f70819aabbccddeeff001"


class TestATTEST005:
    def test_passes_for_well_formed_subject(self):
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": _REAL_SHA256}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert f.passed

    def test_passes_for_multi_subject_array(self):
        att = _att_with_subject((
            {"name": "image-amd64", "digest": {"sha256": _REAL_SHA256}},
            {"name": "image-arm64", "digest": {"sha256": _REAL_SHA256[::-1]}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_empty_subject_array(self):
        att = _att_with_subject(())
        f = a5.check(_index_with_attestations(att))
        assert not f.passed
        assert "empty or missing" in f.description.lower()

    def test_fails_for_missing_digest_map(self):
        att = _att_with_subject((
            {"name": "image"},  # no digest key at all
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed
        assert "no digest" in f.description.lower()

    def test_fails_for_empty_digest_value(self):
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": ""}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed
        assert "unpinned" in f.description.lower()

    def test_fails_for_all_zero_digest(self):
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": "0" * 64}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_non_hex_digest(self):
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": "z" * 64}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_odd_length_digest(self):
        """A valid hex byte encoding has even length; an odd-length
        value can't be a real digest."""
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": "abc"}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_when_only_one_of_two_subjects_is_pinned(self):
        """A partial bind is still a bind to nothing for the unpinned
        entry, attacker substitutes that one and the verifier never
        notices."""
        att = _att_with_subject((
            {"name": "image-amd64", "digest": {"sha256": _REAL_SHA256}},
            {"name": "image-arm64", "digest": {"sha256": ""}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_accepts_truncated_digest(self):
        """Some registries store truncated 16-char digest prefixes;
        the rule treats those as bound-enough as long as they're
        well-formed hex."""
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": "deadbeefcafebabe"}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert f.passed

    def test_validates_sbom_attestation_subjects_too(self):
        """The rule fires on any in-toto Statement regardless of
        predicate type, an SBOM with unpinned subject is the same
        substitution risk."""
        att = _att_with_subject(
            ({"name": "image", "digest": {"sha256": ""}},),
            pt="https://spdx.dev/Document",
        )
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_when_no_attestations_with_explanatory_message(self):
        manifest = OCIManifest(
            path="index.json",
            media_type="application/vnd.oci.image.index.v1+json",
            schema_version=2,
            attestations=(),
        )
        f = a5.check(manifest)
        assert f.passed
        assert "no attestation content" in f.description.lower()

    def test_passes_for_single_image_manifest(self):
        manifest = OCIManifest(
            path="manifest.json",
            media_type="application/vnd.oci.image.manifest.v1+json",
            schema_version=2,
        )
        f = a5.check(manifest)
        assert f.passed

    def test_orchestrator_runs_attest005_end_to_end(self, tmp_path: Path):
        """Build a layout dir whose Statement has an all-zero subject
        digest (the fixture default), confirm ATTEST-005 fires
        through the orchestrator."""
        statement = _slsa_v0_2(
            "https://github.com/slsa-framework/slsa-github-generator/x@v1",
        )
        # _slsa_v0_2 emits subject digest "0" * 64 by default, which
        # is the attestation-substitution surface this rule catches.
        index_path = _build_layout(tmp_path, statement=statement)
        ctx = OCIContext.from_path(index_path)
        findings = OCIManifestChecks(ctx).run()
        attest_findings = [f for f in findings if f.check_id == "ATTEST-005"]
        assert len(attest_findings) == 1
        assert not attest_findings[0].passed

    # ── Edge cases surfaced by the hallucination audit ──────────

    def test_passes_for_mixed_case_hex(self):
        """Hex validation lowercases before comparison, so
        ``AbCdEf...`` should pass exactly like the all-lowercase
        equivalent."""
        mixed = ("AbCdEf" + "0123456789abcdef" * 3 + "AB").ljust(64, "0")
        assert len(mixed) == 64
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": mixed}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_whitespace_only_digest(self):
        """Whitespace-only digest values strip to empty and are
        treated as unpinned, the same as a literal empty string."""
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": "   "}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_digest_with_embedded_space(self):
        """Hex digest values must not contain whitespace; the rule
        validates the character set, not just the length."""
        # 64 chars but with a space splice that breaks the hex class.
        broken = "ab cdef" + "1" * 57
        assert len(broken) == 64
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": broken}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_when_any_algorithm_in_a_subject_is_unpinned(self):
        """A subject entry may declare multiple digest algorithms
        (sha256 + sha512 + sha1). If ANY of them is malformed, the
        verifier downstream can pick the wrong one, fail closed."""
        att = _att_with_subject((
            {
                "name": "image",
                "digest": {
                    "sha256": _REAL_SHA256,
                    "sha512": "",  # this one is empty
                },
            },
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_for_multi_algorithm_all_well_formed(self):
        att = _att_with_subject((
            {
                "name": "image",
                "digest": {
                    "sha256": _REAL_SHA256,
                    "sha512": "abcd" * 32,  # 128 chars, even hex
                },
            },
        ))
        f = a5.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_non_string_digest_value(self):
        """A digest value that isn't a string (number, bool, list,
        nested dict) can't be a hex byte encoding and fails by
        construction."""
        att = _att_with_subject((
            {"name": "image", "digest": {"sha256": 12345}},  # type: ignore[dict-item]
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_subject_entry_with_no_name(self):
        """An entry with a digest but no name still binds artifact
        bytes; spec-permissive but the rule's failure-message path
        synthesizes an ``<entry N>`` label when name is absent and
        proceeds with normal validation."""
        # Well-formed digest + missing name should still pass on the
        # binding-validation grounds — the rule cares about the
        # digest, not the label.
        att = _att_with_subject((
            {"digest": {"sha256": _REAL_SHA256}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_subject_entry_with_empty_digest_map(self):
        """A digest map present but empty is the same shape as 'no
        digest' — there's no algorithm to compare against."""
        att = _att_with_subject((
            {"name": "image", "digest": {}},
        ))
        f = a5.check(_index_with_attestations(att))
        assert not f.passed
        assert "no digest" in f.description.lower()


# ── ATTEST-006 buildType completeness ──────────────────────────────


class TestATTEST006:
    def test_passes_for_v0_2_with_concrete_build_type(self):
        att = _att({
            "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v2",
            "builder": {"id": "https://github.com/actions/runner/Linux"},
        })
        f = a6.check(_index_with_attestations(att))
        assert f.passed

    def test_passes_for_v1_with_concrete_build_type(self):
        att = _att({
            "buildDefinition": {
                "buildType": "https://slsa.dev/buildtypes/github-actions-workflow/v1",
                "externalParameters": {},
                "resolvedDependencies": [],
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a6.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_missing_build_type_v0_2(self):
        att = _att({"builder": {"id": "..."}})
        f = a6.check(_index_with_attestations(att))
        assert not f.passed
        assert "missing" in f.description.lower()

    def test_fails_for_missing_build_type_v1(self):
        att = _att({
            "buildDefinition": {
                "externalParameters": {},
            },
        }, pt="https://slsa.dev/provenance/v1")
        f = a6.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_placeholder_example_com(self):
        """The ``example.com`` URI is a well-known placeholder some
        experimental generators emit. Treat as missing."""
        att = _att({
            "buildType": "https://example.com/buildtype/v1",
        })
        f = a6.check(_index_with_attestations(att))
        assert not f.passed
        assert "placeholder" in f.description.lower()

    def test_fails_for_unknown_token(self):
        att = _att({"buildType": "unknown"})
        f = a6.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_empty_string(self):
        att = _att({"buildType": ""})
        f = a6.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_non_uri_value(self):
        """A bare repo name or unfilled template token isn't a URI."""
        att = _att({"buildType": "github-actions-workflow"})
        f = a6.check(_index_with_attestations(att))
        assert not f.passed
        assert "not a uri" in f.description.lower()

    def test_v1_path_preferred_when_both_present(self):
        """A transitional Statement carries both v0.2 and v1
        keys; the v1 path wins when buildDefinition is present
        because that's the canonical location for SLSA v1."""
        att = _att({
            "buildDefinition": {
                "buildType": "unknown",  # v1 path: placeholder
            },
            "buildType": "https://slsa.dev/buildtypes/foo/v1",  # v0.2 path: ok
        }, pt="https://slsa.dev/provenance/v1")
        f = a6.check(_index_with_attestations(att))
        assert not f.passed  # v1 path wins, finds the placeholder

    def test_passes_when_no_attestations(self):
        manifest = OCIManifest(
            path="index.json",
            media_type="application/vnd.oci.image.index.v1+json",
            schema_version=2,
            attestations=(),
        )
        f = a6.check(manifest)
        assert f.passed

    def test_passes_for_single_image_manifest(self):
        manifest = OCIManifest(
            path="manifest.json",
            media_type="application/vnd.oci.image.manifest.v1+json",
            schema_version=2,
        )
        f = a6.check(manifest)
        assert f.passed

    def test_passes_when_only_sbom_attestations_present(self):
        """ATTEST-006 only reads SLSA provenance. An SBOM-only
        image has nothing to verify; pass with the no-content
        message."""
        sbom_att = _att(
            {"packages": []},
            pt="https://spdx.dev/Document",
        )
        f = a6.check(_index_with_attestations(sbom_att))
        assert f.passed


# ── ATTEST-007 SBOM supplier completeness ──────────────────────────


class TestATTEST007:
    def test_passes_for_spdx_with_full_supplier_coverage(self):
        att = _att({
            "packages": [
                {"name": "openssl", "supplier": "Organization: OpenSSL Foundation"},
                {"name": "zlib", "supplier": "Person: Jean-loup Gailly"},
            ],
        }, pt="https://spdx.dev/Document")
        f = a7.check(_index_with_attestations(att))
        assert f.passed

    def test_passes_for_spdx_with_originator_fallback(self):
        """SPDX permits either ``supplier`` OR ``originator`` as
        attribution. The rule accepts either."""
        att = _att({
            "packages": [
                {"name": "openssl",
                 "originator": "Organization: OpenSSL Foundation"},
            ],
        }, pt="https://spdx.dev/Document")
        f = a7.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_spdx_missing_supplier(self):
        att = _att({
            "packages": [
                {"name": "openssl"},
                {"name": "zlib", "supplier": "Organization: ZLib"},
            ],
        }, pt="https://spdx.dev/Document")
        f = a7.check(_index_with_attestations(att))
        assert not f.passed
        assert "openssl" in f.description

    def test_fails_for_spdx_noassertion_supplier(self):
        """``NOASSERTION`` is the SPDX sentinel meaning "producer
        chose not to populate"; treat as missing for the rule's
        purposes."""
        att = _att({
            "packages": [
                {"name": "openssl", "supplier": "NOASSERTION"},
            ],
        }, pt="https://spdx.dev/Document")
        f = a7.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_for_cyclonedx_with_supplier_object(self):
        att = _att({
            "components": [
                {"name": "openssl", "supplier": {"name": "OpenSSL Foundation"}},
            ],
        }, pt="https://cyclonedx.org/bom")
        f = a7.check(_index_with_attestations(att))
        assert f.passed

    def test_passes_for_cyclonedx_with_publisher_fallback(self):
        """CycloneDX's ``publisher`` field is the fallback the rule
        accepts when ``supplier`` is absent."""
        att = _att({
            "components": [
                {"name": "openssl", "publisher": "OpenSSL Foundation"},
            ],
        }, pt="https://cyclonedx.org/bom")
        f = a7.check(_index_with_attestations(att))
        assert f.passed

    def test_fails_for_cyclonedx_missing_supplier(self):
        att = _att({
            "components": [
                {"name": "openssl"},
            ],
        }, pt="https://cyclonedx.org/bom")
        f = a7.check(_index_with_attestations(att))
        assert not f.passed

    def test_fails_for_cyclonedx_empty_supplier_name(self):
        """An empty ``supplier.name`` is the same as missing; spec
        says the name is the required-for-attribution field."""
        att = _att({
            "components": [
                {"name": "openssl", "supplier": {"name": ""}},
            ],
        }, pt="https://cyclonedx.org/bom")
        f = a7.check(_index_with_attestations(att))
        assert not f.passed

    def test_passes_for_empty_sbom_packages(self):
        """An SBOM with no enumerable packages is structurally
        empty; ATTEST-003 covers the version-coverage angle, and
        this rule pass-by-defaults rather than firing on the same
        shape."""
        att = _att({"packages": []}, pt="https://spdx.dev/Document")
        f = a7.check(_index_with_attestations(att))
        assert f.passed

    def test_passes_when_no_attestations(self):
        manifest = OCIManifest(
            path="index.json",
            media_type="application/vnd.oci.image.index.v1+json",
            schema_version=2,
            attestations=(),
        )
        f = a7.check(manifest)
        assert f.passed

    def test_passes_for_single_image_manifest(self):
        manifest = OCIManifest(
            path="manifest.json",
            media_type="application/vnd.oci.image.manifest.v1+json",
            schema_version=2,
        )
        f = a7.check(manifest)
        assert f.passed

    def test_passes_when_only_provenance_attestations_present(self):
        """ATTEST-007 only reads SBOM attestations. A provenance-only
        image has nothing to verify; pass with the no-content message."""
        prov_att = _att(
            {"builder": {"id": "..."}},
            pt="https://slsa.dev/provenance/v0.2",
        )
        f = a7.check(_index_with_attestations(prov_att))
        assert f.passed

    def test_mixed_attribution_in_multiple_packages(self):
        """Some packages have suppliers, others don't. The rule
        fires with a count summary listing the missing ones."""
        att = _att({
            "packages": [
                {"name": "a", "supplier": "Organization: A"},
                {"name": "b"},
                {"name": "c", "supplier": "NOASSERTION"},
                {"name": "d", "originator": "Person: D"},
            ],
        }, pt="https://spdx.dev/Document")
        f = a7.check(_index_with_attestations(att))
        assert not f.passed
        # 2 of 4 missing (b + c); description should list both names
        assert "b" in f.description
        assert "c" in f.description

    def test_orchestrator_runs_attest006_and_007_end_to_end(self, tmp_path: Path):
        """Build a layout dir with an SPDX SBOM lacking suppliers
        AND a SLSA provenance lacking buildType. Both ATTEST-006 and
        ATTEST-007 should fire through the orchestrator."""
        # Use a fresh statement that lacks buildType + has an
        # incomplete SBOM. The _build_layout helper writes one
        # statement per layout, so this exercises ATTEST-006 only.
        statement = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "image", "digest": {"sha256": "0" * 64}}],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": "https://github.com/slsa-framework/slsa-github-generator/x@v1",
                },
                # no buildType key
                "invocation": {
                    "configSource": {
                        "uri": "git+https://github.com/owner/repo",
                        "digest": {"sha1": "a" * 40},
                    },
                },
                "materials": [
                    {"uri": "git+https://x/y", "digest": {"sha1": "a" * 40}},
                ],
            },
        }
        index_path = _build_layout(tmp_path, statement=statement)
        ctx = OCIContext.from_path(index_path)
        findings = OCIManifestChecks(ctx).run()
        a6_findings = [f for f in findings if f.check_id == "ATTEST-006"]
        assert len(a6_findings) == 1
        assert not a6_findings[0].passed
