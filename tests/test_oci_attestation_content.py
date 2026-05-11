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
