"""Unit tests for the three new Cloud Build rules added in v0.4.0.

GCB-016 dir path escape, GCB-017 build provenance, GCB-018 legacy
KMS-encrypted secrets block. Each rule's ``check(path, doc)`` is
called directly with hand-built dicts so the failure modes are
visible per rule rather than smeared across the fixture-level
contract.
"""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb016_dir_path_escape as r16,
)
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb017_build_provenance as r17,
)
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb018_legacy_secrets_block as r18,
)


def _doc(**fields: Any) -> dict[str, Any]:
    return dict(fields)


# ── GCB-016 ──────────────────────────────────────────────────────────


class TestGCB016DirPathEscape:
    def test_fails_on_dotdot_segment(self):
        f = r16.check("cb.yaml", _doc(steps=[{"id": "build", "dir": "../shared"}]))
        assert not f.passed
        assert "build" in f.description

    def test_fails_on_dotdot_in_middle(self):
        f = r16.check("cb.yaml", _doc(steps=[{"dir": "src/../etc"}]))
        assert not f.passed

    def test_passes_on_relative_subpath(self):
        f = r16.check("cb.yaml", _doc(steps=[{"dir": "src/app"}]))
        assert f.passed

    def test_passes_on_absolute_workspace_path(self):
        f = r16.check("cb.yaml", _doc(steps=[{"dir": "/workspace/sub"}]))
        assert f.passed

    def test_passes_on_dot_only(self):
        # ``./`` is current-dir, not parent-dir; not a path escape.
        f = r16.check("cb.yaml", _doc(steps=[{"dir": "./sub"}]))
        assert f.passed

    def test_passes_when_dir_unset(self):
        f = r16.check("cb.yaml", _doc(steps=[{"name": "x"}]))
        assert f.passed

    def test_passes_when_no_steps(self):
        f = r16.check("cb.yaml", _doc())
        assert f.passed

    def test_handles_backslash_separators(self):
        # Path normalization should treat ``..\foo`` as a parent escape.
        f = r16.check("cb.yaml", _doc(steps=[{"dir": "..\\shared"}]))
        assert not f.passed


# ── GCB-017 ──────────────────────────────────────────────────────────


class TestGCB017BuildProvenance:
    def test_fails_when_images_present_but_verify_option_unset(self):
        doc = _doc(
            steps=[{"name": "x"}],
            images=["gcr.io/p/app:v1"],
        )
        f = r17.check("cb.yaml", doc)
        assert not f.passed
        assert "VERIFIED" in f.recommendation or "VERIFIED" in f.description

    def test_passes_when_images_present_and_verified(self):
        doc = _doc(
            steps=[{"name": "x"}],
            images=["gcr.io/p/app:v1"],
            options={"requestedVerifyOption": "VERIFIED"},
        )
        f = r17.check("cb.yaml", doc)
        assert f.passed

    def test_silent_pass_when_no_image_produced(self):
        # Build runs lint/tests, no image push.
        doc = _doc(steps=[{"name": "lint"}])
        f = r17.check("cb.yaml", doc)
        assert f.passed
        assert "not applicable" in f.description

    def test_fails_when_docker_push_step_present_without_verify(self):
        # Image production is implied by a ``docker push`` step even
        # without a top-level ``images:`` block.
        doc = _doc(steps=[
            {"name": "gcr.io/cloud-builders/docker",
             "args": ["push", "gcr.io/p/app:v1"]},
        ])
        f = r17.check("cb.yaml", doc)
        assert not f.passed

    def test_verify_option_case_insensitive(self):
        doc = _doc(
            images=["gcr.io/p/app:v1"],
            options={"requestedVerifyOption": "verified"},
        )
        f = r17.check("cb.yaml", doc)
        assert f.passed


# ── GCB-018 ──────────────────────────────────────────────────────────


class TestGCB018LegacySecretsBlock:
    def test_fails_when_legacy_secrets_block_present(self):
        doc = _doc(secrets=[{
            "kmsKeyName": "projects/p/locations/global/keyRings/k/cryptoKeys/c",
            "secretEnv": {"TOKEN": "CiQA..."},
        }])
        f = r18.check("cb.yaml", doc)
        assert not f.passed
        assert "Secret Manager" in f.recommendation

    def test_passes_when_only_available_secrets_present(self):
        doc = _doc(availableSecrets={
            "secretManager": [
                {"versionName": "projects/p/secrets/s/versions/3", "env": "TOKEN"},
            ],
        })
        f = r18.check("cb.yaml", doc)
        assert f.passed

    def test_fails_when_both_present_during_migration(self):
        # Documented FP scenario: mid-migration, both blocks coexist.
        # The rule still fires on the legacy one.
        doc = _doc(
            secrets=[{"kmsKeyName": "k", "secretEnv": {"TOKEN": "x"}}],
            availableSecrets={"secretManager": [
                {"versionName": "v", "env": "T"},
            ]},
        )
        f = r18.check("cb.yaml", doc)
        assert not f.passed

    def test_passes_when_no_secret_blocks_at_all(self):
        f = r18.check("cb.yaml", _doc(steps=[]))
        assert f.passed

    def test_passes_when_secrets_block_empty(self):
        # Empty ``secrets: []`` is benign — nothing is actually
        # encrypted into the YAML.
        f = r18.check("cb.yaml", _doc(secrets=[]))
        assert f.passed
