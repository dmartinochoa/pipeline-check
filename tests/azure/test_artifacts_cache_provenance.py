"""Per-rule tests for Azure DevOps artifact, cache, and provenance rules:
ADO-010 (cross-pipeline download unverified),
ADO-012 (Cache@2 key derives from $(System.PullRequest.*)),
ADO-024 (no SLSA provenance attestation produced).

ADO-010 closes the upstream-pipeline-poisoning gap that ``download:``
opens when the producing pipeline accepts PR validation. ADO-012
covers the Azure-specific cache poisoning vector. ADO-024 is the
SLSA Build-L3 attestation requirement that ADO-006 (signing) doesn't
satisfy on its own.
"""
from __future__ import annotations

from .conftest import run_check

# ── ADO-010 cross-pipeline download verification ────────────────────


class TestADO010CrossPipelineDownload:
    def test_fails_when_download_lacks_verification(self):
        cfg = """
        resources:
          pipelines:
            - pipeline: upstream
              source: build-pipeline
        pool: {vmImage: ubuntu-latest}
        steps:
          - download: upstream
            artifact: build-output
          - script: ./run-binary.sh
        """
        f = run_check(cfg, "ADO-010")
        assert not f.passed

    def test_passes_with_cosign_verify_attestation(self):
        cfg = """
        resources:
          pipelines:
            - pipeline: upstream
              source: build-pipeline
        pool: {vmImage: ubuntu-latest}
        steps:
          - download: upstream
            artifact: build-output
          - script: cosign verify-attestation --certificate-identity-regexp '.*' artifact.tar.gz
          - script: ./run-binary.sh
        """
        f = run_check(cfg, "ADO-010")
        assert f.passed

    def test_passes_when_no_cross_pipeline_download(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: make test
        """
        f = run_check(cfg, "ADO-010")
        assert f.passed


# ── ADO-012 Cache@2 PR-tainted key ──────────────────────────────────


class TestADO012CachePullRequestKey:
    def test_fails_when_cache_key_uses_pull_request_id(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - task: Cache@2
            inputs:
              key: 'pip | "$(Agent.OS)" | "$(System.PullRequest.PullRequestId)"'
              path: $(Pipeline.Workspace)/.cache/pip
        """
        f = run_check(cfg, "ADO-012")
        assert not f.passed

    def test_fails_when_cache_key_uses_source_branch(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - task: Cache@2
            inputs:
              key: 'pip | "$(Agent.OS)" | "$(Build.SourceBranchName)"'
              path: $(Pipeline.Workspace)/.cache/pip
        """
        f = run_check(cfg, "ADO-012")
        assert not f.passed

    def test_passes_with_lockfile_hash_only_key(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - task: Cache@2
            inputs:
              key: 'pip | "$(Agent.OS)" | requirements.txt'
              path: $(Pipeline.Workspace)/.cache/pip
        """
        f = run_check(cfg, "ADO-012")
        assert f.passed

    def test_passes_when_no_cache_task(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: make test
        """
        f = run_check(cfg, "ADO-012")
        assert f.passed


# ── ADO-024 SLSA provenance attestation ─────────────────────────────


class TestADO024SLSAProvenance:
    def test_fails_when_artifact_built_without_provenance(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-024")
        assert not f.passed

    def test_passes_with_cosign_attest(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: cosign attest --yes --predicate=provenance.json registry.example.com/app:v1
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-024")
        assert f.passed
