"""Per-rule tests for GitLab cross-project artifact, cache, and
provenance rules:
GL-010 (multi-project pipeline ingests upstream artifact unverified),
GL-012 (cache key derives from MR-controlled CI variable),
GL-024 (no SLSA provenance attestation produced).

GL-010 closes the upstream-pipeline-poisoning gap that
``needs: { project }`` opens when the producing project accepts MR
pipelines. GL-012 is the GitLab-specific cache poisoning vector.
GL-024 covers the SLSA Build-L3 attestation that GL-006 (signing)
doesn't satisfy on its own.
"""
from __future__ import annotations

from .conftest import run_check

# ── GL-010 cross-project artifact verification ──────────────────────


class TestGL010MultiProjectArtifact:
    def test_fails_when_artifact_pulled_without_verify(self):
        cfg = """
        stages: [run]
        run_job:
          stage: run
          image: alpine:3.19.1
          needs:
            - project: org/upstream
              job: build
              ref: main
              artifacts: true
          script:
            - ./run-binary.sh
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-010")
        assert not f.passed

    def test_passes_with_cosign_verify_attestation(self):
        cfg = """
        stages: [run]
        run_job:
          stage: run
          image: alpine:3.19.1
          needs:
            - project: org/upstream
              job: build
              ref: main
              artifacts: true
          script:
            - cosign verify-attestation --certificate-identity-regexp '.*' artifact.tar.gz
            - ./run-binary.sh
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-010")
        assert f.passed

    def test_passes_when_no_cross_project_needs(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-010")
        assert f.passed


# ── GL-012 cache key from MR-controlled CI var ──────────────────────


class TestGL012CacheKey:
    def test_fails_when_cache_key_uses_merge_request_var(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          cache:
            key: pip-$CI_MERGE_REQUEST_IID
            paths: [.cache/pip]
          script: [pip install -r requirements.txt]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-012")
        assert not f.passed

    def test_fails_when_cache_key_uses_commit_branch(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          cache:
            key: pip-$CI_COMMIT_BRANCH
            paths: [.cache/pip]
          script: [pip install -r requirements.txt]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-012")
        assert not f.passed

    def test_passes_with_lockfile_keyed_cache(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          cache:
            key:
              files: [requirements.txt]
            paths: [.cache/pip]
          script: [pip install --require-hashes -r requirements.txt]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-012")
        assert f.passed


# ── GL-024 SLSA provenance attestation ──────────────────────────────


class TestGL024SLSAProvenance:
    def test_fails_when_artifact_built_without_provenance(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker build -t registry.example.com/app:v1 .
            - docker push registry.example.com/app:v1
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-024")
        assert not f.passed

    def test_passes_with_cosign_attest(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker build -t registry.example.com/app:v1 .
            - cosign attest --predicate provenance.intoto.jsonl registry.example.com/app:v1
            - docker push registry.example.com/app:v1
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-024")
        assert f.passed
