"""Per-rule tests for CircleCI cache, provenance, and package-integrity:
CC-024 (no SLSA provenance attestation produced),
CC-025 (cache key derives from attacker-controllable input),
CC-028 (package install from git URL / local path / tarball URL).

CC-024 covers the SLSA Build-L3 attestation requirement that CC-006
(signing) doesn't satisfy on its own. CC-025 closes the cache-
poisoning gap that CircleCI's ``CIRCLE_BRANCH`` / ``CIRCLE_PR_*``
context vars open. CC-028 closes the registry-bypass package
sources that CC-021 (lockfile flag) alone can't cover.
"""
from __future__ import annotations

from .conftest import run_check

_PINNED_IMG = "cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001"


# ── CC-024 SLSA provenance attestation ──────────────────────────────


class TestCC024SLSAProvenance:
    def test_fails_when_artifact_built_without_provenance(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - run:
                  no_output_timeout: 30m
                  command: |
                    docker build -t registry.example.com/app:v1 .
                    docker push registry.example.com/app:v1
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-024")
        assert not f.passed

    def test_passes_with_cosign_attest(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - run:
                  no_output_timeout: 30m
                  command: |
                    docker build -t registry.example.com/app:v1 .
                    cosign attest --predicate provenance.intoto.jsonl registry.example.com/app:v1
                    docker push registry.example.com/app:v1
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-024")
        assert f.passed


# ── CC-025 cache key from attacker-controlled input ─────────────────


class TestCC025CacheKey:
    def test_fails_when_save_cache_key_uses_circle_branch(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - save_cache:
                  key: pip-{{{{ .Branch }}}}
                  paths:
                    - ~/.cache/pip
        """
        f = run_check(cfg, "CC-025")
        assert not f.passed

    def test_fails_when_restore_cache_uses_circle_pr_number(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - restore_cache:
                  keys:
                    - 'pip-${{CIRCLE_PR_NUMBER}}'
                    - pip-
        """
        f = run_check(cfg, "CC-025")
        assert not f.passed

    def test_passes_with_lockfile_checksum_key(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - save_cache:
                  key: pip-{{{{ checksum "requirements.txt" }}}}
                  paths:
                    - ~/.cache/pip
        """
        f = run_check(cfg, "CC-025")
        assert f.passed


# ── CC-028 package source integrity ────────────────────────────────


class TestCC028PackageSourceIntegrity:
    def test_fails_on_pip_install_git_url(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pip install git+https://github.com/example/tool.git
        """
        f = run_check(cfg, "CC-028")
        assert not f.passed

    def test_passes_with_lockfile_install(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "CC-028")
        assert f.passed
