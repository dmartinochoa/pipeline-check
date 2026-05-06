"""Per-rule tests for Bitbucket Pipelines cache, provenance, and
package-integrity rules:
BB-018 (cache key derives from attacker-controllable input),
BB-024 (no SLSA provenance attestation produced),
BB-027 (package install from git URL / local path / tarball URL).

BB-018 closes the cache-poisoning gap that Bitbucket's PR-controlled
``$BITBUCKET_BRANCH`` and friends open in the cache namespace.
BB-024 covers the SLSA Build-L3 attestation requirement BB-006
(signing) doesn't satisfy on its own. BB-027 closes the registry-
bypass paths that BB-021's lockfile flag alone can't catch.
"""
from __future__ import annotations

from .conftest import run_check

# ── BB-018 cache key from attacker-controlled input ─────────────────


class TestBB018CacheKey:
    def test_fails_when_named_cache_path_uses_branch(self):
        # Bitbucket's "custom cache" string form: the value of a
        # ``definitions.caches.<name>`` mapping is a literal path. The
        # rule fires when that path interpolates a PR-controllable var.
        cfg = """
        definitions:
          caches:
            poisoned: ~/.cache/pip-$BITBUCKET_BRANCH
        pipelines:
          default:
            - step:
                max-time: 30
                caches: [poisoned]
                script:
                  - pip install -r requirements.txt
        """
        f = run_check(cfg, "BB-018")
        assert not f.passed

    def test_fails_when_inline_cache_includes_branch(self):
        # Step-level inline string cache form. Same taint check.
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                caches:
                  - $BITBUCKET_TAG/.gradle
                script: [./gradlew build]
        """
        f = run_check(cfg, "BB-018")
        assert not f.passed

    def test_passes_when_cache_path_is_static(self):
        cfg = """
        definitions:
          caches:
            pip: ~/.cache/pip
        pipelines:
          default:
            - step:
                max-time: 30
                caches: [pip]
                script:
                  - pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "BB-018")
        assert f.passed

    def test_passes_when_no_custom_cache_defined(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script: [make build]
        """
        f = run_check(cfg, "BB-018")
        assert f.passed


# ── BB-024 SLSA provenance attestation ──────────────────────────────


class TestBB024SLSAProvenance:
    def test_fails_when_artifact_built_without_provenance(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: docker:24-cli
                script:
                  - docker build -t registry.example.com/app:v1 .
                  - docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "BB-024")
        assert not f.passed

    def test_passes_with_cosign_attest(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: docker:24-cli
                script:
                  - docker build -t registry.example.com/app:v1 .
                  - cosign attest --predicate provenance.intoto.jsonl registry.example.com/app:v1
                  - docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "BB-024")
        assert f.passed

    def test_passes_with_witness_run(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: docker:24-cli
                script:
                  - witness run --step build -- docker build -t registry.example.com/app:v1 .
                  - docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "BB-024")
        assert f.passed


# ── BB-027 package source integrity ────────────────────────────────


class TestBB027PackageSourceIntegrity:
    def test_fails_on_pip_install_git_url(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: python:3.12.1-slim
                script:
                  - pip install git+https://github.com/example/tool.git
        """
        f = run_check(cfg, "BB-027")
        assert not f.passed

    def test_passes_with_lockfile_install(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: python:3.12.1-slim
                script:
                  - pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "BB-027")
        assert f.passed
