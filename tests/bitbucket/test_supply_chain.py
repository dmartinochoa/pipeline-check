"""Per-rule tests for the Bitbucket Pipelines supply-chain rules:
BB-006 (signing), BB-007 (SBOM), BB-013 (docker insecure flags),
BB-014 (insecure package source), BB-021 (lockfile enforcement),
BB-022 (dependency-update commands).

Mirrors the GHA / GL / CC supply-chain test matrix for the
Bitbucket provider. Note: Bitbucket's docker-insecure rule is
``BB-013`` and its package-insecure is ``BB-014``, two off from
the other providers' alignment because the BB rule numbering
diverged early in the catalog.
"""
from __future__ import annotations

from .conftest import run_check

# ── BB-006 signing ──────────────────────────────────────────────────


class TestBB006Signing:
    def test_fails_when_artifacts_produced_without_signing(self):
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
        f = run_check(cfg, "BB-006")
        assert not f.passed

    def test_passes_with_cosign_signing(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: docker:24-cli
                script:
                  - docker build -t registry.example.com/app:v1 .
                  - cosign sign --yes registry.example.com/app@sha256:abc
                  - docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "BB-006")
        assert f.passed


# ── BB-007 SBOM ─────────────────────────────────────────────────────


class TestBB007SBOM:
    def test_fails_when_artifacts_produced_without_sbom(self):
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
        f = run_check(cfg, "BB-007")
        assert not f.passed

    def test_passes_with_syft_sbom(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: docker:24-cli
                script:
                  - docker build -t registry.example.com/app:v1 .
                  - syft registry.example.com/app:v1 -o cyclonedx-json > sbom.json
                  - docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "BB-007")
        assert f.passed


# ── BB-013 docker insecure flags ────────────────────────────────────


class TestBB013DockerInsecure:
    def test_fails_on_privileged_flag(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - docker run --privileged builder make all
        """
        f = run_check(cfg, "BB-013")
        assert not f.passed

    def test_fails_on_cap_add_sys_admin(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - docker run --cap-add=SYS_ADMIN builder make all
        """
        f = run_check(cfg, "BB-013")
        assert not f.passed

    def test_passes_with_minimal_flags(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - docker run --rm -v /tmp:/work builder make all
        """
        f = run_check(cfg, "BB-013")
        assert f.passed


# ── BB-014 insecure package source ──────────────────────────────────


class TestBB014PackageInsecure:
    def test_fails_on_pip_index_url_http(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: python:3.12.1-slim
                script:
                  - pip install --index-url http://example.com/simple/ requests
        """
        f = run_check(cfg, "BB-014")
        assert not f.passed

    def test_passes_with_default_https_sources(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: python:3.12.1-slim
                script:
                  - pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "BB-014")
        assert f.passed


# ── BB-021 lockfile enforcement ─────────────────────────────────────


class TestBB021Lockfile:
    def test_fails_on_npm_install(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: node:20.10.0
                script:
                  - npm install
        """
        f = run_check(cfg, "BB-021")
        assert not f.passed

    def test_passes_on_npm_ci(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: node:20.10.0
                script:
                  - npm ci
        """
        f = run_check(cfg, "BB-021")
        assert f.passed


# ── BB-022 dependency-update commands ───────────────────────────────


class TestBB022DepUpdate:
    def test_fails_on_npm_update(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: node:20.10.0
                script:
                  - npm update
        """
        f = run_check(cfg, "BB-022")
        assert not f.passed

    def test_passes_when_no_update_command(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: python:3.12.1-slim
                script:
                  - pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "BB-022")
        assert f.passed
