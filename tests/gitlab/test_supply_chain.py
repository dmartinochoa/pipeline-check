"""Per-rule tests for the GitLab supply-chain rules:
GL-006 (signing), GL-007 (SBOM), GL-017 (docker insecure flags),
GL-018 (insecure package source), GL-021 (lockfile enforcement),
GL-022 (dependency-update commands).

Mirrors ``tests/github/test_supply_chain.py`` for the GitLab provider.
The cross-provider rule numbers are deliberately aligned so the
shared `_primitives.shell_eval`, `_primitives.remote_script_exec`,
and lockfile primitives stay in sync across the YAML providers.
"""
from __future__ import annotations

from .conftest import run_check

# ── GL-006 signing ──────────────────────────────────────────────────


class TestGL006Signing:
    def test_fails_when_artifacts_produced_without_signing(self):
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
        f = run_check(cfg, "GL-006")
        assert not f.passed

    def test_passes_with_cosign_signing(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker build -t registry.example.com/app:v1 .
            - cosign sign --yes registry.example.com/app@sha256:abc
            - docker push registry.example.com/app:v1
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-006")
        assert f.passed

    def test_silent_pass_when_no_artifacts_produced(self):
        cfg = """
        stages: [test]
        lint_job:
          stage: test
          image: python:3.12.1-slim
          script:
            - ruff check .
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-006")
        assert f.passed


# ── GL-007 SBOM ─────────────────────────────────────────────────────


class TestGL007SBOM:
    def test_fails_when_artifacts_produced_without_sbom(self):
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
        f = run_check(cfg, "GL-007")
        assert not f.passed

    def test_passes_with_trivy_sbom(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker build -t registry.example.com/app:v1 .
            - trivy image --format cyclonedx --output sbom.json registry.example.com/app:v1
            - docker push registry.example.com/app:v1
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-007")
        assert f.passed


# ── GL-017 docker insecure flags ────────────────────────────────────


class TestGL017DockerInsecure:
    def test_fails_on_privileged_flag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker run --privileged builder make all
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-017")
        assert not f.passed

    def test_fails_on_cap_add_sys_admin(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker run --cap-add=SYS_ADMIN builder make all
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-017")
        assert not f.passed

    def test_passes_with_minimal_flags(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: docker:24-cli
          script:
            - docker run --rm -v $CI_PROJECT_DIR:/work builder make all
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-017")
        assert f.passed


# ── GL-018 insecure package source ──────────────────────────────────


class TestGL018PackageInsecure:
    def test_fails_on_pip_index_url_http(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script:
            - pip install --index-url http://example.com/simple/ requests
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-018")
        assert not f.passed

    def test_fails_on_npm_registry_http(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: node:20.10.0
          script:
            - npm install --registry http://internal.example.com/
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-018")
        assert not f.passed

    def test_passes_with_default_https_sources(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script:
            - pip install --require-hashes -r requirements.txt
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-018")
        assert f.passed


# ── GL-021 lockfile enforcement ─────────────────────────────────────


class TestGL021Lockfile:
    def test_fails_on_npm_install(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: node:20.10.0
          script:
            - npm install
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-021")
        assert not f.passed

    def test_passes_on_npm_ci(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: node:20.10.0
          script:
            - npm ci
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-021")
        assert f.passed


# ── GL-022 dependency-update commands ───────────────────────────────


class TestGL022DepUpdate:
    def test_fails_on_npm_update(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: node:20.10.0
          script:
            - npm update
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-022")
        assert not f.passed

    def test_passes_when_no_update_command(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script:
            - pip install --require-hashes -r requirements.txt
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-022")
        assert f.passed
