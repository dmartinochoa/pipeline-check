"""Per-rule tests for the CircleCI supply-chain rules:
CC-006 (signing), CC-007 (SBOM), CC-017 (docker insecure flags),
CC-018 (insecure package source), CC-021 (lockfile enforcement),
CC-022 (dependency-update commands).

Mirrors the GHA / GL versions of the same supply-chain test
matrix. Cross-provider rule numbers are deliberately aligned so
the shared lockfile and signing primitives stay in sync.
"""
from __future__ import annotations

from .conftest import run_check

# ── CC-006 signing ──────────────────────────────────────────────────


class TestCC006Signing:
    def test_fails_when_artifacts_produced_without_signing(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - checkout
              - run:
                  name: build-and-push
                  no_output_timeout: 30m
                  command: |
                    docker build -t registry.example.com/app:v1 .
                    docker push registry.example.com/app:v1
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-006")
        assert not f.passed

    def test_passes_with_cosign_signing(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - checkout
              - run:
                  name: build-sign-push
                  no_output_timeout: 30m
                  command: |
                    docker build -t registry.example.com/app:v1 .
                    cosign sign --yes registry.example.com/app@sha256:abc
                    docker push registry.example.com/app:v1
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-006")
        assert f.passed


# ── CC-007 SBOM ─────────────────────────────────────────────────────


class TestCC007SBOM:
    def test_fails_when_artifacts_produced_without_sbom(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - checkout
              - run:
                  name: build-push
                  no_output_timeout: 30m
                  command: |
                    docker build -t registry.example.com/app:v1 .
                    docker push registry.example.com/app:v1
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-007")
        assert not f.passed

    def test_passes_with_syft_sbom(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - checkout
              - run:
                  name: build-sbom-push
                  no_output_timeout: 30m
                  command: |
                    docker build -t registry.example.com/app:v1 .
                    syft registry.example.com/app:v1 -o cyclonedx-json > sbom.json
                    docker push registry.example.com/app:v1
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-007")
        assert f.passed


# ── CC-017 docker insecure flags ────────────────────────────────────


class TestCC017DockerInsecure:
    def test_fails_on_privileged_flag(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: docker run --privileged builder make all
        """
        f = run_check(cfg, "CC-017")
        assert not f.passed

    def test_fails_on_cap_add_sys_admin(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: docker run --cap-add=SYS_ADMIN builder make all
        """
        f = run_check(cfg, "CC-017")
        assert not f.passed

    def test_passes_with_minimal_flags(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  no_output_timeout: 30m
                  command: docker run --rm -v /tmp:/work builder make all
        """
        f = run_check(cfg, "CC-017")
        assert f.passed


# ── CC-018 insecure package source ──────────────────────────────────


class TestCC018PackageInsecure:
    def test_fails_on_pip_index_url_http(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/python@sha256:0000000000000000000000000000000000000000000000000000000000000002
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pip install --index-url http://example.com/simple/ requests
        """
        f = run_check(cfg, "CC-018")
        assert not f.passed

    def test_passes_with_default_https_sources(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/python@sha256:0000000000000000000000000000000000000000000000000000000000000002
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "CC-018")
        assert f.passed


# ── CC-021 lockfile enforcement ─────────────────────────────────────


class TestCC021Lockfile:
    def test_fails_on_npm_install(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/node@sha256:0000000000000000000000000000000000000000000000000000000000000003
            steps:
              - run:
                  no_output_timeout: 30m
                  command: npm install
        """
        f = run_check(cfg, "CC-021")
        assert not f.passed

    def test_passes_on_npm_ci(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/node@sha256:0000000000000000000000000000000000000000000000000000000000000003
            steps:
              - run:
                  no_output_timeout: 30m
                  command: npm ci
        """
        f = run_check(cfg, "CC-021")
        assert f.passed


# ── CC-022 dependency-update commands ───────────────────────────────


class TestCC022DepUpdate:
    def test_fails_on_npm_update(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/node@sha256:0000000000000000000000000000000000000000000000000000000000000003
            steps:
              - run:
                  no_output_timeout: 30m
                  command: npm update
        """
        f = run_check(cfg, "CC-022")
        assert not f.passed

    def test_passes_when_no_update_command(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/python@sha256:0000000000000000000000000000000000000000000000000000000000000002
            steps:
              - run:
                  no_output_timeout: 30m
                  command: pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "CC-022")
        assert f.passed
