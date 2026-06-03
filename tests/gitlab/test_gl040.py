"""Tests for GL-040 (CI_JOB_TOKEN cross-project / remote access)."""
from __future__ import annotations

from .conftest import run_check


class TestGL040CiJobTokenCrossProject:
    def test_fails_on_token_clone_url(self) -> None:
        f = run_check("""
        pull:
          script:
            - git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/other/proj.git
        """, "GL-040")
        assert not f.passed
        assert "CI_JOB_TOKEN" in f.description

    def test_fails_on_job_token_header(self) -> None:
        f = run_check("""
        pull:
          script:
            - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" https://gitlab.example.com/api/v4/projects/42/packages'
        """, "GL-040")
        assert not f.passed

    def test_fails_on_unbraced_token(self) -> None:
        f = run_check("""
        pull:
          before_script:
            - git clone https://gitlab-ci-token:$CI_JOB_TOKEN@gitlab.example.com/other/proj.git
        """, "GL-040")
        assert not f.passed

    def test_passes_on_deploy_token(self) -> None:
        f = run_check("""
        pull:
          script:
            - git clone https://gitlab-deploy-token:${DEPLOY_TOKEN}@gitlab.example.com/other/proj.git
        """, "GL-040")
        assert f.passed

    def test_passes_when_no_job_token(self) -> None:
        f = run_check("""
        build:
          script: [make]
        """, "GL-040")
        assert f.passed
