"""Tests for GHA-099: deploy env plaintext secret."""
from __future__ import annotations

from .conftest import run_check


class TestGHA099:
    def test_fires_on_plaintext_aws_key_in_deploy(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          deploy-prod:
            runs-on: ubuntu-latest
            environment: production
            env:
              AWS_ACCESS_KEY_ID: AKIAI44QH8DHBEXAMPLE
            steps:
              - run: aws ecs update-service --force-new-deployment
        """
        f = run_check(wf, "GHA-099")
        assert not f.passed
        assert "credential" in f.description.lower() or "plaintext" in f.description.lower()

    def test_passes_with_secrets_reference(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          deploy-prod:
            runs-on: ubuntu-latest
            environment: production
            env:
              AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
            steps:
              - run: aws ecs update-service --force-new-deployment
        """
        f = run_check(wf, "GHA-099")
        assert f.passed

    def test_passes_when_no_deploy_job(self) -> None:
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-099")
        assert f.passed

    def test_fires_on_step_level_env(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          deploy-prod:
            runs-on: ubuntu-latest
            environment: production
            steps:
              - run: aws s3 sync . s3://bucket
                env:
                  AWS_ACCESS_KEY_ID: AKIAI44QH8DHBEXAMPLE
        """
        f = run_check(wf, "GHA-099")
        assert not f.passed
