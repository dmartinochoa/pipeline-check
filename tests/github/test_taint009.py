"""Tests for TAINT-009: environment-secret flow bypasses protection rules."""
from __future__ import annotations

from .conftest import run_check


class TestTAINT009:
    def test_fires_on_secret_output_to_unprotected_job(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          mint:
            runs-on: ubuntu-latest
            environment: production
            outputs:
              token: ${{ steps.get.outputs.token }}
            steps:
              - id: get
                run: echo "token=${{ secrets.DEPLOY_TOKEN }}" >> "$GITHUB_OUTPUT"
          deploy:
            needs: mint
            runs-on: ubuntu-latest
            steps:
              - run: >-
                  curl -H "Authorization: ${{ needs.mint.outputs.token }}"
                  https://example.com
        """
        f = run_check(wf, "TAINT-009")
        assert not f.passed
        assert "deploy" in f.description.lower()
        assert "mint" in f.description.lower()

    def test_passes_when_consumer_has_environment(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          mint:
            runs-on: ubuntu-latest
            environment: production
            outputs:
              token: ${{ steps.get.outputs.token }}
            steps:
              - id: get
                run: echo "token=${{ secrets.DEPLOY_TOKEN }}" >> "$GITHUB_OUTPUT"
          deploy:
            needs: mint
            environment: production
            runs-on: ubuntu-latest
            steps:
              - run: >-
                  curl -H "Authorization: ${{ needs.mint.outputs.token }}"
                  https://example.com
        """
        f = run_check(wf, "TAINT-009")
        assert f.passed

    def test_passes_when_no_environment_job(self) -> None:
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            outputs:
              result: ${{ steps.b.outputs.result }}
            steps:
              - id: b
                run: echo "result=ok" >> "$GITHUB_OUTPUT"
          test:
            needs: build
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ needs.build.outputs.result }}
        """
        f = run_check(wf, "TAINT-009")
        assert f.passed

    def test_passes_when_outputs_carry_no_secrets(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          prepare:
            runs-on: ubuntu-latest
            environment: staging
            outputs:
              version: ${{ steps.v.outputs.version }}
            steps:
              - id: v
                run: echo "version=1.2.3" >> "$GITHUB_OUTPUT"
          deploy:
            needs: prepare
            runs-on: ubuntu-latest
            steps:
              - run: echo deploying ${{ needs.prepare.outputs.version }}
        """
        f = run_check(wf, "TAINT-009")
        assert f.passed

    def test_fires_on_direct_secret_in_output_expression(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          auth:
            runs-on: ubuntu-latest
            environment: production
            outputs:
              key: ${{ secrets.API_KEY }}
            steps:
              - run: echo "placeholder"
          use:
            needs: auth
            runs-on: ubuntu-latest
            steps:
              - run: >-
                  curl -H "X-Key: ${{ needs.auth.outputs.key }}"
                  https://api.example.com
        """
        f = run_check(wf, "TAINT-009")
        assert not f.passed

    def test_fires_on_secret_via_env_indirection(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          mint:
            runs-on: ubuntu-latest
            environment: production
            outputs:
              cred: ${{ steps.get.outputs.cred }}
            steps:
              - id: get
                env:
                  SECRET_VAL: ${{ secrets.PROD_CRED }}
                run: echo "cred=$SECRET_VAL" >> "$GITHUB_OUTPUT"
          consume:
            needs: mint
            runs-on: ubuntu-latest
            steps:
              - run: ./deploy --cred ${{ needs.mint.outputs.cred }}
        """
        f = run_check(wf, "TAINT-009")
        assert not f.passed

    def test_does_not_flag_unrelated_consumer(self) -> None:
        wf = """
        name: deploy
        on: push
        jobs:
          mint:
            runs-on: ubuntu-latest
            environment: production
            outputs:
              token: ${{ steps.get.outputs.token }}
            steps:
              - id: get
                run: echo "token=${{ secrets.DEPLOY_TOKEN }}" >> "$GITHUB_OUTPUT"
          unrelated:
            runs-on: ubuntu-latest
            steps:
              - run: echo "hello"
        """
        f = run_check(wf, "TAINT-009")
        assert f.passed
