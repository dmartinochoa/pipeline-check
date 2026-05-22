"""Per-rule tests for GHA-072 (overprovisioned-secrets)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA072OverprovisionedSecrets:
    def test_fails_on_job_env_with_single_consumer(self):
        wf = """
        jobs:
          ship:
            runs-on: ubuntu-latest
            env:
              DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
            steps:
              - uses: actions/checkout@v4
              - run: './test.sh'
              - run: 'curl -H "Authorization: Bearer $DEPLOY_TOKEN" https://api.example.com/deploy'
        """
        f = run_check(wf, "GHA-072")
        assert not f.passed
        assert "DEPLOY_TOKEN" in f.description

    def test_passes_on_step_scoped_env(self):
        wf = """
        jobs:
          ship:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - env:
                  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
                run: 'curl -H "Authorization: Bearer $DEPLOY_TOKEN" https://api.example.com/deploy'
        """
        assert run_check(wf, "GHA-072").passed

    def test_passes_on_job_env_with_two_consumers(self):
        wf = """
        jobs:
          ship:
            runs-on: ubuntu-latest
            env:
              DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
            steps:
              - run: 'echo length $DEPLOY_TOKEN'
              - run: 'curl -H "Bearer $DEPLOY_TOKEN" https://api.example.com'
        """
        assert run_check(wf, "GHA-072").passed

    def test_fails_on_workflow_env_single_job_consumer(self):
        wf = """
        env:
          PROD_TOKEN: ${{ secrets.PROD_TOKEN }}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: 'echo a'
          b:
            runs-on: ubuntu-latest
            steps:
              - run: 'curl -H "Bearer $PROD_TOKEN" https://api.example.com'
        """
        f = run_check(wf, "GHA-072")
        assert not f.passed
        assert "workflow.env.PROD_TOKEN" in f.description

    def test_passes_on_non_secret_job_env(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              BUILD_NUMBER: 42
            steps:
              - run: './build.sh'
        """
        assert run_check(wf, "GHA-072").passed

    def test_passes_on_zero_consumers_when_no_secret(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: 'echo unrelated'
        """
        assert run_check(wf, "GHA-072").passed

    def test_step_re_binding_counts_as_consumer(self):
        # A step that re-binds the same env var on its own env: is
        # treated as a consumer (explicit forwarding pattern).
        wf = """
        jobs:
          ship:
            runs-on: ubuntu-latest
            env:
              DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
            steps:
              - env:
                  DEPLOY_TOKEN: ${{ env.DEPLOY_TOKEN }}
                run: './deploy.sh'
              - run: 'curl -H "Bearer $DEPLOY_TOKEN" https://api.example.com'
        """
        # Two consumers: the explicit-forward step and the curl step.
        assert run_check(wf, "GHA-072").passed

    def test_with_block_reference_counts_as_consumer(self):
        # A step's ``with:`` parameter referencing $TOKEN counts.
        wf = """
        jobs:
          ship:
            runs-on: ubuntu-latest
            env:
              DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
            steps:
              - uses: actions/some-action@v1
                with:
                  token: $DEPLOY_TOKEN
              - run: 'curl -H "Bearer $DEPLOY_TOKEN" https://api.example.com'
        """
        assert run_check(wf, "GHA-072").passed

    def test_partial_name_not_matched(self):
        # ``$DEPLOY_TOKEN_PATH`` (different var) shouldn't match
        # ``DEPLOY_TOKEN``.
        wf = """
        jobs:
          ship:
            runs-on: ubuntu-latest
            env:
              DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
            steps:
              - run: 'echo $DEPLOY_TOKEN_PATH'
        """
        f = run_check(wf, "GHA-072")
        # Zero consumers of DEPLOY_TOKEN.
        assert not f.passed
