"""Per-rule tests for GHA-087 (derived-value of secret printed to log).

The positive fixture is the scenario-27 workflow body from
``greylag-ci/cicd-goat`` (``scenarios/27-secret-leak-in-logs``),
specifically the derived-value half that GHA-033 deliberately
doesn't cover.
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA087SecretDerivationEcho:
    def test_fails_on_param_truncation(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  API_KEY: ${{ secrets.API_KEY }}
                run: |
                  echo "prefix: ${API_KEY:0:8}"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed
        assert "${API_KEY:0:8}" in f.description

    def test_fails_on_sha256_pipe_to_output(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "fingerprint=$(echo $TOKEN | sha256sum | cut -c1-16)" >> "$GITHUB_OUTPUT"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed
        assert "sha256sum" in f.description

    def test_fails_on_base64_wrap(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "encoded: $(echo $TOKEN | base64)"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed

    def test_fails_on_md5sum_here_string(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  printf "fp=%s\\n" "$(md5sum <<<$TOKEN)"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed

    def test_fails_on_cut_truncation(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "short: $(echo $TOKEN | cut -c1-8)"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed

    def test_fails_on_head_truncation(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "tag: $(echo $TOKEN | head -c 12)"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed

    def test_fails_on_step_summary_redirect(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "fp: ${TOKEN:0:8}" >> "$GITHUB_STEP_SUMMARY"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed

    def test_fails_on_direct_secret_context(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "fp: $(echo ${{ secrets.X }} | sha256sum)"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed

    def test_passes_on_boolean_form(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  [ -n "$TOKEN" ] && echo "set" || echo "unset"
        """
        assert run_check(wf, "GHA-087").passed

    def test_passes_on_no_secret_env(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "build sha: $(date | sha256sum)"
        """
        assert run_check(wf, "GHA-087").passed

    def test_passes_on_full_secret_print_no_transform(self):
        # ``echo $TOKEN`` (no derivation) is GHA-033's territory,
        # not GHA-087's. The two rules are deliberately disjoint.
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "$TOKEN"
        """
        assert run_check(wf, "GHA-087").passed

    def test_passes_on_transform_no_sink(self):
        # The transform happens but the result doesn't reach a
        # logged sink. ``EXPECTED=$(echo $TOKEN | sha256sum)``
        # used immediately for a comparison stays in the
        # process's variable space and isn't logged.
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  EXPECTED=$(echo "$TOKEN" | sha256sum | head -c8)
                  test "$EXPECTED" = "$EXPECTED_FROM_VAULT"
        """
        # Note: the first line has a transform on a secret but no
        # print sink (no echo/printf/tee/> at the head). The rule's
        # single-line scope is intentional, the assignment is a
        # comparison primitive, not a leak primitive.
        assert run_check(wf, "GHA-087").passed

    def test_passes_when_secret_env_name_has_partial_match(self):
        # ``$TOKEN_PATH`` (different variable from ``$TOKEN``) shouldn't
        # match the secret name ``TOKEN``.
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                  TOKEN_PATH: /etc/path
                run: |
                  echo "path: ${TOKEN_PATH:0:8}"
        """
        # TOKEN_PATH is NOT secret-bound (its value is a literal). The
        # truncation on it is harmless. The rule must not false-fire.
        assert run_check(wf, "GHA-087").passed

    def test_multiple_offenders_reported(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "prefix: ${TOKEN:0:8}"
                  echo "sha: $(echo $TOKEN | sha256sum)" >> "$GITHUB_OUTPUT"
                  echo "b64: $(echo $TOKEN | base64)"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed
        assert "3 ``run:`` line(s)" in f.description

    def test_fails_on_job_level_secret_env(self):
        # The canonical pattern: secret bound at the job level, then
        # truncated in a step's run body. Step-only secret-name lookup
        # would miss this.
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            env:
              TOKEN: ${{ secrets.DEPLOY_KEY }}
            steps:
              - run: |
                  echo "prefix: ${TOKEN:0:8}"
        """
        f = run_check(wf, "GHA-087")
        assert not f.passed
        assert "${TOKEN:0:8}" in f.description

    def test_fails_on_workflow_level_secret_env(self):
        # Same shape one level higher: ``env:`` at the workflow root.
        wf = """
        on: push
        env:
          TOKEN: ${{ secrets.DEPLOY_KEY }}
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "prefix: ${TOKEN:0:8}"
        """
        assert not run_check(wf, "GHA-087").passed

    def test_param_expansion_range_slice(self):
        # ``${VAR:2:6}`` is a midstring slice, still derives from
        # the secret. Should fire.
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TOKEN: ${{ secrets.DEPLOY_KEY }}
                run: |
                  echo "middle: ${TOKEN:2:6}"
        """
        assert not run_check(wf, "GHA-087").passed
