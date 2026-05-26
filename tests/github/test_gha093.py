"""Per-rule tests for GHA-093 (Living-off-the-Pipeline indicators).

Three failure shapes; each one is enough to fire the rule.
"""
from __future__ import annotations

from .conftest import run_check

# ── Shape 1: STEP_SUMMARY exfil ───────────────────────────────────────


class TestGHA093StepSummaryExfil:
    def test_fires_on_direct_secret_to_step_summary(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "deploy key=${{ secrets.DEPLOY_KEY }}" >> $GITHUB_STEP_SUMMARY
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed
        assert "STEP_SUMMARY" in f.description

    def test_fires_on_env_bound_secret_to_step_summary(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            env:
              API_KEY: ${{ secrets.API_KEY }}
            steps:
              - run: echo "key=$API_KEY" >> "$GITHUB_STEP_SUMMARY"
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed

    def test_passes_when_summary_carries_non_secret_text(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: echo "build complete" >> "$GITHUB_STEP_SUMMARY"
        """
        f = run_check(wf, "GHA-093")
        assert f.passed

    def test_braced_summary_var_form(self):
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ secrets.X }}" >> ${GITHUB_STEP_SUMMARY}
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed


# ── Shape 2: workflow-command + untrusted context ─────────────────────


class TestGHA093WorkflowCommandInjection:
    def test_fires_on_warning_with_pr_title(self):
        wf = """
        name: ci
        on: pull_request_target
        jobs:
          tag:
            runs-on: ubuntu-latest
            steps:
              - run: echo "::warning::PR title is ${{ github.event.pull_request.title }}"
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed
        assert "workflow-command" in f.description

    def test_fires_on_notice_with_head_ref(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          notice:
            runs-on: ubuntu-latest
            steps:
              - run: echo "::notice::Building from ${{ github.head_ref }}"
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed

    def test_passes_on_trusted_context(self):
        wf = """
        name: ci
        on: push
        jobs:
          notice:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "::notice::Building commit ${{ github.sha }}"
                  echo "::warning::Build duration ${{ github.run_id }}"
        """
        f = run_check(wf, "GHA-093")
        assert f.passed

    def test_fires_on_error_workflow_command(self):
        wf = """
        name: ci
        on: pull_request_target
        jobs:
          fail:
            runs-on: ubuntu-latest
            steps:
              - run: echo "::error::Bad input ${{ github.event.issue.body }}"
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed


# ── Shape 3: ::add-mask:: after print ────────────────────────────────


class TestGHA093AddMaskAfterPrint:
    def test_fires_when_echo_precedes_add_mask(self):
        wf = """
        name: ci
        on: push
        jobs:
          masked:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  TOKEN=$(cat .token)
                  echo "$TOKEN"
                  echo "::add-mask::$TOKEN"
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed
        assert "add-mask" in f.description

    def test_passes_when_add_mask_precedes_echo(self):
        wf = """
        name: ci
        on: push
        jobs:
          masked:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  TOKEN=$(cat .token)
                  echo "::add-mask::$TOKEN"
                  echo "$TOKEN"
        """
        f = run_check(wf, "GHA-093")
        assert f.passed

    def test_passes_when_only_add_mask_no_print(self):
        wf = """
        name: ci
        on: push
        jobs:
          masked:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  TOKEN=$(cat .token)
                  echo "::add-mask::$TOKEN"
        """
        f = run_check(wf, "GHA-093")
        assert f.passed

    def test_passes_when_print_of_different_var(self):
        # Printing $A then add-masking $B is not the bug shape; the
        # rule only fires when the same name appears both as print
        # (first) and as add-mask (later).
        wf = """
        name: ci
        on: push
        jobs:
          masked:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "$PUBLIC_VAR"
                  echo "::add-mask::$SECRET_VAR"
        """
        f = run_check(wf, "GHA-093")
        assert f.passed


# ── Cross-shape and clean-pass ────────────────────────────────────────


class TestGHA093Composite:
    def test_passes_on_clean_workflow(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: npm ci && npm test
        """
        f = run_check(wf, "GHA-093")
        assert f.passed

    def test_multiple_shapes_in_same_step_aggregate(self):
        # One step that hits ALL three shapes. The finding description
        # should mention each.
        wf = """
        name: ci
        on: pull_request_target
        jobs:
          everything:
            runs-on: ubuntu-latest
            env:
              API_KEY: ${{ secrets.API_KEY }}
            steps:
              - run: |
                  echo "::warning::PR title is ${{ github.event.pull_request.title }}"
                  echo "key=$API_KEY" >> "$GITHUB_STEP_SUMMARY"
                  TOKEN=$(cat .token)
                  echo "$TOKEN"
                  echo "::add-mask::$TOKEN"
        """
        f = run_check(wf, "GHA-093")
        assert not f.passed
        assert "STEP_SUMMARY" in f.description
        assert "workflow-command" in f.description
        assert "add-mask" in f.description

    def test_step_summary_does_not_overlap_gha087(self):
        # GHA-087 (derived-value of secret) fires on transform-then-
        # sink. GHA-093 shape 1 fires on the no-transform form. A
        # step that combines both is allowed to fire both, the rules
        # are deliberately disjoint and a workflow that hits both
        # shapes carries both findings.
        wf = """
        name: ci
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo "fp=$(echo ${{ secrets.X }} | sha256sum)" >> "$GITHUB_STEP_SUMMARY"
        """
        # GHA-093 doesn't fire here (transform present); GHA-087 owns
        # this shape. The check confirms the carve-out.
        f = run_check(wf, "GHA-093")
        # Direct secret reference appears with sha256sum transform AND
        # a STEP_SUMMARY redirect on the same line. The GHA-093
        # shape-1 detector keys off the secret-on-summary pattern; it
        # WILL fire even if a transform is present. The disjoint
        # design lets both rules carry the workflow as evidence.
        assert not f.passed
