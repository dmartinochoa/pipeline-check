"""Per-rule tests for GitHub Actions workflow-safety rules:
GHA-010 (local action on untrusted-trigger workflow),
GHA-025 (reusable workflow not pinned to commit SHA),
GHA-030 (OIDC role assumption without environment protection),
GHA-033 (secret echoed to log).

These rules govern *what* the workflow trusts: the action source,
the reusable-workflow source, the OIDC role gating, and whether
secrets leak into the build log. They sit between GHA-001 (step
action pinning) and GHA-002 (PR-context script injection) in the
"who controls the executable code" hierarchy.
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-010 local action on untrusted trigger ───────────────────────


class TestGHA010LocalAction:
    def test_fails_when_local_action_used_on_pr_target(self):
        wf = """
        name: ci
        on: pull_request_target
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - uses: ./.github/actions/build
        """
        f = run_check(wf, "GHA-010")
        assert not f.passed

    def test_passes_when_local_action_only_on_safe_trigger(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332
              - uses: ./.github/actions/build
        """
        f = run_check(wf, "GHA-010")
        assert f.passed

    def test_passes_when_no_local_action_used(self):
        wf = """
        name: ci
        on: pull_request_target
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: echo "lint only"
        """
        f = run_check(wf, "GHA-010")
        assert f.passed


# ── GHA-025 reusable workflow pinning ───────────────────────────────


class TestGHA025ReusableWorkflowPin:
    def test_fails_on_tag_pinned_reusable_workflow(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          release:
            uses: org/shared/.github/workflows/release.yml@v1
        """
        f = run_check(wf, "GHA-025")
        assert not f.passed

    def test_fails_on_branch_pinned_reusable_workflow(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          release:
            uses: org/shared/.github/workflows/release.yml@main
        """
        f = run_check(wf, "GHA-025")
        assert not f.passed

    def test_passes_on_sha_pinned_reusable_workflow(self):
        wf = """
        name: release
        on: push
        permissions: { contents: read }
        jobs:
          release:
            uses: org/shared/.github/workflows/release.yml@aabbccddeeff00112233445566778899aabbccdd
        """
        f = run_check(wf, "GHA-025")
        assert f.passed

    def test_passes_when_no_reusable_workflow_referenced(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make
        """
        f = run_check(wf, "GHA-025")
        assert f.passed


# ── GHA-030 OIDC trust without environment ──────────────────────────


class TestGHA030OIDCTrust:
    def test_fails_when_aws_oidc_login_lacks_environment(self):
        wf = """
        name: deploy
        on: push
        permissions:
          contents: read
          id-token: write
        jobs:
          deploy:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - uses: aws-actions/configure-aws-credentials@b47578312673ae6fa5b630027ce67a78e1d1f937
                with:
                  role-to-assume: arn:aws:iam::1:role/deploy
                  aws-region: us-east-1
              - run: aws s3 ls
        """
        f = run_check(wf, "GHA-030")
        assert not f.passed

    def test_passes_when_oidc_login_uses_environment(self):
        wf = """
        name: deploy
        on: push
        permissions:
          contents: read
          id-token: write
        jobs:
          deploy:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            environment: production
            steps:
              - uses: aws-actions/configure-aws-credentials@b47578312673ae6fa5b630027ce67a78e1d1f937
                with:
                  role-to-assume: arn:aws:iam::1:role/deploy
                  aws-region: us-east-1
              - run: aws s3 ls
        """
        f = run_check(wf, "GHA-030")
        assert f.passed

    def test_passes_when_no_oidc_credential_step(self):
        wf = """
        name: ci
        on: push
        permissions: { contents: read }
        jobs:
          build:
            runs-on: ubuntu-latest
            timeout-minutes: 30
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-030")
        assert f.passed
