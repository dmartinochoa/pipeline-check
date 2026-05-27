"""Per-shape tests for GHA-004's overprovisioned-permissions widening.

The original ``TestGHA004Permissions`` class in ``test_workflows.py``
covers the four legacy firing conditions (missing block, write-all,
contents:write+PR, id-token without OIDC step). This module covers
the fifth condition (generalized write-scope overprovisioning) added
under issue #150.
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA004ExcessPackagesWrite:
    def test_fails_on_packages_write_without_consumer(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              packages: write
            steps:
              - uses: actions/checkout@v4
              - run: './build.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "packages: write" in f.description

    def test_passes_on_packages_write_with_docker_push_run(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              packages: write
            steps:
              - uses: actions/checkout@v4
              - run: 'docker push ghcr.io/example/image:latest'
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_on_packages_write_with_npm_publish(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          publish:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              packages: write
            steps:
              - uses: actions/checkout@v4
              - run: 'npm publish --access public'
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_on_packages_write_with_docker_build_push_action(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          publish:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              packages: write
            steps:
              - uses: actions/checkout@v4
              - uses: docker/build-push-action@v6
                with:
                  push: true
                  tags: ghcr.io/example/image:latest
        """
        assert run_check(wf, "GHA-004").passed

    def test_fails_on_docker_build_push_action_without_push(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              packages: write
            steps:
              - uses: actions/checkout@v4
              - uses: docker/build-push-action@v6
                with:
                  load: true
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "packages: write" in f.description


class TestGHA004ExcessPullRequestsWrite:
    def test_fails_without_consumer(self):
        wf = """
        on: pull_request
        permissions:
          contents: read
        jobs:
          analyze:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              pull-requests: write
            steps:
              - uses: actions/checkout@v4
              - run: './analyze.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "pull-requests: write" in f.description

    def test_passes_with_gh_pr_comment(self):
        wf = """
        on: pull_request
        permissions:
          contents: read
        jobs:
          comment:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              pull-requests: write
            steps:
              - run: 'gh pr comment "${{ github.event.number }}" --body "hi"'
                env:
                  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_with_sticky_pr_comment_action(self):
        wf = """
        on: pull_request
        permissions:
          contents: read
        jobs:
          comment:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              pull-requests: write
            steps:
              - uses: marocchino/sticky-pull-request-comment@v2
                with:
                  message: 'Lint passed.'
        """
        assert run_check(wf, "GHA-004").passed


class TestGHA004ExcessIssuesWrite:
    def test_fails_without_consumer(self):
        wf = """
        on: schedule
        permissions:
          contents: read
        jobs:
          triage:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              issues: write
            steps:
              - run: './scan.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "issues: write" in f.description

    def test_passes_with_gh_issue_create(self):
        wf = """
        on: schedule
        permissions:
          contents: read
        jobs:
          triage:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              issues: write
            steps:
              - run: 'gh issue create --title "found" --body "details"'
                env:
                  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        """
        assert run_check(wf, "GHA-004").passed


class TestGHA004ExcessSecurityEventsWrite:
    def test_fails_without_consumer(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          scan:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              security-events: write
            steps:
              - uses: actions/checkout@v4
              - run: './scan.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "security-events: write" in f.description

    def test_passes_with_codeql_upload(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          analyze:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              security-events: write
            steps:
              - uses: github/codeql-action/upload-sarif@v3
                with:
                  sarif_file: results.sarif
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_with_trivy_action(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          scan:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              security-events: write
            steps:
              - uses: aquasecurity/trivy-action@v0.20.0
                with:
                  format: sarif
                  output: trivy.sarif
        """
        assert run_check(wf, "GHA-004").passed


class TestGHA004ExcessContentsWriteNonPR:
    """``contents: write`` on a non-PR workflow with no consumer.

    The existing GHA-004 specifically flags ``contents: write`` on a
    PR-triggered workflow (the canonical foot-gun). The widening
    extends that to non-PR triggers when no consumer step exists.
    """

    def test_fails_without_consumer_on_push(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: actions/checkout@v4
              - run: './build.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "contents: write" in f.description

    def test_passes_with_git_push(self):
        wf = """
        on: schedule
        permissions:
          contents: read
        jobs:
          autobump:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: actions/checkout@v4
              - run: |
                  ./bump.sh
                  git push origin main
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_with_gh_release_create(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          release:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - run: 'gh release create v1.0.0 --notes "ok"'
                env:
                  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_with_release_drafter_action(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          draft:
            runs-on: ubuntu-latest
            permissions:
              contents: write
            steps:
              - uses: release-drafter/release-drafter@v6
        """
        assert run_check(wf, "GHA-004").passed


class TestGHA004WildcardConsumer:
    def test_github_script_suppresses_overprovisioning(self):
        # ``actions/github-script`` can mutate any scope via octokit.
        # The rule conservatively treats it as a consumer of all
        # granted scopes.
        wf = """
        on: pull_request
        permissions:
          contents: read
        jobs:
          comment:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              issues: write
              pull-requests: write
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    github.rest.issues.createComment({...})
        """
        assert run_check(wf, "GHA-004").passed


class TestGHA004ReusableWorkflowCarveOut:
    def test_caller_with_excess_scopes_does_not_fire(self):
        # Reusable-workflow callers don't carry ``steps:``. The
        # caller forward the grants to the callee, which is the
        # actual consumer. The rule must not flag the caller.
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          forward:
            permissions:
              contents: write
              issues: write
              packages: write
            uses: my-org/shared/.github/workflows/build.yml@v1
            with:
              x: 1
        """
        assert run_check(wf, "GHA-004").passed


class TestGHA004UnknownScopeStaysSilent:
    def test_attestations_write_alone_does_not_fire(self):
        # ``attestations`` doesn't have a consumer catalog yet.
        # The rule conservatively stays silent rather than guess at
        # consumers; document the gap in the rule's known_fp.
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              attestations: write
            steps:
              - uses: actions/checkout@v4
              - run: './build.sh'
        """
        # Specifically NO finding about ``attestations: write`` since
        # the rule's consumer catalog doesn't cover that scope yet.
        f = run_check(wf, "GHA-004")
        # Either passes (no other issues), or fails for unrelated
        # reasons but not for attestations: write. We assert the
        # description doesn't mention attestations.
        assert "attestations" not in f.description


class TestGHA004MultipleExcessScopes:
    def test_multiple_offenders_reported(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              packages: write
              issues: write
              security-events: write
            steps:
              - uses: actions/checkout@v4
              - run: './build.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "packages: write" in f.description
        assert "issues: write" in f.description
        assert "security-events: write" in f.description


class TestGHA004TopLevelAggregation:
    """Top-level write-scope aggregation across inheriting jobs."""

    def test_fails_top_level_packages_write_not_consumed(self):
        wf = """
        on: push
        permissions:
          contents: read
          packages: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: './build.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "top-level" in f.description
        assert "packages: write" in f.description

    def test_fails_multiple_excess_top_level_scopes(self):
        wf = """
        on: push
        permissions:
          contents: read
          packages: write
          issues: write
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: './lint.sh'
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "packages: write" in f.description
        assert "issues: write" in f.description

    def test_passes_top_level_contents_write_consumed_by_git_push(self):
        wf = """
        on: schedule
        permissions:
          contents: write
        jobs:
          autobump:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  ./bump.sh
                  git push origin main
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_top_level_packages_write_consumed_by_docker_push(self):
        wf = """
        on: push
        permissions:
          contents: read
          packages: write
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: docker/build-push-action@v6
                with:
                  push: true
                  tags: ghcr.io/example/image:latest
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_all_jobs_override_permissions(self):
        wf = """
        on: push
        permissions:
          contents: read
          packages: write
        jobs:
          build:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: actions/checkout@v4
              - run: './build.sh'
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_wildcard_consumer_suppresses(self):
        wf = """
        on: push
        permissions:
          contents: read
          packages: write
        jobs:
          script:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    // custom logic
        """
        assert run_check(wf, "GHA-004").passed

    def test_passes_one_of_two_jobs_consumes(self):
        wf = """
        on: push
        permissions:
          contents: read
          packages: write
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: './build.sh'
          publish:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: 'docker push ghcr.io/example/image:latest'
        """
        assert run_check(wf, "GHA-004").passed

    def test_skips_reusable_workflow_caller(self):
        wf = """
        on: push
        permissions:
          contents: read
          packages: write
        jobs:
          forward:
            uses: my-org/shared/.github/workflows/publish.yml@v1
            with:
              x: 1
        """
        assert run_check(wf, "GHA-004").passed


class TestGHA004ReusableCallerNote:
    """Reusable workflow callers should note unverified permissions."""

    def test_passed_finding_includes_resolve_remote_note(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          call-reusable:
            uses: org/repo/.github/workflows/reusable.yml@main
        """
        f = run_check(wf, "GHA-004")
        assert f.passed
        assert "--resolve-remote" in f.description
        assert "call-reusable" in f.description

    def test_failed_finding_includes_resolve_remote_note(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
          call-reusable:
            uses: org/repo/.github/workflows/reusable.yml@main
        """
        f = run_check(wf, "GHA-004")
        assert not f.passed
        assert "--resolve-remote" in f.description
        assert "call-reusable" in f.description

    def test_no_note_without_reusable_callers(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
        """
        f = run_check(wf, "GHA-004")
        assert f.passed
        assert "--resolve-remote" not in f.description

    def test_multiple_reusable_callers_listed(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          deploy-staging:
            uses: org/repo/.github/workflows/deploy.yml@main
          deploy-prod:
            uses: org/repo/.github/workflows/deploy.yml@main
        """
        f = run_check(wf, "GHA-004")
        assert f.passed
        assert "2 job(s)" in f.description
        assert "deploy-staging" in f.description
        assert "deploy-prod" in f.description

    def test_overflow_indicator_with_more_than_three(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          a:
            uses: org/repo/.github/workflows/a.yml@main
          b:
            uses: org/repo/.github/workflows/b.yml@main
          c:
            uses: org/repo/.github/workflows/c.yml@main
          d:
            uses: org/repo/.github/workflows/d.yml@main
        """
        f = run_check(wf, "GHA-004")
        assert f.passed
        assert "4 job(s)" in f.description
        assert "+1 more" in f.description
