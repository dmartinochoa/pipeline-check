"""Per-rule tests for GHA-105 (self-hosted runner on an untrusted PR trigger)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA105SelfHostedUntrustedTrigger:
    def test_fails_on_pull_request_self_hosted_string(self):
        wf = """
        on: pull_request
        jobs:
          test:
            runs-on: self-hosted
            steps: [{run: make test}]
        """
        f = run_check(wf, "GHA-105")
        assert not f.passed
        assert "test" in f.job_anchors

    def test_fails_on_pull_request_self_hosted_list(self):
        wf = """
        on:
          pull_request:
            branches: [main]
        jobs:
          build:
            runs-on: [self-hosted, linux, x64]
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-105").passed

    def test_fails_on_pull_request_target_self_hosted(self):
        wf = """
        on: pull_request_target
        jobs:
          build:
            runs-on: self-hosted
            steps: [{run: echo}]
        """
        f = run_check(wf, "GHA-105")
        assert not f.passed
        assert "pull_request_target" in f.description

    def test_fails_on_runner_group_dict(self):
        # A ``group:`` selector is always a self-hosted runner group.
        wf = """
        on: pull_request
        jobs:
          deploy:
            runs-on:
              group: prod-fleet
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-105").passed

    def test_fails_on_dict_labels_self_hosted(self):
        wf = """
        on: pull_request
        jobs:
          build:
            runs-on:
              labels: [self-hosted, gpu]
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-105").passed

    def test_passes_on_push_trigger(self):
        # push is a trusted-ref trigger, not fork-reachable.
        wf = """
        on: push
        jobs:
          build:
            runs-on: self-hosted
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-105").passed

    def test_passes_on_workflow_dispatch(self):
        wf = """
        on: workflow_dispatch
        jobs:
          build:
            runs-on: [self-hosted, linux]
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-105").passed

    def test_passes_on_pull_request_hosted_runner(self):
        wf = """
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-105").passed

    def test_passes_on_dict_labels_hosted_no_group(self):
        wf = """
        on: pull_request
        jobs:
          build:
            runs-on:
              labels: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-105").passed

    def test_multiple_self_hosted_jobs_aggregated(self):
        wf = """
        on: pull_request
        jobs:
          a:
            runs-on: self-hosted
            steps: [{run: echo}]
          b:
            runs-on: [self-hosted, arm64]
            steps: [{run: echo}]
          c:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        f = run_check(wf, "GHA-105")
        assert not f.passed
        assert "2 job(s)" in f.description
        assert set(f.job_anchors) == {"a", "b"}
