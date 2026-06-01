"""Per-rule tests for GHA-112 (self-hosted deploy job, no environment gate)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA112SelfHostedDeployGate:
    def test_fails_self_hosted_deploy_command_no_env(self):
        wf = """
        on: {push: {branches: [main]}}
        jobs:
          deploy:
            runs-on: [self-hosted, linux, prod]
            steps:
              - run: kubectl apply -f k8s/
        """
        f = run_check(wf, "GHA-112")
        assert not f.passed
        assert "deploy" in f.job_anchors

    def test_fails_self_hosted_deploy_by_name(self):
        wf = """
        on: push
        jobs:
          release:
            runs-on: self-hosted
            steps: [{run: "make ship"}]
        """
        assert not run_check(wf, "GHA-112").passed

    def test_fails_runs_on_dict_labels_form(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on:
              group: prod-pool
              labels: [self-hosted, deploy]
            steps: [{run: "helm upgrade app ./chart"}]
        """
        assert not run_check(wf, "GHA-112").passed

    def test_passes_self_hosted_deploy_with_environment(self):
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: [self-hosted, prod]
            environment: production
            steps: [{run: "kubectl apply -f k8s/"}]
        """
        assert run_check(wf, "GHA-112").passed

    def test_passes_github_hosted_deploy(self):
        # GitHub-hosted ungated deploy is GHA-014's domain, not GHA-112's.
        wf = """
        on: push
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps: [{run: "kubectl apply -f k8s/"}]
        """
        assert run_check(wf, "GHA-112").passed

    def test_passes_self_hosted_non_deploy(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: self-hosted
            steps: [{run: "make build"}]
        """
        assert run_check(wf, "GHA-112").passed

    def test_passes_self_hosted_deploy_against_local_mock(self):
        # terraform apply against LocalStack isn't a real deploy.
        wf = """
        on: push
        jobs:
          itest:
            runs-on: self-hosted
            env: {AWS_ENDPOINT_URL: "http://localhost:4566"}
            steps: [{run: "terraform apply -auto-approve"}]
        """
        assert run_check(wf, "GHA-112").passed

    def test_multiple_jobs_aggregated(self):
        wf = """
        on: push
        jobs:
          deploy-prod:
            runs-on: [self-hosted, prod]
            steps: [{run: "kubectl apply -f k8s/"}]
          build:
            runs-on: self-hosted
            steps: [{run: "make build"}]
          gated:
            runs-on: self-hosted
            environment: production
            steps: [{run: "terraform apply"}]
        """
        f = run_check(wf, "GHA-112")
        assert not f.passed
        assert set(f.job_anchors) == {"deploy-prod"}
