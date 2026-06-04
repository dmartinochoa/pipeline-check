"""Tests for GHA-117 (unattended IaC apply on an untrusted PR trigger)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA117IacApplyUntrustedPr:
    def test_fails_on_pull_request_terraform_apply(self):
        wf = """
        on: pull_request
        permissions:
          id-token: write
        jobs:
          apply:
            runs-on: ubuntu-latest
            steps:
              - run: terraform init && terraform apply -auto-approve
        """
        f = run_check(wf, "GHA-117")
        assert not f.passed
        assert "pull_request" in f.description

    def test_fails_on_pull_request_target_cfn_deploy(self):
        wf = """
        on: pull_request_target
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: aws cloudformation deploy --template-file t.yml --stack-name s
        """
        f = run_check(wf, "GHA-117")
        assert not f.passed

    def test_fails_on_mapping_trigger_with_pull_request(self):
        wf = """
        on:
          push:
            branches: [main]
          pull_request:
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: pulumi up --yes
        """
        f = run_check(wf, "GHA-117")
        assert not f.passed

    def test_fails_on_pull_request_tofu_apply(self):
        # OpenTofu shares the apply sink via the same primitive.
        wf = """
        on: pull_request
        jobs:
          apply:
            runs-on: ubuntu-latest
            steps:
              - run: tofu apply -auto-approve
        """
        f = run_check(wf, "GHA-117")
        assert not f.passed

    def test_passes_on_push_apply(self):
        # apply on push (trusted) is the intended deploy path, not flagged.
        wf = """
        on: push
        jobs:
          apply:
            runs-on: ubuntu-latest
            steps:
              - run: terraform apply -auto-approve
        """
        f = run_check(wf, "GHA-117")
        assert f.passed

    def test_passes_on_pull_request_plan_only(self):
        # plan is read-only; the apply verb is what realizes state.
        wf = """
        on: pull_request
        jobs:
          plan:
            runs-on: ubuntu-latest
            steps:
              - run: terraform init && terraform plan
        """
        f = run_check(wf, "GHA-117")
        assert f.passed

    def test_passes_on_pull_request_no_iac(self):
        wf = """
        on: pull_request
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-117")
        assert f.passed
