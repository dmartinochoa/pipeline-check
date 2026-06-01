"""Per-rule tests for GHA-111 (AI agent + IaC apply in one job)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA111AIAgentIaCApply:
    def test_fails_agent_and_apply_same_step(self):
        wf = """
        on: {pull_request_target: null}
        jobs:
          iac:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  claude -p "update the terraform for this PR"
                  terraform apply -auto-approve
        """
        f = run_check(wf, "GHA-111")
        assert not f.passed
        assert "iac" in f.job_anchors

    def test_fails_agent_then_cfn_deploy_separate_steps(self):
        wf = """
        on: push
        jobs:
          a:
            steps:
              - run: aider --message "refresh the stack"
              - run: aws cloudformation deploy --template-file t.yml --stack-name s
        """
        assert not run_check(wf, "GHA-111").passed

    def test_fails_pulumi_up(self):
        wf = """
        on: push
        jobs:
          a:
            steps:
              - run: gemini generate
              - run: pulumi up --yes
        """
        assert not run_check(wf, "GHA-111").passed

    def test_passes_split_across_jobs(self):
        # Agent in one job, apply in another: not co-located.
        wf = """
        on: push
        jobs:
          propose:
            steps: [{run: "claude -p draft"}]
          apply:
            steps: [{run: "terraform apply -auto-approve"}]
        """
        assert run_check(wf, "GHA-111").passed

    def test_passes_agent_only(self):
        wf = """
        on: push
        jobs:
          a:
            steps: [{run: "claude -p summarize"}]
        """
        assert run_check(wf, "GHA-111").passed

    def test_passes_apply_only(self):
        wf = """
        on: push
        jobs:
          a:
            steps: [{run: "terraform apply -auto-approve"}]
        """
        assert run_check(wf, "GHA-111").passed

    def test_passes_read_only_plan(self):
        # ``terraform plan`` is read-only; not an apply.
        wf = """
        on: push
        jobs:
          a:
            steps:
              - run: |
                  claude -p "review the plan"
                  terraform plan
        """
        assert run_check(wf, "GHA-111").passed

    def test_passes_echoed_agent_name(self):
        # Agent name only echoed, not a real invocation.
        wf = """
        on: push
        jobs:
          a:
            steps:
              - run: |
                  echo "claude -p x"
                  terraform apply -auto-approve
        """
        assert run_check(wf, "GHA-111").passed

    def test_multiple_jobs_aggregated(self):
        wf = """
        on: push
        jobs:
          a:
            steps:
              - run: |
                  claude -p x
                  cdk deploy
          b:
            steps: [{run: "make build"}]
          c:
            steps:
              - run: goose run
              - run: terragrunt apply
        """
        f = run_check(wf, "GHA-111")
        assert not f.passed
        assert set(f.job_anchors) == {"a", "c"}
