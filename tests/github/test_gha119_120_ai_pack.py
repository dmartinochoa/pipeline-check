"""Per-rule tests for the AI/LLM-pipeline pack:
GHA-119 (untrusted context reaches an agentic CLI prompt -> injection),
GHA-120 (ML model loaded with trust_remote_code -> code execution).
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA119PromptInjection:
    def test_fails_on_direct_untrusted_in_agent_prompt(self):
        wf = """
        on: pull_request_target
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: claude -p "${{ github.event.pull_request.body }}"
        """
        assert run_check(wf, "GHA-119").passed is False

    def test_fails_on_env_routed_untrusted_referenced_by_agent(self):
        # Env routing does NOT sanitize an LLM prompt the way it does a
        # shell command -- the model still ingests the value.
        wf = """
        on: issue_comment
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR: ${{ github.event.comment.body }}
                run: aider --message "$PR"
        """
        assert run_check(wf, "GHA-119").passed is False

    def test_passes_on_fixed_prompt(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: claude -p "summarize the diff"
        """
        assert run_check(wf, "GHA-119").passed is True

    def test_passes_when_untrusted_but_no_agent_cli(self):
        # GHA-003's territory (shell), not GHA-119's (agent prompt).
        wf = """
        on: pull_request_target
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.title }}"
        """
        assert run_check(wf, "GHA-119").passed is True

    def test_passes_when_tainted_env_not_referenced(self):
        wf = """
        on: issue_comment
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - env:
                  PR: ${{ github.event.comment.body }}
                run: cursor-agent -p "fixed prompt"
        """
        assert run_check(wf, "GHA-119").passed is True


class TestGHA120TrustRemoteCode:
    def test_fails_on_trust_remote_code_true(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "AutoModel.from_pretrained('x', trust_remote_code=True)"
        """
        assert run_check(wf, "GHA-120").passed is False

    def test_fails_on_cli_trust_remote_code_flag(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: text-generation-launcher --model m --trust-remote-code
        """
        assert run_check(wf, "GHA-120").passed is False

    def test_passes_on_clean_training_run(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python train.py --model bert
        """
        assert run_check(wf, "GHA-120").passed is True

    def test_passes_on_trust_remote_code_false(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "AutoModel.from_pretrained('x', trust_remote_code=False)"
        """
        assert run_check(wf, "GHA-120").passed is True
