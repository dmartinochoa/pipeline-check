"""Per-rule tests for the AI/LLM-pipeline pack:
GHA-119 (untrusted context reaches an agentic CLI prompt -> injection),
GHA-120 (ML model loaded with trust_remote_code -> code execution),
GHA-121 (model pulled from a mutable / unpinned registry ref),
GHA-122 (unsafe deserialization of a fetched artifact -> pickle RCE).
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


class TestGHA121ModelPinning:
    def test_fails_on_unpinned_from_pretrained(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "AutoModel.from_pretrained('acme/sentiment')"
        """
        assert run_check(wf, "GHA-121").passed is False

    def test_fails_on_unpinned_hf_cli_download(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: huggingface-cli download acme/model
        """
        assert run_check(wf, "GHA-121").passed is False

    def test_passes_when_revision_pinned(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  python -c "AutoModel.from_pretrained('acme/sentiment', \\
                      revision='a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2')"
        """
        assert run_check(wf, "GHA-121").passed is True

    def test_passes_on_canonical_single_segment_name(self):
        # No org/ namespace -> first-party canonical hub model, out of scope.
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "AutoModel.from_pretrained('bert-base-uncased')"
        """
        assert run_check(wf, "GHA-121").passed is True

    def test_passes_on_local_path(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "AutoModel.from_pretrained('./checkpoints/final')"
        """
        assert run_check(wf, "GHA-121").passed is True

    def test_passes_on_non_model_step(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: pip install -r requirements.txt && pytest -q
        """
        assert run_check(wf, "GHA-121").passed is True


class TestGHA122UnsafeDeserialization:
    def test_fails_on_explicit_weights_only_false(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "import torch; torch.load('m.pt', weights_only=False)"
        """
        assert run_check(wf, "GHA-122").passed is False

    def test_fails_on_allow_pickle_true(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "import numpy; numpy.load('a.npy', allow_pickle=True)"
        """
        assert run_check(wf, "GHA-122").passed is False

    def test_fails_on_fetch_then_unpickle(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -o m.pkl https://example.com/m.pkl
                  python -c "import pickle; pickle.load(open('m.pkl','rb'))"
        """
        assert run_check(wf, "GHA-122").passed is False

    def test_passes_on_safe_weights_only_true(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -o m.pt https://example.com/m.pt
                  python -c "import torch; torch.load('m.pt', weights_only=True)"
        """
        assert run_check(wf, "GHA-122").passed is True

    def test_passes_on_safetensors(self):
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  huggingface-cli download acme/m model.safetensors
                  python -c "from safetensors.torch import load_file; load_file('model.safetensors')"
        """
        assert run_check(wf, "GHA-122").passed is True

    def test_passes_on_local_load_without_fetch(self):
        # Loading a self-produced local checkpoint, no remote fetch: not GHA-122.
        wf = """
        on: push
        jobs:
          b:
            runs-on: ubuntu-latest
            steps:
              - run: python -c "import torch; torch.load('ckpt.pt')"
        """
        assert run_check(wf, "GHA-122").passed is True
