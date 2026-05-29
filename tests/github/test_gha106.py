"""Per-rule tests for GHA-106 (AI agent CLI with a write-scoped token)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA106AIAgentWriteToken:
    def test_fails_on_workflow_contents_write(self):
        wf = """
        on: {issues: {types: [opened]}}
        permissions:
          contents: write
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps: [{run: "claude -p summarize"}]
        """
        f = run_check(wf, "GHA-106")
        assert not f.passed
        assert "triage" in f.job_anchors

    def test_fails_on_write_all_string(self):
        wf = """
        on: push
        permissions: write-all
        jobs:
          a:
            runs-on: ubuntu-latest
            steps: [{run: "aider --message go"}]
        """
        assert not run_check(wf, "GHA-106").passed

    def test_fails_on_packages_write(self):
        wf = """
        on: push
        permissions:
          packages: write
        jobs:
          a:
            steps: [{run: "gemini generate"}]
        """
        assert not run_check(wf, "GHA-106").passed

    def test_job_permissions_override_workflow_read(self):
        # Job-level write overrides a read-only workflow block.
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          a:
            permissions:
              contents: write
            steps: [{run: "claude -p x"}]
        """
        assert not run_check(wf, "GHA-106").passed

    def test_job_read_overrides_workflow_write(self):
        # Job-level read-only overrides a permissive workflow block.
        wf = """
        on: push
        permissions: write-all
        jobs:
          a:
            permissions:
              contents: read
            steps: [{run: "claude -p x"}]
        """
        assert run_check(wf, "GHA-106").passed

    def test_passes_on_contents_read(self):
        wf = """
        on: push
        permissions:
          contents: read
        jobs:
          a:
            steps: [{run: "claude -p x"}]
        """
        assert run_check(wf, "GHA-106").passed

    def test_passes_on_low_impact_write_scope(self):
        # pull-requests: write (comment/label bot) is not flagged.
        wf = """
        on: push
        permissions:
          pull-requests: write
        jobs:
          a:
            steps: [{run: "claude -p x"}]
        """
        assert run_check(wf, "GHA-106").passed

    def test_passes_when_no_permissions_block(self):
        # Absent block is GHA-004's domain, not this rule's.
        wf = """
        on: push
        jobs:
          a:
            steps: [{run: "claude -p x"}]
        """
        assert run_check(wf, "GHA-106").passed

    def test_passes_when_write_but_no_agent(self):
        wf = """
        on: push
        permissions: write-all
        jobs:
          a:
            steps: [{run: "make build"}]
        """
        assert run_check(wf, "GHA-106").passed

    def test_multiple_agent_jobs_aggregated(self):
        wf = """
        on: push
        permissions:
          contents: write
        jobs:
          a:
            steps: [{run: "claude -p x"}]
          b:
            steps: [{run: "goose run"}]
          c:
            steps: [{run: "make build"}]
        """
        f = run_check(wf, "GHA-106")
        assert not f.passed
        assert set(f.job_anchors) == {"a", "b"}
