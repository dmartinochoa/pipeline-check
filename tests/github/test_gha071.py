"""Per-rule tests for GHA-071 (powershell on non-Windows runner)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA071PowershellOnUnix:
    def test_fails_on_step_level_pwsh_ubuntu(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - shell: pwsh
                run: Write-Output hi
        """
        f = run_check(wf, "GHA-071")
        assert not f.passed
        assert "pwsh" in f.description

    def test_fails_on_step_level_powershell_macos(self):
        wf = """
        jobs:
          build:
            runs-on: macos-14
            steps:
              - shell: powershell
                run: Write-Output hi
        """
        assert not run_check(wf, "GHA-071").passed

    def test_fails_on_job_defaults(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            defaults:
              run:
                shell: pwsh
            steps:
              - run: Write-Output hi
        """
        f = run_check(wf, "GHA-071")
        assert not f.passed
        assert "job defaults" in f.description

    def test_fails_on_workflow_defaults(self):
        wf = """
        defaults:
          run:
            shell: pwsh
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: Write-Output hi
        """
        f = run_check(wf, "GHA-071")
        assert not f.passed
        assert "workflow defaults" in f.description

    def test_passes_on_windows_runner(self):
        wf = """
        jobs:
          build:
            runs-on: windows-latest
            steps:
              - shell: pwsh
                run: Write-Output hi
        """
        assert run_check(wf, "GHA-071").passed

    def test_passes_when_bash_default(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo hi
        """
        assert run_check(wf, "GHA-071").passed

    def test_passes_when_uses_only_step(self):
        # uses: actions/setup-node doesn't pick a shell.
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            defaults:
              run:
                shell: pwsh
            steps:
              - uses: actions/setup-node@v4
                with:
                  node-version: 20
        """
        # The step has no ``run:`` body, so the rule doesn't fire
        # on this job (no powershell-on-linux execution risk).
        assert run_check(wf, "GHA-071").passed

    def test_step_shell_overrides_default(self):
        # Workflow defaults to pwsh, but the step pins bash. The job
        # has no offending run-step.
        wf = """
        defaults:
          run:
            shell: pwsh
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - shell: bash
                run: echo hi
        """
        assert run_check(wf, "GHA-071").passed

    def test_self_hosted_label_list_skipped(self):
        # Self-hosted-style label lists can't be classified as Linux
        # vs Windows from the labels alone. The rule conservatively
        # stays silent rather than guess.
        wf = """
        jobs:
          build:
            runs-on: [self-hosted, linux, x64]
            steps:
              - shell: pwsh
                run: Write-Output hi
        """
        assert run_check(wf, "GHA-071").passed
