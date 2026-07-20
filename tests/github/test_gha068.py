"""Per-rule tests for GHA-068 (deprecated runner image)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA068DeprecatedRunner:
    def test_fails_on_ubuntu_18(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-18.04
            steps: [{run: echo}]
        """
        f = run_check(wf, "GHA-068")
        assert not f.passed
        assert "ubuntu-18.04" in f.description

    def test_fails_on_ubuntu_20(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-20.04
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-068").passed

    def test_fails_on_macos_11(self):
        wf = """
        jobs:
          build:
            runs-on: macos-11
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-068").passed

    def test_fails_on_windows_2019(self):
        wf = """
        jobs:
          build:
            runs-on: windows-2019
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-068").passed

    def test_fails_on_matrix_os_with_deprecated_value(self):
        # ``runs-on: ${{ matrix.os }}`` resolves through strategy.matrix;
        # an OS matrix is the most common way a deprecated image appears
        # (B4 FN: the matrix axis was never consulted).
        wf = """
        jobs:
          build:
            runs-on: ${{ matrix.os }}
            strategy:
              matrix:
                os: [ubuntu-latest, ubuntu-20.04]
            steps: [{run: echo}]
        """
        f = run_check(wf, "GHA-068")
        assert not f.passed
        assert "ubuntu-20.04" in f.description

    def test_fails_on_matrix_include_deprecated_value(self):
        wf = """
        jobs:
          build:
            runs-on: ${{ matrix.os }}
            strategy:
              matrix:
                os: [ubuntu-latest]
                include:
                  - os: macos-12
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-068").passed

    def test_passes_on_matrix_os_all_current(self):
        wf = """
        jobs:
          build:
            runs-on: ${{ matrix.os }}
            strategy:
              matrix:
                os: [ubuntu-latest, ubuntu-24.04, macos-14]
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-068").passed

    def test_passes_on_ubuntu_latest(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-068").passed

    def test_passes_on_ubuntu_24(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-24.04
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-068").passed

    def test_passes_on_self_hosted_list(self):
        wf = """
        jobs:
          build:
            runs-on: [self-hosted, linux, x64]
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-068").passed

    def test_passes_on_dict_runs_on_with_safe_labels(self):
        wf = """
        jobs:
          build:
            runs-on:
              group: my-group
              labels: ubuntu-latest
            steps: [{run: echo}]
        """
        assert run_check(wf, "GHA-068").passed

    def test_fails_on_dict_runs_on_with_deprecated_label(self):
        wf = """
        jobs:
          build:
            runs-on:
              group: my-group
              labels: ubuntu-18.04
            steps: [{run: echo}]
        """
        assert not run_check(wf, "GHA-068").passed

    def test_multiple_jobs_aggregated(self):
        wf = """
        jobs:
          a:
            runs-on: ubuntu-18.04
            steps: [{run: echo}]
          b:
            runs-on: windows-2019
            steps: [{run: echo}]
          c:
            runs-on: ubuntu-latest
            steps: [{run: echo}]
        """
        f = run_check(wf, "GHA-068")
        assert not f.passed
        assert "2 job(s)" in f.description
