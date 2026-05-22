"""Per-rule tests for GHA-066 (upload-artifact wildcard path)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA066UploadArtifactWildcard:
    def test_fails_on_dot_path(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/upload-artifact@v4
                with:
                  name: debug
                  path: .
        """
        f = run_check(wf, "GHA-066")
        assert not f.passed
        assert "'.'" in f.description

    def test_fails_on_double_star_glob(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: bundle
                  path: '**/*'
        """
        assert not run_check(wf, "GHA-066").passed

    def test_fails_on_workspace_expression(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: ws
                  path: ${{ github.workspace }}
        """
        assert not run_check(wf, "GHA-066").passed

    def test_fails_on_workspace_with_glob(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: ws
                  path: ${{ github.workspace }}/**
        """
        assert not run_check(wf, "GHA-066").passed

    def test_passes_on_scoped_subdir(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: dist
                  path: dist/
        """
        assert run_check(wf, "GHA-066").passed

    def test_passes_on_multi_line_scoped(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: bundle
                  path: |
                    dist/
                    coverage.xml
                    LICENSE
        """
        assert run_check(wf, "GHA-066").passed

    def test_fails_on_multi_line_with_wildcard(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: bundle
                  path: |
                    dist/
                    **/*
        """
        assert not run_check(wf, "GHA-066").passed

    def test_passes_on_non_upload_action(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/setup-node@v4
                with:
                  node-version: 20
              - run: ls .
        """
        assert run_check(wf, "GHA-066").passed

    def test_matches_versioned_path(self):
        # actions/upload-artifact@v3, @v4 both fire on the same shape.
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v3
                with:
                  name: x
                  path: '**/*'
        """
        assert not run_check(wf, "GHA-066").passed

    def test_passes_when_no_path_value(self):
        # Missing path is its own bug (the action defaults to ``.``
        # in some versions) but the rule only fires on values it
        # can read literally. The default behavior is covered by
        # the action's own warnings.
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/upload-artifact@v4
                with:
                  name: x
        """
        # Stay silent rather than guess at action defaults.
        assert run_check(wf, "GHA-066").passed
