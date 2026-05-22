"""Per-rule tests for GHA-067 (cache-sensitive-files)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA067CacheSensitivePaths:
    def test_fails_on_quoted_home(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: '~'
                  key: home-key
        """
        f = run_check(wf, "GHA-067")
        assert not f.passed
        assert "~" in f.description

    def test_fails_on_home_with_slash(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/
                  key: k
        """
        assert not run_check(wf, "GHA-067").passed

    def test_fails_on_dollar_home(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: $HOME
                  key: k
        """
        assert not run_check(wf, "GHA-067").passed

    def test_fails_on_npmrc(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.npmrc
                  key: k
        """
        assert not run_check(wf, "GHA-067").passed

    def test_fails_on_aws_credentials(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.aws
                  key: k
        """
        assert not run_check(wf, "GHA-067").passed

    def test_fails_on_docker_config(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.docker
                  key: k
        """
        assert not run_check(wf, "GHA-067").passed

    def test_fails_on_gradle_properties(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.gradle/gradle.properties
                  key: k
        """
        assert not run_check(wf, "GHA-067").passed

    def test_fails_on_list_with_sensitive_entry(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: |
                    ~/.cache/pip
                    ~/.docker
                  key: k
        """
        f = run_check(wf, "GHA-067")
        assert not f.passed
        assert "~/.docker" in f.description

    def test_passes_on_npm_metadata(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.npm
                  key: k
        """
        assert run_check(wf, "GHA-067").passed

    def test_passes_on_pip_cache(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.cache/pip
                  key: k
        """
        assert run_check(wf, "GHA-067").passed

    def test_passes_on_cargo_registry(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cache@v4
                with:
                  path: ~/.cargo/registry
                  key: k
        """
        assert run_check(wf, "GHA-067").passed

    def test_passes_on_non_cache_step(self):
        wf = """
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo ~/.npmrc
        """
        assert run_check(wf, "GHA-067").passed
