"""Tests for GHA-102: submodule checkout on PR trigger."""
from __future__ import annotations

from .conftest import run_check


class TestGHA102:
    def test_fires_on_recursive_submodules_with_pr(self) -> None:
        wf = """
        name: build
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  submodules: recursive
              - run: npm ci
        """
        f = run_check(wf, "GHA-102")
        assert not f.passed
        assert "submodule" in f.description.lower()

    def test_fires_on_submodules_true_with_pr(self) -> None:
        wf = """
        name: build
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  submodules: true
              - run: make
        """
        f = run_check(wf, "GHA-102")
        assert not f.passed

    def test_fires_on_pull_request_target(self) -> None:
        wf = """
        name: build
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  submodules: recursive
              - run: cargo build
        """
        f = run_check(wf, "GHA-102")
        assert not f.passed

    def test_passes_on_push_trigger(self) -> None:
        wf = """
        name: build
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  submodules: recursive
              - run: npm ci
        """
        f = run_check(wf, "GHA-102")
        assert f.passed

    def test_passes_without_submodules(self) -> None:
        wf = """
        name: build
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: npm ci
        """
        f = run_check(wf, "GHA-102")
        assert f.passed

    def test_passes_with_submodules_false(self) -> None:
        wf = """
        name: build
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  submodules: false
              - run: npm ci
        """
        f = run_check(wf, "GHA-102")
        assert f.passed

    def test_fires_on_sha_pinned_checkout(self) -> None:
        wf = """
        name: build
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
                with:
                  submodules: recursive
              - run: make test
        """
        f = run_check(wf, "GHA-102")
        assert not f.passed

    def test_multiple_jobs_only_flags_offenders(self) -> None:
        wf = """
        name: build
        on: pull_request
        jobs:
          lint:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: make lint
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  submodules: recursive
              - run: make build
        """
        f = run_check(wf, "GHA-102")
        assert not f.passed
        assert "build" in f.description
