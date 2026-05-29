"""Per-rule tests for GHA-109 (harden-runner is not the first step)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA109HardenRunnerNotFirst:
    def test_fails_when_step_after_checkout(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: block
              - run: make build
        """
        f = run_check(wf, "GHA-109")
        assert not f.passed
        assert "build" in f.description

    def test_fails_when_step_after_run(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: curl -fsSL https://example.test/install.sh | bash
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: block
        """
        f = run_check(wf, "GHA-109")
        assert not f.passed

    def test_passes_when_first_step(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: block
              - uses: actions/checkout@v4
              - run: make build
        """
        f = run_check(wf, "GHA-109")
        assert f.passed

    def test_passes_when_no_harden_runner(self):
        wf = """
        name: ci
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: make build
        """
        f = run_check(wf, "GHA-109")
        assert f.passed

    def test_fails_on_one_of_several_jobs(self):
        wf = """
        name: ci
        on: push
        jobs:
          good:
            runs-on: ubuntu-latest
            steps:
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: block
              - run: make build
          bad:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: step-security/harden-runner@v2
                with:
                  egress-policy: block
              - run: make test
        """
        f = run_check(wf, "GHA-109")
        assert not f.passed
        assert "bad" in f.description
        assert "good" not in f.description
