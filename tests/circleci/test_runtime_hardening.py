"""Per-rule tests for CC-015 (no_output_timeout), CC-016 (curl-pipe),
CC-017 (Docker insecure), CC-023 (TLS bypass).

These four rules cover the everyday hardening that a typical
CircleCI config should observe: bound runtime, verify what you
download, don't disable Docker security flags, don't bypass TLS.
"""
from __future__ import annotations

from .conftest import run_check


# ── CC-015 no_output_timeout ─────────────────────────────────────────


class TestCC015NoOutputTimeout:
    def test_fails_when_run_step_has_no_timeout(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  name: long
                  command: ./long-build.sh
        """
        f = run_check(cfg, "CC-015")
        assert not f.passed

    def test_passes_with_step_level_timeout(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run:
                  name: long
                  no_output_timeout: 30m
                  command: ./long-build.sh
        """
        f = run_check(cfg, "CC-015")
        assert f.passed


# ── CC-016 curl-pipe ─────────────────────────────────────────────────


class TestCC016CurlPipe:
    def test_fails_when_run_pipes_curl_to_bash(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run: curl -fsSL https://example.com/install.sh | bash
        """
        f = run_check(cfg, "CC-016")
        assert not f.passed

    def test_fails_when_run_pipes_wget_to_sh(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run: wget -O - https://example.com/install.sh | sh
        """
        f = run_check(cfg, "CC-016")
        assert not f.passed

    def test_passes_when_install_uses_checksum_verify(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run: |
                  curl -fsSL https://example.com/install.sh -o install.sh
                  sha256sum -c install.sh.sha256
                  bash install.sh
        """
        f = run_check(cfg, "CC-016")
        assert f.passed


# ── CC-023 TLS bypass ────────────────────────────────────────────────


class TestCC023TLSBypass:
    def test_fails_on_curl_insecure_flag(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run: curl -k https://internal.example.com/secret
        """
        f = run_check(cfg, "CC-023")
        assert not f.passed

    def test_fails_on_npm_strict_ssl_false(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run: npm config set strict-ssl false
        """
        f = run_check(cfg, "CC-023")
        assert not f.passed

    def test_passes_when_no_tls_bypass_present(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps:
              - run: curl -fsSL https://example.com/data
        """
        f = run_check(cfg, "CC-023")
        assert f.passed
