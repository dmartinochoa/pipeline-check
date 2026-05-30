"""Tests for CC-033 (Go module verification disabled in a job)."""
from __future__ import annotations

from .conftest import run_check


class TestCC033:
    def test_fires_on_job_environment(self):
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            environment:
              GOSUMDB: "off"
            steps:
              - checkout
              - run: go build ./...
        """, "CC-033")
        assert not f.passed
        assert "GOSUMDB" in f.description

    def test_fires_on_inline_export(self):
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            steps:
              - run:
                  command: |
                    export GOFLAGS=-insecure
                    go build ./...
        """, "CC-033")
        assert not f.passed

    def test_fires_on_run_step_environment(self):
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            steps:
              - run:
                  environment:
                    GONOSUMCHECK: "1"
                  command: go build ./...
        """, "CC-033")
        assert not f.passed

    def test_passes_on_clean_job(self):
        f = run_check("""
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/go:1.22
            steps:
              - checkout
              - run: go build ./...
        """, "CC-033")
        assert f.passed
