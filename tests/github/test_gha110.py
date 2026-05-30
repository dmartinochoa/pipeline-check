"""Tests for GHA-110 (Go module verification disabled in a workflow)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA110:
    def test_fires_on_job_env_gosumdb_off(self):
        f = run_check("""
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              GOSUMDB: "off"
            steps:
              - run: go build ./...
        """, "GHA-110")
        assert not f.passed
        assert "GOSUMDB" in f.description

    def test_fires_on_workflow_env_goflags_insecure(self):
        f = run_check("""
        on: push
        env:
          GOFLAGS: -insecure
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: go build ./...
        """, "GHA-110")
        assert not f.passed

    def test_fires_on_inline_export(self):
        f = run_check("""
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  export GONOSUMCHECK=1
                  go build ./...
        """, "GHA-110")
        assert not f.passed

    def test_passes_on_clean_workflow(self):
        f = run_check("""
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              GOFLAGS: -mod=readonly
            steps:
              - run: go build ./...
        """, "GHA-110")
        assert f.passed

    def test_passes_on_scoped_goprivate(self):
        f = run_check("""
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            env:
              GOPRIVATE: github.com/myorg/*
            steps:
              - run: go build ./...
        """, "GHA-110")
        assert f.passed
