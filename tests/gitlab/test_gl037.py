"""Tests for GL-037 (Go module verification disabled in a pipeline)."""
from __future__ import annotations

from .conftest import run_check


class TestGL037:
    def test_fires_on_global_variables(self):
        f = run_check("""
        variables:
          GOSUMDB: "off"
        build:
          script:
            - go build ./...
        """, "GL-037")
        assert not f.passed
        assert "GOSUMDB" in f.description

    def test_fires_on_job_variables_goflags(self):
        f = run_check("""
        build:
          variables:
            GOFLAGS: -insecure
          script:
            - go build ./...
        """, "GL-037")
        assert not f.passed

    def test_fires_on_inline_export(self):
        f = run_check("""
        build:
          script:
            - export GOSUMDB=off
            - go build ./...
        """, "GL-037")
        assert not f.passed

    def test_passes_on_clean_pipeline(self):
        f = run_check("""
        build:
          variables:
            GOFLAGS: -mod=readonly
          script:
            - go build ./...
        """, "GL-037")
        assert f.passed

    def test_passes_on_scoped_goprivate(self):
        f = run_check("""
        variables:
          GOPRIVATE: gitlab.example.com/myteam/*
        build:
          script:
            - go build ./...
        """, "GL-037")
        assert f.passed
