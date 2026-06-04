"""Tests for GL-042 (include: component pinned to a mutable version)."""
from __future__ import annotations

from .conftest import run_check


class TestGL042ComponentPinning:
    def test_fails_on_latest(self):
        f = run_check("""
        include:
          - component: gitlab.example.com/ci/security/scan@~latest
        build:
          script: [make]
        """, "GL-042")
        assert not f.passed
        assert "mutable" in f.description

    def test_fails_on_branch_ref(self):
        f = run_check("""
        include:
          - component: gitlab.example.com/ci/security/scan@main
        build:
          script: [make]
        """, "GL-042")
        assert not f.passed

    def test_fails_on_partial_version(self):
        f = run_check("""
        include:
          - component: gitlab.example.com/ci/security/scan@1
        build:
          script: [make]
        """, "GL-042")
        assert not f.passed

    def test_fails_when_no_version(self):
        f = run_check("""
        include:
          - component: gitlab.example.com/ci/security/scan
        build:
          script: [make]
        """, "GL-042")
        assert not f.passed

    def test_passes_on_full_semver_tag(self):
        f = run_check("""
        include:
          - component: gitlab.example.com/ci/security/scan@1.4.2
        build:
          script: [make]
        """, "GL-042")
        assert f.passed

    def test_passes_on_commit_sha(self):
        f = run_check("""
        include:
          - component: gitlab.example.com/ci/security/scan@0a1b2c3d4e5f60718293a4b5c6d7e8f901234567
        build:
          script: [make]
        """, "GL-042")
        assert f.passed

    def test_passes_when_no_component_include(self):
        f = run_check("""
        include:
          - project: ci/templates
            ref: v1.0.0
        build:
          script: [make]
        """, "GL-042")
        assert f.passed
