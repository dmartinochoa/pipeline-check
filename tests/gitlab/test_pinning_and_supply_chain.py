"""Per-rule tests for GitLab GL-001 (image pinning) and GL-005 (include
pinning).

Both rules guard against pulling mutable references at run time —
GL-001 for container images consumed by jobs, GL-005 for ``include:``
of remote pipeline templates.
"""
from __future__ import annotations

from .conftest import run_check

# ── GL-001 image pinning ─────────────────────────────────────────────


class TestGL001ImagePinning:
    def test_passes_with_digest_pinned_top_level_image(self):
        cfg = """
        image: python@sha256:0000000000000000000000000000000000000000000000000000000000000001
        stages: [build]
        build_job:
          stage: build
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-001")
        assert f.passed

    def test_passes_with_full_version_tag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-001")
        assert f.passed

    def test_fails_with_latest_tag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:latest
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-001")
        assert not f.passed

    def test_fails_with_no_tag(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-001")
        assert not f.passed

    def test_passes_with_major_only_tag(self):
        # Documents the GL-001 helper's current behavior: a tag
        # containing any digit is accepted as ``pinned``. Major-only
        # tags like ``python:3`` are mutable upstream but the rule
        # leaves catching them to a future tightening of
        # ``_primitives.image_pinning.VERSION_TAG_RE``.
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-001")
        assert f.passed


# ── GL-005 include pinning ──────────────────────────────────────────


class TestGL005IncludePinning:
    def test_fails_when_remote_include_lacks_ref(self):
        # Remote include without a ``ref:`` floats — whoever controls
        # the source repo can ship code into this pipeline.
        cfg = """
        include:
          - project: 'group/templates'
            file: '/build.yml'
        stages: [build]
        build_job:
          stage: build
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-005")
        assert not f.passed

    def test_passes_when_include_pinned_to_tag(self):
        cfg = """
        include:
          - project: 'group/templates'
            file: '/build.yml'
            ref: 'v1.4.2'
        stages: [build]
        build_job:
          stage: build
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-005")
        assert f.passed

    def test_passes_when_include_pinned_to_commit_sha(self):
        cfg = """
        include:
          - project: 'group/templates'
            file: '/build.yml'
            ref: aabbccddeeff00112233445566778899aabbccdd
        stages: [build]
        build_job:
          stage: build
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-005")
        assert f.passed

    def test_passes_when_no_include_block(self):
        cfg = """
        stages: [build]
        build_job:
          stage: build
          image: python:3.12.1-slim
          script: [pytest]
          timeout: 30 minutes
        """
        f = run_check(cfg, "GL-005")
        assert f.passed
