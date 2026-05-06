"""Per-rule tests for CC-001 (orb pinning) and CC-003 (docker image pinning).

Both rules are about supply-chain integrity: a CircleCI config that
references mutable upstreams gets a different release on every run.
The tests cover positive (compliant pin), negative (floating ref),
and edge cases (volatile keyword, semver-major-only).
"""
from __future__ import annotations

from .conftest import run_check

# ── CC-001 orb pinning ───────────────────────────────────────────────


class TestCC001OrbPinning:
    def test_passes_with_exact_semver_orb(self):
        cfg = """
        version: 2.1
        orbs:
          node: circleci/node@5.1.0
        jobs:
          build:
            executor: node/default
            steps: [checkout]
        """
        f = run_check(cfg, "CC-001")
        assert f.passed

    def test_fails_when_orb_uses_volatile(self):
        cfg = """
        version: 2.1
        orbs:
          node: circleci/node@volatile
        """
        f = run_check(cfg, "CC-001")
        assert not f.passed
        assert "@volatile" in f.description or "volatile" in f.description

    def test_fails_when_orb_pins_major_only(self):
        cfg = """
        version: 2.1
        orbs:
          node: circleci/node@5
        """
        f = run_check(cfg, "CC-001")
        assert not f.passed

    def test_fails_when_orb_pins_major_minor(self):
        cfg = """
        version: 2.1
        orbs:
          node: circleci/node@5.1
        """
        f = run_check(cfg, "CC-001")
        assert not f.passed

    def test_fails_when_orb_lacks_at_sign(self):
        cfg = """
        version: 2.1
        orbs:
          node: circleci/node
        """
        f = run_check(cfg, "CC-001")
        assert not f.passed

    def test_passes_with_no_orbs_block(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/base:stable
            steps: [checkout]
        """
        f = run_check(cfg, "CC-001")
        assert f.passed

    def test_skips_inline_orb_definitions(self):
        # An inline orb (a dict, not a string) is a local override —
        # not a registry reference, so the floating-ref rule doesn't
        # apply. Should silently pass.
        cfg = """
        version: 2.1
        orbs:
          local:
            commands:
              greet:
                steps:
                  - run: echo hi
        """
        f = run_check(cfg, "CC-001")
        assert f.passed


# ── CC-003 docker image pinning ──────────────────────────────────────


class TestCC003DockerImagePinning:
    def test_passes_with_digest_pinned_image(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/node@sha256:0000000000000000000000000000000000000000000000000000000000000001
            steps: [checkout]
        """
        f = run_check(cfg, "CC-003")
        assert f.passed

    def test_fails_with_tag_pinned_image(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/node:18.17
            steps: [checkout]
        """
        f = run_check(cfg, "CC-003")
        assert not f.passed

    def test_fails_with_latest_tag(self):
        cfg = """
        version: 2.1
        jobs:
          build:
            docker:
              - image: cimg/node:latest
            steps: [checkout]
        """
        f = run_check(cfg, "CC-003")
        assert not f.passed
