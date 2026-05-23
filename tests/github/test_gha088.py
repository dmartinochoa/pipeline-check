"""Per-rule tests for GHA-088 (typosquat ``uses:``).

Distance ceiling is 2 by design. The fixtures exercise both
character-level (one missing, one inserted, one swapped) and
small-suffix (``setup-nodejs`` near ``setup-node``) cases, plus the
silence carve-outs for exact matches, local refs, and docker steps.
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA088TyposquatUses:
    def test_passes_on_canonical_actions(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-node@v4
              - uses: docker/build-push-action@v5
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-088").passed

    def test_fails_on_zero_for_o(self):
        # actions/check0ut: ``0`` instead of ``o``, distance 1.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/check0ut@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-088")
        assert not f.passed
        assert "actions/check0ut" in f.description
        assert "actions/checkout" in f.description

    def test_fails_on_missing_character(self):
        # actons/checkout: missing ``i``, distance 1.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actons/checkout@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-088")
        assert not f.passed
        assert "actons/checkout" in f.description
        assert "actions/checkout" in f.description

    def test_fails_on_transposition(self):
        # actions/cehckout: ``c<->h`` swap, distance 1 under Damerau.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/cehckout@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-088")
        assert not f.passed
        assert "actions/cehckout" in f.description

    def test_fails_on_distance_two(self):
        # actins/checkoutt: missing ``o``, extra trailing ``t``,
        # distance 2.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actins/checkoutt@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-088")
        assert not f.passed

    def test_passes_on_distance_three(self):
        # actoons/chekot: three or more edits, outside the ceiling.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actoons/chekot@v4
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-088").passed

    def test_passes_on_completely_unknown_action(self):
        # Custom internal action; not close to any top entry.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: acme-corp/internal-deploy@v1
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-088").passed

    def test_silent_on_local_action(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/build
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-088").passed

    def test_silent_on_docker_ref(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: docker://ghcr.io/acme/builder:1.2.3
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-088").passed

    def test_case_insensitive_match(self):
        # ``ACTIONS/CHECKOUT`` upper-cased is still the exact action,
        # not a typosquat. Make sure case folding kicks in.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: ACTIONS/Checkout@v4
              - run: ./build.sh
        """
        assert run_check(wf, "GHA-088").passed

    def test_case_insensitive_typosquat(self):
        # Upper-case typosquat still flags.
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: Actions/Checkouts@v4
              - run: ./build.sh
        """
        assert not run_check(wf, "GHA-088").passed

    def test_fails_on_reusable_workflow_uses(self):
        # Job-level ``uses:`` (reusable-workflow reference). The
        # owner/repo portion can be typosquatted too.
        wf = """
        on: push
        jobs:
          call-build:
            uses: dockre/build-push-action/.github/workflows/build.yml@v1
            secrets: inherit
        """
        f = run_check(wf, "GHA-088")
        assert not f.passed
        assert "docker/build-push-action" in f.description

    def test_multiple_typosquats_aggregated(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkouts@v4
              - uses: actions/setup-noide@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-088")
        assert not f.passed
        assert "2 ``uses:`` reference(s)" in f.description

    def test_finding_carries_step_locations(self):
        wf = """
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkouts@v4
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-088")
        assert not f.passed
        assert len(f.locations) == 1
        assert f.locations[0].path == "wf.yml"
