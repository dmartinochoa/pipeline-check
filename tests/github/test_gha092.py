"""Per-rule tests for GHA-092 (TOCTOU on PR head SHA between capture and checkout)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA092TOCTOUPRHeadSHA:
    def test_fires_on_capture_then_checkout(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review-and-build:
            runs-on: ubuntu-latest
            steps:
              - id: snap
                run: echo "sha=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_OUTPUT"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed
        assert "review-and-build" in f.description

    def test_fires_with_env_capture_at_step_scope(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - id: snap
                env:
                  HEAD_SHA: ${{ github.event.pull_request.head.sha }}
                run: ./gate.sh "$HEAD_SHA"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed

    def test_fires_with_workflow_env_capture(self):
        wf = """
        name: pr-review
        on: pull_request_target
        env:
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - run: ./gate.sh "$HEAD_SHA"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed

    def test_fires_with_git_rev_parse_capture(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - id: rev
                run: |
                  HEAD_SHA=$(git rev-parse HEAD)
                  echo "sha=$HEAD_SHA" >> "$GITHUB_OUTPUT"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        # First checkout step itself is the FIRST read (captures the
        # SHA into the working tree). Second checkout fires.
        f = run_check(wf, "GHA-092")
        assert not f.passed

    def test_silent_on_single_checkout_without_prior_capture(self):
        # Only one read: the checkout itself. Not TOCTOU.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: ./build.sh
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_silent_when_checkout_uses_captured_value(self):
        # The safe pattern: capture once into a step output, then
        # use the captured value (not a fresh interpolation) for the
        # checkout ref.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - id: snap
                run: echo "sha=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_OUTPUT"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ steps.snap.outputs.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_silent_on_main_ref_checkout(self):
        wf = """
        name: pr-review
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.head.sha }}"
              - uses: actions/checkout@v4
                with:
                  ref: main
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_silent_when_capture_after_checkout(self):
        # Order matters. Capture AFTER checkout (the canonical
        # "snapshot the resolved SHA for downstream gating") is
        # only one read of the live SHA, not two.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: echo "post-checkout sha=${{ github.event.pull_request.head.sha }}"
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_fires_on_pull_request_target_head_sha_variant(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request_target.head.sha }}"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request_target.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed

    def test_per_job_state_does_not_leak(self):
        # A capture in job A should not make a checkout in job B
        # fire. Different runners, no shared state.
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          gate:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.head.sha }}"
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_multiple_offenders_aggregated(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.head.sha }}"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
                  path: copy
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed
        assert "2 actions/checkout step(s)" in f.description

    def test_fires_with_git_rev_parse_in_separate_step(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: |
                  HEAD_SHA=$(git rev-parse HEAD)
                  ./gate.sh "$HEAD_SHA"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed
