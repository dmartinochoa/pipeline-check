"""Per-rule tests for GHA-092 (force-push race between a LIVE PR-head read
and a pinned re-fetch).

The rule fires only when one read of the PR head is *live* (``gh pr
view`` / ``gh api .../pulls/<n>``, or ``git rev-parse HEAD`` after a
mutable checkout) and a later ``actions/checkout`` pins to the payload
``head.sha``. Two reads of the immutable ``github.event.*.head.sha``
payload are constant-vs-constant and safe.
"""
from __future__ import annotations

from .conftest import run_check


class TestGHA092TOCTOUPRHeadSHA:
    def test_fires_on_gh_pr_view_live_read_then_pinned_checkout(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          gate-and-build:
            runs-on: ubuntu-latest
            steps:
              - id: gate
                env:
                  PR: ${{ github.event.number }}
                run: |
                  LIVE=$(gh pr view "$PR" --json headRefOid -q .headRefOid)
                  ./review-gate.sh "$LIVE"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed
        assert "gate-and-build" in f.description

    def test_fires_on_gh_api_pulls_live_read_then_pinned_checkout(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - run: gh api repos/${{ github.repository }}/pulls/${{ github.event.number }} > pr.json
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert not f.passed

    def test_fires_with_git_rev_parse_after_mutable_checkout(self):
        # Default checkout (no ref) leaves a mutable tree; git rev-parse
        # HEAD is then a live read, and the later pinned checkout is the
        # second, independent read.
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

    # ── Safe: two reads of the immutable payload SHA (constant pairs) ──

    def test_silent_on_pinned_capture_then_pinned_checkout(self):
        # The reported false positive: reading github.event.*.head.sha
        # for a gate then checking it out is reading the same immutable
        # constant twice. No race.
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
        assert f.passed

    def test_silent_on_env_pinned_capture_then_pinned_checkout(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          review:
            runs-on: ubuntu-latest
            steps:
              - env:
                  HEAD_SHA: ${{ github.event.pull_request.head.sha }}
                run: ./gate.sh "$HEAD_SHA"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_silent_on_workflow_env_pinned_capture(self):
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
        assert f.passed

    def test_silent_on_rev_parse_after_pinned_checkout(self):
        # rev-parse HEAD after a checkout PINNED to the payload SHA reads
        # that same immutable constant — not a live read.
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
              - run: |
                  HEAD_SHA=$(git rev-parse HEAD)
                  echo "sha=$HEAD_SHA" >> "$GITHUB_OUTPUT"
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_silent_on_pinned_variant_pair(self):
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
        assert f.passed

    def test_silent_on_multiple_pinned_checkouts(self):
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
        assert f.passed

    def test_silent_on_single_checkout_without_prior_read(self):
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

    def test_silent_on_live_read_after_the_pinned_checkout(self):
        # gh pr view AFTER the pinned checkout is a single live read with
        # no subsequent pinned re-fetch — order matters, not TOCTOU.
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
              - run: gh pr view "${{ github.event.number }}" --json headRefOid
        """
        f = run_check(wf, "GHA-092")
        assert f.passed

    def test_per_job_state_does_not_leak(self):
        wf = """
        name: pr-review
        on: pull_request_target
        jobs:
          gate:
            runs-on: ubuntu-latest
            steps:
              - run: gh pr view "${{ github.event.number }}" --json headRefOid
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
        """
        f = run_check(wf, "GHA-092")
        assert f.passed
