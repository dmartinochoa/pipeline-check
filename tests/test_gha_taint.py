"""Tests for the GHA dataflow / taint-path engine + TAINT-001.

Two layers:

  * ``analyze_workflow`` — the engine under
    ``pipeline_check.core.checks.github._taint_graph``.
    Tests cover producer detection (``$GITHUB_OUTPUT`` writes
    + legacy ``::set-output``), consumer detection
    (``${{ steps.<id>.outputs.<name> }}`` references), and the
    same-step / cross-job edge cases.
  * The ``TAINT-001`` rule wrapper. Tests the pass / fail
    description shape and confirm the rule fires only on
    cross-step paths (so it doesn't double-fire with GHA-003
    on direct interpolation).
"""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.github._taint_graph import (
    analyze_workflow,
)
from pipeline_check.core.checks.github.rules import (
    taint001_step_output_taint as t1,
)
from pipeline_check.core.checks.github.rules import (
    taint002_cross_job_output_taint as t2,
)


def _doc(yaml_text: str) -> dict:
    return yaml.safe_load(yaml_text)


# ── Engine: analyze_workflow ───────────────────────────────────────


class TestAnalyzeWorkflowProducer:
    def test_detects_canonical_github_output_write(self) -> None:
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "${{ steps.extract.outputs.title }}"
""")
        paths = analyze_workflow(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "github.event.issue.title"
        assert paths[0].source.location == "build[0]"

    def test_detects_legacy_set_output_form(self) -> None:
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "::set-output name=title::${{ github.event.pull_request.title }}"
      - run: echo "${{ steps.extract.outputs.title }}"
""")
        paths = analyze_workflow(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "github.event.pull_request.title"

    def test_detects_quoted_github_output_form(self) -> None:
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "msg=${{ github.event.head_commit.message }}" >> "$GITHUB_OUTPUT"
      - run: echo "${{ steps.extract.outputs.msg }}"
""")
        paths = analyze_workflow(doc)
        assert len(paths) == 1


class TestAnalyzeWorkflowConsumer:
    def test_zero_paths_when_no_consumer_in_workflow(self) -> None:
        # Producer present but nothing reads the output downstream.
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "no consumer here"
""")
        assert analyze_workflow(doc) == []

    def test_skips_self_step_reference(self) -> None:
        # A step that writes-then-reads its own output in the same
        # ``run:`` body is GHA-003 territory; the engine doesn't
        # fire on that case.
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
          echo "${{ steps.extract.outputs.title }}"
""")
        assert analyze_workflow(doc) == []

    def test_with_block_consumer(self) -> None:
        # ``with:`` parameters flowing into an action are also a
        # sink for the purpose of this engine.
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ steps.extract.outputs.title }}")
""")
        paths = analyze_workflow(doc)
        assert len(paths) == 1


class TestAnalyzeWorkflowMultiplePaths:
    def test_one_path_per_distinct_source_per_consumer(self) -> None:
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
          echo "msg=${{ github.event.head_commit.message }}" >> $GITHUB_OUTPUT
      - run: |
          echo "${{ steps.extract.outputs.title }}"
          echo "${{ steps.extract.outputs.msg }}"
""")
        paths = analyze_workflow(doc)
        # Two distinct outputs, two distinct consumers.
        assert len(paths) == 2

    def test_two_consumers_of_one_tainted_output(self) -> None:
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "${{ steps.extract.outputs.title }}"
      - run: cat <<<"${{ steps.extract.outputs.title }}"
""")
        paths = analyze_workflow(doc)
        # One source, two consumer steps -> two paths.
        assert len(paths) == 2


class TestAnalyzeWorkflowEdgeCases:
    def test_returns_empty_on_non_dict_doc(self) -> None:
        assert analyze_workflow("not a dict") == []  # type: ignore[arg-type]
        assert analyze_workflow({}) == []

    def test_returns_empty_on_jobs_not_dict(self) -> None:
        assert analyze_workflow({"jobs": "broken"}) == []

    def test_step_without_id_cannot_be_a_producer(self) -> None:
        # Without an ``id:`` the producer can't be referenced
        # downstream; the engine skips the producer pass for it.
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "${{ steps.extract.outputs.title }}"
""")
        assert analyze_workflow(doc) == []

    def test_untainted_output_is_not_propagated(self) -> None:
        # Producer writes a literal value, no source taint.
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=hardcoded-string" >> $GITHUB_OUTPUT
      - run: echo "${{ steps.extract.outputs.title }}"
""")
        assert analyze_workflow(doc) == []


# ── TAINT-001 rule wrapper ─────────────────────────────────────────


class TestTAINT001:
    def test_passes_when_no_paths(self) -> None:
        doc = _doc("""
on: push
jobs:
  build:
    steps:
      - run: echo hello
""")
        f = t1.check("wf.yml", doc)
        assert f.passed
        assert "No cross-step taint path" in f.description

    def test_fails_with_path_in_description(self) -> None:
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "${{ steps.extract.outputs.title }}"
""")
        f = t1.check("wf.yml", doc)
        assert not f.passed
        # The description carries the source name and the consumed token.
        assert "github.event.issue.title" in f.description
        assert "steps.extract.outputs.title" in f.description
        assert "1 cross-step taint path" in f.description

    def test_fails_with_truncation_for_many_paths(self) -> None:
        # Build a workflow with 5 distinct tainted outputs all
        # consumed; the rule's rendered description truncates to
        # the first three.
        sources = [
            ("a", "github.event.issue.title"),
            ("b", "github.event.pull_request.title"),
            ("c", "github.event.head_commit.message"),
            ("d", "github.event.comment.body"),
            ("e", "github.head_ref"),
        ]
        produces = "\n          ".join(
            f'echo "{n}=${{{{ {expr} }}}}" >> $GITHUB_OUTPUT'
            for n, expr in sources
        )
        consumes = "\n          ".join(
            f'echo "${{{{ steps.x.outputs.{n} }}}}"'
            for n, _ in sources
        )
        doc = _doc(f"""
on: pull_request_target
jobs:
  build:
    steps:
      - id: x
        run: |
          {produces}
      - run: |
          {consumes}
""")
        f = t1.check("wf.yml", doc)
        assert not f.passed
        assert "5 cross-step taint path" in f.description
        # ``...`` continuation marker after the first three.
        assert "..." in f.description

    def test_does_not_double_fire_on_direct_interpolation(self) -> None:
        # The same-step direct case is GHA-003's. TAINT-001 is silent.
        doc = _doc("""
on: push
jobs:
  build:
    steps:
      - run: echo "${{ github.event.head_commit.message }}"
""")
        f = t1.check("wf.yml", doc)
        assert f.passed

    def test_silent_on_cross_job_path(self) -> None:
        # Cross-job is TAINT-002's territory; TAINT-001 stays silent
        # so the two rules don't double-fire on the same workflow.
        doc = _doc("""
on: pull_request_target
jobs:
  extract:
    outputs:
      title: ${{ steps.x.outputs.title }}
    steps:
      - id: x
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
  use:
    needs: extract
    steps:
      - run: echo "${{ needs.extract.outputs.title }}"
""")
        assert t1.check("wf.yml", doc).passed


# ── TAINT-002 rule wrapper ─────────────────────────────────────────


class TestTAINT002:
    def test_passes_when_no_cross_job_paths(self) -> None:
        # No cross-job propagation in this workflow.
        doc = _doc("""
on: push
jobs:
  build:
    steps:
      - run: echo hello
""")
        assert t2.check("wf.yml", doc).passed

    def test_passes_on_same_job_only_path(self) -> None:
        # Single-job step-output flow is TAINT-001 territory.
        doc = _doc("""
on: pull_request_target
jobs:
  build:
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
      - run: echo "${{ steps.extract.outputs.title }}"
""")
        assert t2.check("wf.yml", doc).passed

    def test_fails_on_cross_job_propagation(self) -> None:
        doc = _doc("""
on: pull_request_target
jobs:
  extract:
    outputs:
      title: ${{ steps.x.outputs.title }}
    steps:
      - id: x
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
  use:
    needs: extract
    steps:
      - run: echo "${{ needs.extract.outputs.title }}"
""")
        f = t2.check("wf.yml", doc)
        assert not f.passed
        # Description carries the source, the job-output hop, and
        # the consumer side.
        assert "github.event.issue.title" in f.description
        assert "jobs.extract.outputs.title" in f.description
        assert "needs.extract.outputs.title" in f.description
        assert "1 cross-job taint path" in f.description

    def test_fails_on_direct_github_event_in_job_output(self) -> None:
        # A job output that interpolates ``${{ github.event.* }}``
        # directly (no intermediate step output) is also tainted
        # and the cross-job consumer fires TAINT-002.
        doc = _doc("""
on: pull_request_target
jobs:
  extract:
    outputs:
      title: ${{ github.event.issue.title }}
    steps:
      - run: echo noop
  use:
    needs: extract
    steps:
      - run: echo "${{ needs.extract.outputs.title }}"
""")
        f = t2.check("wf.yml", doc)
        assert not f.passed
        assert "github.event.issue.title" in f.description

    def test_silent_when_consumer_uses_unknown_needs_output(self) -> None:
        # Consumer references a needs.X.outputs.Y that wasn't
        # declared as tainted (the producer's expression is benign).
        doc = _doc("""
on: pull_request_target
jobs:
  extract:
    outputs:
      title: hardcoded-string
    steps:
      - run: echo noop
  use:
    needs: extract
    steps:
      - run: echo "${{ needs.extract.outputs.title }}"
""")
        assert t2.check("wf.yml", doc).passed
