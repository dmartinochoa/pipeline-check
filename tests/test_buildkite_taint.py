"""Tests for the Buildkite dataflow / taint-path engine + TAINT-005.

Mirrors ``tests/test_gha_taint.py`` and ``tests/test_gitlab_taint.py``.
The Buildkite-specific shape is the meta-data set/get round-trip;
tests cover producer detection, consumer detection, the
producer-equals-consumer skip, and the rule wrapper output shape.
"""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.buildkite._taint_graph import (
    analyze_pipeline,
)
from pipeline_check.core.checks.buildkite.rules import (
    taint005_metadata_taint as t5,
)


def _doc(yaml_text: str) -> dict:
    return yaml.safe_load(yaml_text)


# ── Engine: analyze_pipeline ───────────────────────────────────────


class TestAnalyzePipelineProducer:
    def test_detects_canonical_meta_data_set(self) -> None:
        doc = _doc("""
steps:
  - label: extract
    command: |
      buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST"
  - wait
  - label: use
    command: |
      buildkite-agent meta-data get title
""")
        paths = analyze_pipeline(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "BUILDKITE_PULL_REQUEST"

    def test_detects_branch_source(self) -> None:
        doc = _doc("""
steps:
  - label: extract
    command: buildkite-agent meta-data set "branch" "$BUILDKITE_BRANCH"
  - label: use
    command: buildkite-agent meta-data get branch
""")
        paths = analyze_pipeline(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "BUILDKITE_BRANCH"

    def test_detects_message_source(self) -> None:
        doc = _doc("""
steps:
  - label: extract
    command: buildkite-agent meta-data set "msg" "$BUILDKITE_MESSAGE"
  - label: use
    command: buildkite-agent meta-data get msg
""")
        assert len(analyze_pipeline(doc)) == 1


class TestAnalyzePipelineConsumer:
    def test_zero_paths_when_no_consumer(self) -> None:
        doc = _doc("""
steps:
  - label: extract
    command: buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST"
""")
        assert analyze_pipeline(doc) == []

    def test_zero_paths_when_consumer_uses_different_key(self) -> None:
        # Producer leaks "title", consumer reads "version".
        doc = _doc("""
steps:
  - label: extract
    command: buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST"
  - label: use
    command: buildkite-agent meta-data get version
""")
        assert analyze_pipeline(doc) == []

    def test_skips_self_step_reference(self) -> None:
        # Single step that sets and gets its own meta-data is
        # BK-003 territory (direct interpolation within the step).
        doc = _doc("""
steps:
  - label: extract
    command: |
      buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST"
      X=$(buildkite-agent meta-data get title)
      echo $X
""")
        assert analyze_pipeline(doc) == []


class TestAnalyzePipelineMultiple:
    def test_one_path_per_distinct_key(self) -> None:
        doc = _doc("""
steps:
  - label: extract
    command: |
      buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST"
      buildkite-agent meta-data set "branch" "$BUILDKITE_BRANCH"
  - wait
  - label: use
    command: |
      buildkite-agent meta-data get title
      buildkite-agent meta-data get branch
""")
        paths = analyze_pipeline(doc)
        assert len(paths) == 2

    def test_two_consumers_of_one_leak(self) -> None:
        doc = _doc("""
steps:
  - label: extract
    command: buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST"
  - label: build
    command: buildkite-agent meta-data get title
  - label: deploy
    command: buildkite-agent meta-data get title
""")
        paths = analyze_pipeline(doc)
        assert len(paths) == 2


class TestAnalyzePipelineEdgeCases:
    def test_returns_empty_on_non_dict(self) -> None:
        assert analyze_pipeline("nope") == []  # type: ignore[arg-type]
        assert analyze_pipeline({}) == []

    def test_no_taint_in_set_value(self) -> None:
        # Producer sets a hardcoded literal; consumer's get is benign.
        doc = _doc("""
steps:
  - label: extract
    command: buildkite-agent meta-data set "title" "hardcoded-value"
  - label: use
    command: buildkite-agent meta-data get title
""")
        assert analyze_pipeline(doc) == []

    def test_handles_step_without_command(self) -> None:
        # ``wait`` / ``block`` steps don't carry a command.
        doc = _doc("""
steps:
  - wait
  - block: "Manual gate"
""")
        assert analyze_pipeline(doc) == []


# ── TAINT-005 rule wrapper ─────────────────────────────────────────


class TestTAINT005:
    def test_passes_when_no_meta_data_flow(self) -> None:
        doc = _doc("""
steps:
  - label: build
    command: make
""")
        f = t5.check("pipeline.yml", doc)
        assert f.passed
        assert "No cross-step taint path" in f.description

    def test_fails_with_path_in_description(self) -> None:
        doc = _doc("""
steps:
  - label: extract
    command: buildkite-agent meta-data set "title" "$BUILDKITE_PULL_REQUEST"
  - label: use
    command: buildkite-agent meta-data get title
""")
        f = t5.check("pipeline.yml", doc)
        assert not f.passed
        assert "BUILDKITE_PULL_REQUEST" in f.description
        assert "meta-data.title" in f.description
        assert "1 cross-step taint path" in f.description
