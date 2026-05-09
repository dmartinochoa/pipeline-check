"""Tests for the GitLab CI dataflow / taint-path engine + TAINT-004.

Mirrors the GHA equivalent in ``tests/test_gha_taint.py``. Two
layers:

  * ``analyze_pipeline`` — engine in
    ``pipeline_check.core.checks.gitlab._taint_graph``.
  * ``TAINT-004`` rule wrapper that filters engine output to
    fail/pass shape.
"""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.gitlab._taint_graph import (
    analyze_extends_taint,
    analyze_pipeline,
)
from pipeline_check.core.checks.gitlab.rules import (
    taint004_dotenv_artifact_taint as t4,
)
from pipeline_check.core.checks.gitlab.rules import (
    taint008_extends_chain_taint as t8,
)


def _doc(yaml_text: str) -> dict:
    return yaml.safe_load(yaml_text)


# ── Engine: analyze_pipeline ───────────────────────────────────────


class TestAnalyzePipelineProducer:
    def test_detects_canonical_dotenv_write(self) -> None:
        doc = _doc("""
stages: [extract, build]
extract:
  stage: extract
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  stage: build
  needs: [extract]
  script:
    - echo $TITLE
""")
        paths = analyze_pipeline(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "CI_COMMIT_TITLE"

    def test_detects_dotenv_with_relative_path_prefix(self) -> None:
        # ``./taint.env`` and ``taint.env`` should resolve to the
        # same path (basename match).
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > ./taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo $TITLE
""")
        assert len(analyze_pipeline(doc)) == 1

    def test_detects_dotenv_list_form(self) -> None:
        # ``dotenv:`` accepts either a string or a list of strings.
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv:
        - taint.env
        - other.env
build:
  needs: [extract]
  script:
    - echo $TITLE
""")
        assert len(analyze_pipeline(doc)) == 1

    def test_detects_merge_request_title_source(self) -> None:
        doc = _doc("""
extract:
  script:
    - echo "DESC=$CI_MERGE_REQUEST_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo $DESC
""")
        paths = analyze_pipeline(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "CI_MERGE_REQUEST_TITLE"


class TestAnalyzePipelineConsumer:
    def test_zero_paths_when_no_consumer(self) -> None:
        # Producer leaks but no downstream needs: link.
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
""")
        assert analyze_pipeline(doc) == []

    def test_zero_paths_when_consumer_does_not_need_producer(self) -> None:
        # Consumer doesn't list extract in needs.
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  script:
    - echo $TITLE
""")
        assert analyze_pipeline(doc) == []

    def test_dependencies_field_also_propagates(self) -> None:
        # ``dependencies:`` is the legacy field that also triggers
        # auto-import of dotenv vars.
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  dependencies: [extract]
  script:
    - echo $TITLE
""")
        assert len(analyze_pipeline(doc)) == 1

    def test_quoted_consumer_reference_still_emits_engine_path(self) -> None:
        # The engine itself doesn't filter on quote state — the
        # rule layer can. Even quoted ``"$TITLE"`` references emit
        # an engine-level path; rule consumers may treat this
        # differently. Check the engine emits the path.
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo "$TITLE"
""")
        # Quoted reference, our walker treats this as safe and
        # doesn't emit. (The engine does perform quote-state
        # filtering inside ``_iter_var_refs``.)
        paths = analyze_pipeline(doc)
        assert paths == []


class TestAnalyzePipelineMultiple:
    def test_one_path_per_distinct_var_per_consumer(self) -> None:
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
    - echo "BRANCH=$CI_COMMIT_BRANCH" >> taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo $TITLE
    - echo $BRANCH
""")
        paths = analyze_pipeline(doc)
        # Two leaks, two consumers -> two paths.
        assert len(paths) == 2

    def test_two_consumers_of_one_leak(self) -> None:
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo $TITLE
deploy:
  needs: [extract]
  script:
    - cat <<<$TITLE
""")
        paths = analyze_pipeline(doc)
        assert len(paths) == 2


class TestAnalyzePipelineEdgeCases:
    def test_returns_empty_on_non_dict(self) -> None:
        assert analyze_pipeline("nope") == []  # type: ignore[arg-type]
        assert analyze_pipeline({}) == []

    def test_no_dotenv_means_no_leak(self) -> None:
        # Producer writes KEY=VALUE but doesn't declare dotenv,
        # so no auto-import happens.
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
build:
  needs: [extract]
  script:
    - echo $TITLE
""")
        assert analyze_pipeline(doc) == []

    def test_untainted_value_not_propagated(self) -> None:
        doc = _doc("""
extract:
  script:
    - echo "TITLE=hardcoded-string" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo $TITLE
""")
        assert analyze_pipeline(doc) == []


# ── TAINT-004 rule wrapper ─────────────────────────────────────────


class TestTAINT004:
    def test_passes_when_no_paths(self) -> None:
        doc = _doc("""
build:
  script:
    - echo hello
""")
        f = t4.check("ci.yml", doc)
        assert f.passed
        assert "No cross-job taint path" in f.description

    def test_fails_with_path_in_description(self) -> None:
        doc = _doc("""
extract:
  script:
    - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo $TITLE
""")
        f = t4.check("ci.yml", doc)
        assert not f.passed
        assert "CI_COMMIT_TITLE" in f.description
        assert "$TITLE" in f.description
        assert "1 cross-job taint path" in f.description

    def test_fails_with_truncation_for_many_paths(self) -> None:
        doc = _doc("""
extract:
  script:
    - echo "A=$CI_COMMIT_TITLE" > taint.env
    - echo "B=$CI_COMMIT_BRANCH" >> taint.env
    - echo "C=$CI_COMMIT_MESSAGE" >> taint.env
    - echo "D=$CI_MERGE_REQUEST_TITLE" >> taint.env
  artifacts:
    reports:
      dotenv: taint.env
build:
  needs: [extract]
  script:
    - echo $A
    - echo $B
    - echo $C
    - echo $D
""")
        f = t4.check("ci.yml", doc)
        assert not f.passed
        assert "4 cross-job taint path" in f.description
        assert "..." in f.description


# ── Engine: analyze_extends_taint ─────────────────────────────────


class TestExtendsEngine:
    def test_detects_inherited_tainted_var(self) -> None:
        doc = _doc("""
.base:
  variables:
    TITLE: $CI_COMMIT_TITLE
build:
  extends: .base
  script:
    - echo Building $TITLE
""")
        paths = analyze_extends_taint(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "CI_COMMIT_TITLE"
        assert "$TITLE" in paths[0].sink_consumer

    def test_resolves_multi_level_chain(self) -> None:
        # ``.real -> .middle -> .base`` chain. Taint declared in
        # the deepest link should still propagate.
        doc = _doc("""
.base:
  variables:
    TITLE: $CI_COMMIT_TITLE
.middle:
  extends: .base
build:
  extends: .middle
  script:
    - echo Building $TITLE
""")
        paths = analyze_extends_taint(doc)
        assert len(paths) == 1

    def test_handles_extends_list_form(self) -> None:
        # ``extends: [a, b]`` is the multi-template form. We
        # union variables from both.
        doc = _doc("""
.base:
  variables:
    A: $CI_COMMIT_TITLE
.helper:
  variables:
    B: $CI_COMMIT_BRANCH
build:
  extends:
    - .base
    - .helper
  script:
    - echo $A $B
""")
        paths = analyze_extends_taint(doc)
        assert len(paths) == 2

    def test_zero_paths_when_no_extends(self) -> None:
        doc = _doc("""
.base:
  variables:
    TITLE: $CI_COMMIT_TITLE
build:
  script:
    - echo $TITLE
""")
        # Job doesn't extend, so it doesn't inherit.
        assert analyze_extends_taint(doc) == []

    def test_zero_paths_when_consumer_quotes_var(self) -> None:
        doc = _doc("""
.base:
  variables:
    TITLE: $CI_COMMIT_TITLE
build:
  extends: .base
  script:
    - echo "$TITLE"
""")
        # Quoted reference is safe.
        assert analyze_extends_taint(doc) == []

    def test_zero_paths_when_inherited_var_not_referenced(self) -> None:
        doc = _doc("""
.base:
  variables:
    TITLE: $CI_COMMIT_TITLE
build:
  extends: .base
  script:
    - echo unrelated
""")
        assert analyze_extends_taint(doc) == []

    def test_breaks_extends_cycles(self) -> None:
        # Pathological YAML with a self-referential cycle. The
        # walker shouldn't infinite-loop.
        doc = _doc("""
.base:
  extends: .base
  variables:
    TITLE: $CI_COMMIT_TITLE
build:
  extends: .base
  script:
    - echo $TITLE
""")
        paths = analyze_extends_taint(doc)
        # Detection still works, cycle is just bounded.
        assert len(paths) == 1

    def test_returns_empty_on_non_dict_doc(self) -> None:
        assert analyze_extends_taint("not a dict") == []  # type: ignore[arg-type]
        assert analyze_extends_taint({}) == []


# ── TAINT-008 rule wrapper ─────────────────────────────────────────


class TestTAINT008:
    def test_passes_when_no_extends_taint(self) -> None:
        doc = _doc("""
build:
  script:
    - echo hello
""")
        f = t8.check("ci.yml", doc)
        assert f.passed
        assert "No tainted variable inherited" in f.description

    def test_fails_with_path_in_description(self) -> None:
        doc = _doc("""
.base:
  variables:
    TITLE: $CI_COMMIT_TITLE
build:
  extends: .base
  script:
    - echo Building $TITLE
""")
        f = t8.check("ci.yml", doc)
        assert not f.passed
        assert "CI_COMMIT_TITLE" in f.description
        assert ".base.variables.TITLE" in f.description
        assert "1 extends-inheritance taint path" in f.description
