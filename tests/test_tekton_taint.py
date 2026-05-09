"""Tests for the Tekton dataflow / taint-path engine + TAINT-006."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.tekton._taint_graph import (
    analyze_pipeline_doc,
)
from pipeline_check.core.checks.tekton.base import (
    TektonContext,
    TektonDoc,
)
from pipeline_check.core.checks.tekton.rules import (
    taint006_results_taint as t6,
)


def _pipeline_doc(yaml_text: str) -> TektonDoc:
    """Build a Pipeline TektonDoc from raw YAML."""
    data = yaml.safe_load(yaml_text)
    return TektonDoc(
        path="pipeline.yaml",
        doc_index=0,
        api_version=str(data.get("apiVersion", "")),
        kind=str(data.get("kind", "")),
        name=str((data.get("metadata") or {}).get("name", "")),
        namespace=str((data.get("metadata") or {}).get("namespace", "")),
        data=data,
    )


# ── Engine: analyze_pipeline_doc ───────────────────────────────────


class TestEngineProducer:
    def test_detects_canonical_results_write(self) -> None:
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: extract
      taskSpec:
        params:
          - name: title
        results:
          - name: clean
        steps:
          - name: extract
            script: |
              echo "$(params.title)" > $(results.clean.path)
    - name: build
      runAfter: [extract]
      params:
        - name: title
          value: $(tasks.extract.results.clean)
      taskSpec:
        params:
          - name: title
        steps:
          - name: b
            script: |
              echo $(params.title)
""")
        paths = analyze_pipeline_doc(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "title"

    def test_returns_empty_for_non_pipeline_doc(self) -> None:
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: t
spec:
  steps:
    - name: x
      script: echo hello
""")
        assert analyze_pipeline_doc(doc) == []


class TestEngineConsumer:
    def test_zero_paths_when_no_consumer(self) -> None:
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: extract
      taskSpec:
        params:
          - name: title
        results:
          - name: clean
        steps:
          - script: |
              echo "$(params.title)" > $(results.clean.path)
""")
        assert analyze_pipeline_doc(doc) == []

    def test_zero_paths_when_consumer_uses_different_result(self) -> None:
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: extract
      taskSpec:
        params:
          - name: title
        results:
          - name: clean
        steps:
          - script: |
              echo "$(params.title)" > $(results.clean.path)
    - name: build
      params:
        - name: title
          value: $(tasks.extract.results.other)
      taskSpec:
        params:
          - name: title
        steps:
          - script: echo $(params.title)
""")
        assert analyze_pipeline_doc(doc) == []

    def test_zero_paths_when_consumer_does_not_reference_param(self) -> None:
        # Consumer receives the tainted forward but never uses it.
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: extract
      taskSpec:
        params:
          - name: title
        results:
          - name: clean
        steps:
          - script: |
              echo "$(params.title)" > $(results.clean.path)
    - name: build
      params:
        - name: title
          value: $(tasks.extract.results.clean)
      taskSpec:
        params:
          - name: title
        steps:
          - script: echo unrelated
""")
        assert analyze_pipeline_doc(doc) == []


class TestEngineMultiplePaths:
    def test_one_path_per_distinct_consumer_step(self) -> None:
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: extract
      taskSpec:
        params:
          - name: title
        results:
          - name: clean
        steps:
          - script: |
              echo "$(params.title)" > $(results.clean.path)
    - name: build
      params:
        - name: title
          value: $(tasks.extract.results.clean)
      taskSpec:
        params:
          - name: title
        steps:
          - script: echo $(params.title)
          - script: cat <<<$(params.title)
""")
        paths = analyze_pipeline_doc(doc)
        assert len(paths) == 2


# ── TAINT-006 rule wrapper ─────────────────────────────────────────


def _ctx(*docs: TektonDoc) -> TektonContext:
    return TektonContext(list(docs))


class TestTAINT006:
    def test_passes_when_no_pipeline_in_context(self) -> None:
        # Only Task docs, no Pipeline -> short-circuit.
        task_doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: t
spec:
  steps:
    - script: echo hi
""")
        f = t6.check(_ctx(task_doc))
        assert f.passed
        assert "No Pipeline documents" in f.description

    def test_passes_when_pipeline_has_no_taint_path(self) -> None:
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: build
      taskSpec:
        steps:
          - script: echo build
""")
        f = t6.check(_ctx(doc))
        assert f.passed

    def test_fails_with_path_in_description(self) -> None:
        doc = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: extract
      taskSpec:
        params:
          - name: title
        results:
          - name: clean
        steps:
          - script: |
              echo "$(params.title)" > $(results.clean.path)
    - name: build
      params:
        - name: title
          value: $(tasks.extract.results.clean)
      taskSpec:
        params:
          - name: title
        steps:
          - script: echo $(params.title)
""")
        f = t6.check(_ctx(doc))
        assert not f.passed
        assert "1 cross-task taint path" in f.description
        assert "$(params.title)" in f.description
