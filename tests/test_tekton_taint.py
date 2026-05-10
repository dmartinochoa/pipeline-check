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


# ── taskRef cross-document resolution ──────────────────────────────


class TestTaskRefResolution:
    """When a Pipeline references a Task via ``taskRef:`` instead of
    inlining ``taskSpec:``, the resolver looks up the Task document
    by name within the same :class:`TektonContext`. This closes the
    long-standing v1 gap where TAINT-006 missed cross-document taint
    flow."""

    def _producer_taskref_pipeline(self) -> str:
        return """
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: p
spec:
  tasks:
    - name: extract
      taskRef:
        name: extract-task
      params:
        - name: title
          value: $(params.pr-title)
    - name: build
      runAfter: [extract]
      params:
        - name: title
          value: $(tasks.extract.results.clean)
      taskSpec:
        params:
          - name: title
        steps:
          - script: echo $(params.title)
"""

    def _producer_task(self) -> str:
        return """
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: extract-task
spec:
  params:
    - name: title
  results:
    - name: clean
  steps:
    - script: |
        echo "$(params.title)" > $(results.clean.path)
"""

    def test_taint_resolved_when_producer_uses_taskref(self) -> None:
        pipeline = _pipeline_doc(self._producer_taskref_pipeline())
        producer = _pipeline_doc(self._producer_task())
        ctx = _ctx(pipeline, producer)
        f = t6.check(ctx)
        assert not f.passed, (
            "TAINT-006 should fire when the producer's body lives in a "
            "sibling Task document and the pipeline references it via "
            "taskRef:"
        )
        assert "1 cross-task taint path" in f.description

    def test_passes_when_referenced_task_not_in_context(self) -> None:
        """A taskRef pointing at a Task that wasn't loaded into the
        same scan resolves to None and the path is silently skipped.
        Avoids a false-positive when the producer is shipped from a
        location the user didn't include in --tekton-path."""
        pipeline = _pipeline_doc(self._producer_taskref_pipeline())
        # Note: no producer Task document in the context.
        ctx = _ctx(pipeline)
        f = t6.check(ctx)
        assert f.passed

    def test_taint_resolved_when_consumer_uses_taskref(self) -> None:
        """The mirror case: producer inline, consumer via taskRef."""
        pipeline = _pipeline_doc("""
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
      taskRef:
        name: build-task
      params:
        - name: title
          value: $(tasks.extract.results.clean)
""")
        consumer = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: build-task
spec:
  params:
    - name: title
  steps:
    - script: echo $(params.title)
""")
        f = t6.check(_ctx(pipeline, consumer))
        assert not f.passed

    def test_clustertask_resolves_same_as_task(self) -> None:
        """``ClusterTask`` is the cluster-scoped variant of ``Task``;
        the resolver indexes both kinds the same way."""
        pipeline = _pipeline_doc(self._producer_taskref_pipeline())
        producer = _pipeline_doc("""
apiVersion: tekton.dev/v1beta1
kind: ClusterTask
metadata:
  name: extract-task
spec:
  params:
    - name: title
  results:
    - name: clean
  steps:
    - script: |
        echo "$(params.title)" > $(results.clean.path)
""")
        f = t6.check(_ctx(pipeline, producer))
        assert not f.passed

    def test_engine_skips_taskref_without_ctx(self) -> None:
        """Direct callers of ``analyze_pipeline_doc(doc)`` (no ctx)
        keep the legacy behavior: ``taskRef:`` paths are skipped
        silently. Preserves the old API for any third-party callers
        that depend on the single-doc shape."""
        pipeline = _pipeline_doc(self._producer_taskref_pipeline())
        from pipeline_check.core.checks.tekton._taint_graph import (
            analyze_pipeline_doc,
        )
        # Without ctx, no resolver, no cross-document analysis.
        paths = analyze_pipeline_doc(pipeline)
        assert paths == []
