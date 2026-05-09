"""Tests for the Argo Workflows dataflow / taint-path engine + TAINT-007."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.argo._taint_graph import (
    analyze_workflow_doc,
)
from pipeline_check.core.checks.argo.base import (
    ArgoContext,
    ArgoDoc,
)
from pipeline_check.core.checks.argo.rules import (
    taint007_outputs_taint as t7,
)


def _doc(yaml_text: str) -> ArgoDoc:
    data = yaml.safe_load(yaml_text)
    return ArgoDoc(
        path="wf.yaml",
        doc_index=0,
        api_version=str(data.get("apiVersion", "")),
        kind=str(data.get("kind", "")),
        name=str((data.get("metadata") or {}).get("name", "")),
        namespace=str((data.get("metadata") or {}).get("namespace", "")),
        data=data,
    )


# ── Engine: analyze_workflow_doc ───────────────────────────────────


class TestEngineProducer:
    def test_detects_canonical_outputs_propagation(self) -> None:
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: build
spec:
  entrypoint: main
  templates:
    - name: main
      dag:
        tasks:
          - name: extract
            template: extract-tpl
          - name: build
            depends: extract
            template: build-tpl
            arguments:
              parameters:
                - name: title
                  value: "{{tasks.extract.outputs.parameters.clean}}"
    - name: extract-tpl
      inputs:
        parameters:
          - name: title
      outputs:
        parameters:
          - name: clean
            valueFrom:
              path: /tmp/clean
      script:
        image: alpine
        source: |
          echo "{{inputs.parameters.title}}" > /tmp/clean
    - name: build-tpl
      inputs:
        parameters:
          - name: title
      script:
        image: alpine
        source: |
          echo {{inputs.parameters.title}}
""")
        paths = analyze_workflow_doc(doc)
        assert len(paths) == 1
        assert paths[0].source.expr == "title"

    def test_returns_empty_for_doc_without_spec(self) -> None:
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: empty
""")
        assert analyze_workflow_doc(doc) == []


class TestEngineConsumer:
    def test_zero_paths_when_no_consumer(self) -> None:
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  templates:
    - name: only
      outputs:
        parameters:
          - name: clean
            valueFrom:
              path: /tmp/x
      script:
        image: alpine
        source: |
          echo "{{inputs.parameters.title}}" > /tmp/x
""")
        assert analyze_workflow_doc(doc) == []

    def test_zero_paths_when_consumer_does_not_reference_param(self) -> None:
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  templates:
    - name: main
      dag:
        tasks:
          - name: extract
            template: extract-tpl
          - name: build
            depends: extract
            template: build-tpl
            arguments:
              parameters:
                - name: title
                  value: "{{tasks.extract.outputs.parameters.clean}}"
    - name: extract-tpl
      outputs:
        parameters:
          - name: clean
            valueFrom:
              path: /tmp/x
      script:
        image: alpine
        source: |
          echo "{{inputs.parameters.title}}" > /tmp/x
    - name: build-tpl
      script:
        image: alpine
        source: |
          echo unrelated-text
""")
        assert analyze_workflow_doc(doc) == []


class TestEngineMultiplePaths:
    def test_one_path_per_distinct_consumer_match(self) -> None:
        # Two consumer steps using the same param.
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  templates:
    - name: main
      dag:
        tasks:
          - name: extract
            template: extract-tpl
          - name: build
            template: build-tpl
            arguments:
              parameters:
                - name: title
                  value: "{{tasks.extract.outputs.parameters.clean}}"
    - name: extract-tpl
      outputs:
        parameters:
          - name: clean
            valueFrom:
              path: /tmp/x
      script:
        image: alpine
        source: |
          echo "{{inputs.parameters.title}}" > /tmp/x
    - name: build-tpl
      inputs:
        parameters:
          - name: title
      script:
        image: alpine
        source: |
          echo {{inputs.parameters.title}}
          echo {{inputs.parameters.title}} > /tmp/y
""")
        paths = analyze_workflow_doc(doc)
        # One match per occurrence of {{inputs.parameters.title}}
        # in the consumer template's script.
        assert len(paths) == 2

    def test_steps_orchestrator_works_too(self) -> None:
        # Argo supports both ``dag:`` and ``steps:``. The engine
        # walks both shapes via ``_iter_orchestrator_tasks``.
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  templates:
    - name: main
      steps:
        - - name: extract
            template: extract-tpl
        - - name: build
            template: build-tpl
            arguments:
              parameters:
                - name: title
                  value: "{{tasks.extract.outputs.parameters.clean}}"
    - name: extract-tpl
      outputs:
        parameters:
          - name: clean
            valueFrom:
              path: /tmp/x
      script:
        image: alpine
        source: |
          echo "{{inputs.parameters.title}}" > /tmp/x
    - name: build-tpl
      inputs:
        parameters:
          - name: title
      script:
        image: alpine
        source: |
          echo {{inputs.parameters.title}}
""")
        paths = analyze_workflow_doc(doc)
        assert len(paths) == 1


# ── TAINT-007 rule wrapper ─────────────────────────────────────────


def _ctx(*docs: ArgoDoc) -> ArgoContext:
    return ArgoContext(list(docs))


class TestTAINT007:
    def test_passes_when_no_argo_doc_in_context(self) -> None:
        # Empty context.
        f = t7.check(_ctx())
        assert f.passed
        assert "No Argo workflow documents" in f.description

    def test_passes_when_no_taint_path(self) -> None:
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  templates:
    - name: only
      script:
        image: alpine
        source: echo hi
""")
        f = t7.check(_ctx(doc))
        assert f.passed

    def test_fails_with_path_in_description(self) -> None:
        doc = _doc("""
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: w
spec:
  templates:
    - name: main
      dag:
        tasks:
          - name: extract
            template: extract-tpl
          - name: build
            template: build-tpl
            arguments:
              parameters:
                - name: title
                  value: "{{tasks.extract.outputs.parameters.clean}}"
    - name: extract-tpl
      outputs:
        parameters:
          - name: clean
            valueFrom:
              path: /tmp/x
      script:
        image: alpine
        source: |
          echo "{{inputs.parameters.title}}" > /tmp/x
    - name: build-tpl
      inputs:
        parameters:
          - name: title
      script:
        image: alpine
        source: |
          echo {{inputs.parameters.title}}
""")
        f = t7.check(_ctx(doc))
        assert not f.passed
        assert "1 cross-template taint path" in f.description
        assert "outputs.parameters" in f.description
