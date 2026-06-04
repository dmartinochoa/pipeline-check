"""Tests for the GitHub step-level pipeline-graph builder."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks._yaml_lines import safe_load_yaml_lines
from pipeline_check.core.checks.github._graph import build_graphs


def _ctx(yaml_text: str, path: str = ".github/workflows/ci.yml") -> Any:
    data = safe_load_yaml_lines(yaml_text)
    wf = type("W", (), {"path": path, "data": data})()
    return type("Ctx", (), {"workflows": [wf]})()


def _graph(yaml_text: str):
    return build_graphs(_ctx(yaml_text))[0]


def test_jobs_and_steps_become_nodes():
    g = _graph("""
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: make
""")
    kinds = {n.id: n.kind for n in g.nodes}
    assert kinds["__root__"] == "file"
    assert kinds["build"] == "job"
    assert kinds["build#0"] == "step" and kinds["build#1"] == "step"
    # steps carry their job as parent
    parents = {n.id: n.parent for n in g.nodes}
    assert parents["build#0"] == "build" and parents["build"] == "__root__"


def test_step_labels():
    g = _graph("""
on: push
jobs:
  b:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - run: echo hi
""")
    labels = {n.id: n.label for n in g.nodes if n.kind == "step"}
    assert labels["b#0"] == "Checkout"
    assert labels["b#1"].startswith("run: echo")


def test_needs_string_and_list_forms_make_edges():
    g = _graph("""
on: push
jobs:
  a:
    steps: [{run: a}]
  b:
    needs: a
    steps: [{run: b}]
  c:
    needs: [a, b]
    steps: [{run: c}]
""")
    needs = {(e.src, e.dst) for e in g.edges if e.kind == "needs"}
    assert needs == {("a", "b"), ("a", "c"), ("b", "c")}


def test_sequence_edges_between_consecutive_steps():
    g = _graph("""
on: push
jobs:
  b:
    steps:
      - run: one
      - run: two
      - run: three
""")
    seq = [(e.src, e.dst) for e in g.edges if e.kind == "sequence"]
    assert seq == [("b#0", "b#1"), ("b#1", "b#2")]


def test_line_spans_are_monotonic_and_non_overlapping():
    g = _graph("""
on: push
jobs:
  b:
    steps:
      - run: one
      - run: two
""")
    steps = sorted(
        (n for n in g.nodes if n.kind == "step"), key=lambda n: n.start_line,
    )
    # first step ends before the second begins; the last step extends to EOF.
    assert steps[0].start_line < steps[1].start_line
    assert steps[0].end_line is not None
    assert steps[0].end_line < steps[1].start_line
    assert steps[-1].end_line is None  # last step -> EOF


def test_needs_cycle_does_not_raise():
    # Malformed: a needs b, b needs a. Builder must still produce a graph.
    g = _graph("""
on: push
jobs:
  a:
    needs: b
    steps: [{run: a}]
  b:
    needs: a
    steps: [{run: b}]
""")
    assert {n.id for n in g.nodes} >= {"a", "b"}
    assert len([e for e in g.edges if e.kind == "needs"]) == 2


def test_job_without_steps_is_a_leaf():
    g = _graph("""
on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
""")
    ids = {n.id for n in g.nodes}
    assert "call" in ids
    assert not any(n.kind == "step" for n in g.nodes)


def test_empty_workflow_yields_only_root():
    g = _graph("on: push\n")
    assert [n.kind for n in g.nodes] == ["file"]
