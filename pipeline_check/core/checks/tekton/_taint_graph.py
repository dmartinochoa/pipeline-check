"""Per-pipeline taint graph for the Tekton dataflow rules.

The Tekton analogue of the GHA / GitLab / Buildkite engines.
``TKN-003`` already catches direct interpolation of
``$(params.<name>)`` into a Task's script body within a single
Task. The cross-task gap is Tekton's ``tasks[*].results`` /
``$(tasks.<task-name>.results.<result-name>)`` mechanism,
documented at:

  https://tekton.dev/docs/pipelines/pipelines/#using-results

A producer Task declares a ``results:`` array and writes data
to ``$(results.<name>.path)`` from its script; the producer's
position in a Pipeline forward the result to a downstream Task
via:

  - name: build
    runAfter: [extract]
    params:
      - name: title
        value: "$(tasks.extract.results.clean-title)"
    taskSpec:
      params:
        - name: title
      steps:
        - script: echo $(params.title)         <- taint exits here

The producer's interpolation of ``$(params.X)`` into the result
is TKN-003 territory; the consumer-side ``$(params.title)``
reference looks like an ordinary param substitution until you
trace the ``tasks.<producer>.results.<output>`` chain. The
engine here closes that gap.

Scope: same-document Pipeline analysis (the ``Pipeline`` kind
with inline ``taskSpec:`` definitions). v1 limitations:

  * ``taskRef:`` references to externally-defined Tasks aren't
    followed (would need cross-document resolution like the
    GHA ``--resolve-remote`` flow);
  * ``finally:`` task blocks aren't walked yet (same shape but
    less common);
  * ``when:`` / ``conditions:`` aren't sinks; Tekton's
    expression evaluator is sandboxed.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from .base import TektonDoc


@dataclass(frozen=True, slots=True)
class TaintSource:
    """One untrusted-input expression detected in the pipeline."""

    expr: str
    location: str


@dataclass(frozen=True, slots=True)
class TaintPath:
    """A computed source-to-sink path through the Tekton pipeline."""

    source: TaintSource
    hops: tuple[str, ...]
    sink_location: str
    sink_consumer: str

    def render(self) -> str:
        chain: list[str] = [
            f"$(params.{self.source.expr})@{self.source.location}",
        ]
        chain.extend(self.hops)
        chain.append(f"sink@{self.sink_location}({self.sink_consumer})")
        return " -> ".join(chain)


# ── Detectors ─────────────────────────────────────────────────────


# ``$(params.<name>)`` reference. Tekton substitutes these before
# the shell parses the script, identical risk shape to GHA's
# ``${{ github.event.* }}``.
_PARAMS_REF_RE = re.compile(
    r"\$\(params\.(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\)"
)

# ``$(results.<name>.path)`` write target inside a script body.
# The script writes to this path to leak data via the result.
_RESULTS_WRITE_RE = re.compile(
    r"\$\(results\.(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\.path\)"
)

# ``$(tasks.<task>.results.<output>)`` cross-task reference. Used
# by Pipeline ``tasks[*].params[*].value`` to forward another
# task's result into this task's parameter list.
_TASK_RESULTS_REF_RE = re.compile(
    r"\$\(tasks\.(?P<task>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.results\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)\)"
)


def _iter_params_refs(text: str) -> Iterator[str]:
    """Yield every ``$(params.<name>)`` reference's name in *text*."""
    for m in _PARAMS_REF_RE.finditer(text):
        yield m.group("name")


def _iter_results_writes(script: str) -> Iterator[str]:
    """Yield every ``$(results.<name>.path)`` mentioned in a script body.

    The presence of the path expression is treated as a write
    intent. Tekton's ``results`` mechanism requires the script
    to redirect output to that path; we don't try to match the
    full ``echo ... > $(results.X.path)`` shape because Tekton
    scripts use heredocs, ``tee``, ``printf``, and several other
    redirection forms that would each need their own pattern.
    The presence of the result-path token in the script is a
    strong-enough signal that the script writes to that result.
    """
    for m in _RESULTS_WRITE_RE.finditer(script):
        yield m.group("name")


# ── Engine state ──────────────────────────────────────────────────


@dataclass
class _GraphState:
    """Per-Pipeline taint graph.

    Tracks tainted task results: ``(producer_task_name,
    output_name) -> sources``. Sources are the upstream
    ``$(params.<X>)`` references that flowed into the producer's
    ``$(results.<output>.path)``.
    """

    leaks: dict[str, dict[str, list[TaintSource]]] = field(
        default_factory=dict,
    )

    def record(
        self,
        producer: str,
        output: str,
        source: TaintSource,
    ) -> None:
        bucket = self.leaks.setdefault(producer, {}).setdefault(output, [])
        bucket.append(source)

    def lookup(self, producer: str, output: str) -> list[TaintSource]:
        return self.leaks.get(producer, {}).get(output, [])


# ── Public API ────────────────────────────────────────────────────


def analyze_pipeline_doc(doc: TektonDoc) -> list[TaintPath]:
    """Build a taint graph for *doc* and return every source-to-sink path.

    The doc must be a ``Pipeline``; other kinds (Task / TaskRun /
    PipelineRun / ClusterTask) return ``[]``. Pipelines with
    ``taskRef:`` references to external Tasks are still walked,
    only inline ``taskSpec:`` definitions contribute to the
    producer pass.
    """
    if doc.kind != "Pipeline":
        return []
    spec = doc.data.get("spec")
    if not isinstance(spec, dict):
        return []
    tasks = spec.get("tasks")
    if not isinstance(tasks, list):
        return []

    state = _GraphState()
    paths: list[TaintPath] = []

    # ── Pass 1: producers. ────────────────────────────────────
    # A task is a producer when its inline ``taskSpec.steps[*]``
    # has a ``script:`` that:
    #   1. Mentions ``$(results.<X>.path)`` (write target),
    #   2. Interpolates a ``$(params.<Y>)`` reference (taint source).
    for task in tasks:
        if not isinstance(task, dict):
            continue
        producer_name = task.get("name")
        if not isinstance(producer_name, str) or not producer_name:
            continue
        task_spec = task.get("taskSpec")
        if not isinstance(task_spec, dict):
            continue
        steps = task_spec.get("steps")
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            script = step.get("script")
            if not isinstance(script, str) or not script:
                continue
            results_written = list(_iter_results_writes(script))
            if not results_written:
                continue
            params_referenced = list(_iter_params_refs(script))
            if not params_referenced:
                continue
            for output_name in results_written:
                for param_name in params_referenced:
                    state.record(
                        producer_name,
                        output_name,
                        TaintSource(
                            expr=param_name,
                            location=f"{producer_name}.steps[{idx}]",
                        ),
                    )

    # ── Pass 2: consumers. ────────────────────────────────────
    # A task is a consumer when:
    #   1. It has a param value of the form
    #      ``$(tasks.<producer>.results.<output>)`` AND that
    #      ``(producer, output)`` was recorded in pass 1;
    #   2. Its inline ``taskSpec.steps[*].script`` references
    #      ``$(params.<consumer-param-name>)`` for that param.
    for task in tasks:
        if not isinstance(task, dict):
            continue
        consumer_name = task.get("name")
        if not isinstance(consumer_name, str) or not consumer_name:
            continue
        # Map this task's params: which ones are tainted via
        # ``$(tasks.X.results.Y)`` references, with their source list.
        tainted_consumer_params: dict[str, list[TaintSource]] = {}
        params = task.get("params")
        if isinstance(params, list):
            for p in params:
                if not isinstance(p, dict):
                    continue
                pname = p.get("name")
                pvalue = p.get("value")
                if not isinstance(pname, str) or not isinstance(pvalue, str):
                    continue
                for m in _TASK_RESULTS_REF_RE.finditer(pvalue):
                    sources = state.lookup(
                        m.group("task"), m.group("output"),
                    )
                    if sources:
                        tainted_consumer_params.setdefault(
                            pname, [],
                        ).extend(sources)
        if not tainted_consumer_params:
            continue
        # Walk the inline taskSpec for sinks.
        task_spec = task.get("taskSpec")
        if not isinstance(task_spec, dict):
            continue
        steps = task_spec.get("steps")
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            script = step.get("script")
            if not isinstance(script, str) or not script:
                continue
            for ref_name in _iter_params_refs(script):
                if ref_name not in tainted_consumer_params:
                    continue
                for src in tainted_consumer_params[ref_name]:
                    paths.append(TaintPath(
                        source=src,
                        hops=(
                            "tasks.<producer>.results.<output>",
                            f"tasks.{consumer_name}.params.{ref_name}",
                        ),
                        sink_location=(
                            f"{consumer_name}.steps[{idx}]"
                        ),
                        sink_consumer=f"$(params.{ref_name})",
                    ))
    return paths


__all__ = [
    "TaintPath",
    "TaintSource",
    "analyze_pipeline_doc",
]
