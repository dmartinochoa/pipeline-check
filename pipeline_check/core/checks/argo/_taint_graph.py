"""Per-workflow taint graph for the Argo Workflows dataflow rules.

The Argo analogue of the GHA / GitLab / Buildkite / Tekton
engines. ``ARGO-005`` already catches direct interpolation of
``{{inputs.parameters.<X>}}`` into a template's script body. The
cross-template gap is Argo's
``{{tasks.<task>.outputs.parameters.<output>}}`` substitution
(equivalent to Tekton's results channel):

  apiVersion: argoproj.io/v1alpha1
  kind: Workflow
  spec:
    arguments:
      parameters:
        - name: pr-title
    entrypoint: main
    templates:
      - name: main
        dag:
          tasks:
            - name: extract
              template: extract-tpl
              arguments:
                parameters:
                  - name: title
                    value: "{{workflow.parameters.pr-title}}"
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
                                                # ^^ ARGO-005 fires
      - name: build-tpl
        inputs:
          parameters:
            - name: title
        script:
          image: alpine
          source: |
            echo {{inputs.parameters.title}}
                 # ^^ TAINT-007 catches the cross-template injection

ARGO-005 catches the producer template's inner interpolation.
TAINT-007 catches the actual injection at the consumer
template's script.

Scope: same-document Workflow analysis. v1 limitations:

  * ``workflowTemplateRef:`` cross-document references are not
    followed (would need machinery like the GHA
    ``--resolve-remote`` flow);
  * ``steps:`` template orchestrators (alternative to ``dag:``)
    are walked the same way; both surface ``arguments.parameters``;
  * ``onExit:`` and exit handlers aren't yet tracked;
  * artifact-based propagation (``artifacts.parameters``,
    different shape) is out of scope for this v1.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .base import ArgoDoc, iter_templates, workflow_spec


@dataclass(frozen=True, slots=True)
class TaintSource:
    """One untrusted-input expression detected in the workflow."""

    expr: str
    location: str


@dataclass(frozen=True, slots=True)
class TaintPath:
    """A computed source-to-sink path through the Argo workflow."""

    source: TaintSource
    hops: tuple[str, ...]
    sink_location: str
    sink_consumer: str

    def render(self) -> str:
        chain: list[str] = [
            f"{{{{inputs.parameters.{self.source.expr}}}}}@"
            f"{self.source.location}",
        ]
        chain.extend(self.hops)
        chain.append(f"sink@{self.sink_location}({self.sink_consumer})")
        return " -> ".join(chain)


# ── Detectors ─────────────────────────────────────────────────────


# ``{{inputs.parameters.<name>}}`` reference. Argo substitutes
# these before the shell parses; identical risk shape to
# ``$(params.X)`` in Tekton.
_INPUTS_PARAM_RE = re.compile(
    r"\{\{\s*inputs\.parameters\.(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)

# ``{{tasks.<task>.outputs.parameters.<output>}}`` cross-task
# substitution that forward a template's output parameter into
# a downstream task's argument list.
_TASKS_OUT_REF_RE = re.compile(
    r"\{\{\s*tasks\.(?P<task>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.parameters\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\s*\}\}"
)


def _iter_input_param_refs(text: str) -> Iterator[str]:
    """Yield every ``{{inputs.parameters.<name>}}`` reference name."""
    for m in _INPUTS_PARAM_RE.finditer(text):
        yield m.group("name")


# ── Engine state ──────────────────────────────────────────────────


@dataclass
class _GraphState:
    """Per-workflow taint graph.

    ``leaks`` maps ``(template_name, output_name)`` to the input
    parameters whose values flowed into that output. ``template_to_task``
    maps the template's name to every task name that uses it via
    ``template:``, so consumer-side detection can resolve which
    task entries are using which template.
    """

    leaks: dict[str, dict[str, list[TaintSource]]] = field(
        default_factory=dict,
    )

    def record(
        self,
        template: str,
        output: str,
        source: TaintSource,
    ) -> None:
        self.leaks.setdefault(template, {}).setdefault(output, []).append(
            source,
        )

    def lookup(self, template: str, output: str) -> list[TaintSource]:
        return self.leaks.get(template, {}).get(output, [])


# ── Public API ────────────────────────────────────────────────────


def analyze_workflow_doc(doc: ArgoDoc) -> list[TaintPath]:
    """Build a taint graph for *doc* and return every source-to-sink path.

    The doc must declare ``spec.templates`` (Workflow,
    WorkflowTemplate, ClusterWorkflowTemplate, or CronWorkflow).
    Other shapes return ``[]``.

    Detection is a three-pass walk:

      1. **Producer pass** — for each template with
         ``outputs.parameters`` declared, classify its inline
         ``script.source`` for ``{{inputs.parameters.<X>}}``
         references. Tainted templates record
         ``(template_name, output_name) -> sources``.

      2. **Forwarding pass** — for each task in any
         ``dag.tasks`` / ``steps`` orchestrator, find arguments
         whose value is
         ``{{tasks.<producer>.outputs.parameters.<X>}}`` matching
         a recorded leak. Build a map of ``(consumer_task_name,
         consumer_template, consumer_param_name) -> sources``.

      3. **Consumer pass** — for each tainted argument, walk the
         consumer template's ``script.source`` for
         ``{{inputs.parameters.<consumer_param>}}`` references
         and emit a path per match.
    """
    spec = workflow_spec(doc)
    if not spec:
        return []

    # ── Build a name -> template index up front so passes 2 and
    # 3 can resolve template references in O(1).
    templates_by_name: dict[str, dict[str, Any]] = {}
    for tpl in iter_templates(doc):
        nm = tpl.get("name")
        if isinstance(nm, str):
            templates_by_name[nm] = tpl

    state = _GraphState()
    paths: list[TaintPath] = []

    # ── Build a task -> template lookup. ──────────────────────
    # Cross-task references in arguments are keyed by *task* name
    # (``{{tasks.<task>.outputs...}}``), but the producer pass
    # below records leaks by *template* name (because templates
    # are the unit of script analysis). We need to resolve a
    # task name to its template's leak set, so build the map up
    # front.
    task_to_template: dict[str, str] = {}
    for tpl in iter_templates(doc):
        for task in _iter_orchestrator_tasks(tpl):
            task_nm = task.get("name")
            tpl_nm = task.get("template")
            if isinstance(task_nm, str) and isinstance(tpl_nm, str):
                task_to_template[task_nm] = tpl_nm

    # ── Pass 1: producers. ────────────────────────────────────
    for tpl in iter_templates(doc):
        nm = tpl.get("name")
        if not isinstance(nm, str):
            continue
        outputs = tpl.get("outputs")
        if not isinstance(outputs, dict):
            continue
        out_params = outputs.get("parameters")
        if not isinstance(out_params, list):
            continue
        # Output parameter names declared by this template.
        output_names: list[str] = [
            p["name"] for p in out_params
            if isinstance(p, dict) and isinstance(p.get("name"), str)
        ]
        if not output_names:
            continue
        # Walk the template's script body for input-parameter
        # references; if any are present, the output parameters
        # inherit taint. (We don't model which output absorbs
        # which input, the producer leaks every declared output
        # under every interpolated input.)
        script = tpl.get("script")
        if not isinstance(script, dict):
            continue
        source_text = script.get("source")
        if not isinstance(source_text, str):
            continue
        param_refs = list(_iter_input_param_refs(source_text))
        if not param_refs:
            continue
        for output_name in output_names:
            for input_name in param_refs:
                state.record(
                    nm,
                    output_name,
                    TaintSource(
                        expr=input_name,
                        location=f"{nm}.script",
                    ),
                )

    # ── Pass 2: forwarding (dag/steps orchestrators). ────────
    # Map ``(consumer_task_name, consumer_template_name,
    # consumer_param_name)`` to the inherited taint sources.
    tainted_args: dict[
        tuple[str, str, str], list[TaintSource],
    ] = {}
    for tpl in iter_templates(doc):
        for task in _iter_orchestrator_tasks(tpl):
            consumer_template = task.get("template")
            consumer_task_name = task.get("name")
            if (
                not isinstance(consumer_template, str)
                or not isinstance(consumer_task_name, str)
            ):
                continue
            args = task.get("arguments")
            if not isinstance(args, dict):
                continue
            arg_params = args.get("parameters")
            if not isinstance(arg_params, list):
                continue
            for ap in arg_params:
                if not isinstance(ap, dict):
                    continue
                ap_name = ap.get("name")
                ap_value = ap.get("value")
                if (
                    not isinstance(ap_name, str)
                    or not isinstance(ap_value, str)
                ):
                    continue
                for m in _TASKS_OUT_REF_RE.finditer(ap_value):
                    # Resolve the task name to its template, then
                    # look up the leak under that template.
                    producer_task = m.group("task")
                    producer_template = task_to_template.get(producer_task)
                    if not producer_template:
                        continue
                    sources = state.lookup(
                        producer_template, m.group("output"),
                    )
                    if sources:
                        key = (
                            consumer_task_name,
                            consumer_template,
                            ap_name,
                        )
                        tainted_args.setdefault(key, []).extend(sources)

    # ── Pass 3: consumers. ────────────────────────────────────
    for (
        consumer_task_name,
        consumer_template_name,
        consumer_param_name,
    ), sources in tainted_args.items():
        consumer_tpl = templates_by_name.get(consumer_template_name)
        if not isinstance(consumer_tpl, dict):
            continue
        script = consumer_tpl.get("script")
        if not isinstance(script, dict):
            continue
        source_text = script.get("source")
        if not isinstance(source_text, str):
            continue
        for ref_name in _iter_input_param_refs(source_text):
            if ref_name != consumer_param_name:
                continue
            for src in sources:
                paths.append(TaintPath(
                    source=src,
                    hops=(
                        "tasks.<producer>.outputs.parameters.<output>",
                        (
                            f"tasks.{consumer_task_name}"
                            f".arguments.{consumer_param_name}"
                        ),
                    ),
                    sink_location=(
                        f"{consumer_template_name}.script"
                    ),
                    sink_consumer=(
                        f"{{{{inputs.parameters.{consumer_param_name}}}}}"
                    ),
                ))
    return paths


def _iter_orchestrator_tasks(
    template: dict[str, Any],
) -> Iterator[dict[str, Any]]:
    """Yield every task entry inside a template's orchestrator block.

    Argo templates can be DAGs (``dag.tasks``) or step lists
    (``steps``), and the step list itself nests as a list of
    parallel-step lists. Both shapes carry the same per-task
    structure: ``name`` / ``template`` / ``arguments``.
    """
    dag = template.get("dag")
    if isinstance(dag, dict):
        tasks = dag.get("tasks")
        if isinstance(tasks, list):
            for task in tasks:
                if isinstance(task, dict):
                    yield task
    steps = template.get("steps")
    if isinstance(steps, list):
        for parallel_group in steps:
            if isinstance(parallel_group, list):
                for step in parallel_group:
                    if isinstance(step, dict):
                        yield step


__all__ = [
    "TaintPath",
    "TaintSource",
    "analyze_workflow_doc",
]
