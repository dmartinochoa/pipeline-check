"""Per-workflow taint graph for the GHA dataflow rules.

Generalises the per-step pattern matching that ``GHA-003`` does
(direct interpolation + env-inherited taint within a single step)
to a workflow-wide reachability problem:

  source -> propagator -> ... -> sink

Sources are the well-known author-controllable context expressions
(``github.event.issue.title``, ``head_ref``, etc.). Propagators are
shapes that move data without modifying it: workflow / job / step
``env:`` blocks, and ``$GITHUB_OUTPUT`` writes that publish a step
output. Sinks are the security-critical operations that the
existing ``run:`` rule already cares about, plus the *downstream*
``run:`` blocks that reference a tainted step output.

The engine is deliberately small. It does NOT model:

  * job outputs (``jobs.<id>.outputs.*``) — flagged for v2 once the
    cross-step shape is validated;
  * reusable-workflow inputs / secrets — already partly handled by
    the resolver, taint propagation across the boundary is out
    of scope for this v1;
  * ``if:`` expression sinks — the ``if:`` evaluator runs in a
    sandbox; even tainted booleans there are gated by GitHub's
    own expression parser, not by the shell;
  * ``with:`` parameter sinks for arbitrary actions — the
    actions/github-script case is a sink in practice, but the
    surface across every action is too large for the v1 catalog;
    GHA-035 already covers the main one.

The data class :class:`TaintPath` carries every concrete path the
engine finds. Rules consume ``analyze_workflow(doc)`` and emit
findings shaped around the paths they care about.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .rules._helpers import UNTRUSTED_CONTEXT_RE


@dataclass(frozen=True, slots=True)
class TaintSource:
    """One untrusted-input expression detected in the workflow.

    ``expr`` is the raw text of the matched ``${{ ... }}`` reference
    (e.g. ``github.event.issue.title``); ``location`` is a
    ``job_id[step_idx]`` breadcrumb that the rule's description
    string interpolates so a reader can find the source quickly.
    """

    expr: str
    location: str


@dataclass(frozen=True, slots=True)
class TaintPath:
    """A computed source-to-sink path through the workflow.

    Carries:

      * the original :class:`TaintSource` (where the untrusted data
        first entered);
      * the chain of propagator hops as human-readable labels
        (``env.MSG``, ``steps.extract.outputs.title``);
      * the sink location (``job_id[step_idx]``) and the consuming
        token in the sink body.

    The narrative shape is the description text the rule emits:
    ``source -> hop1 -> hop2 -> sink``.
    """

    source: TaintSource
    hops: tuple[str, ...]
    sink_location: str
    sink_consumer: str

    def render(self) -> str:
        """One-line ``source -> hop -> ... -> sink`` rendering."""
        chain: list[str] = [
            f"${{{{ {self.source.expr} }}}}@{self.source.location}",
        ]
        chain.extend(self.hops)
        chain.append(f"sink@{self.sink_location}({self.sink_consumer})")
        return " -> ".join(chain)


# ── Step-output write detector ─────────────────────────────────────────


# Match the canonical ``$GITHUB_OUTPUT`` write idiom:
#   echo "name=value" >> $GITHUB_OUTPUT
#   echo "name=value" >> "$GITHUB_OUTPUT"
#   echo "name=value" >> ${GITHUB_OUTPUT}
# Captures the output name and the raw RHS value text. The legacy
# ``::set-output name=foo::value`` workflow-command form is also
# matched as a fallback.
_GITHUB_OUTPUT_WRITE_RE = re.compile(
    r"""
    (?:
        echo\s+
        ["']?(?P<name1>[A-Za-z_][A-Za-z0-9_-]*)=(?P<val1>[^\n]*?)["']?\s*
        >>\s*
        (?:"?\$\{?GITHUB_OUTPUT\}?"?)
    |
        echo\s+
        ["']?
        ::set-output\s+name=(?P<name2>[A-Za-z_][A-Za-z0-9_-]*)::
        (?P<val2>[^\n"']*)
        ["']?
    )
    """,
    re.VERBOSE,
)


def _extract_output_writes(run_body: str) -> list[tuple[str, str]]:
    """Return ``[(output_name, rhs_value), ...]`` for *run_body*.

    Captures both the modern ``>> $GITHUB_OUTPUT`` form and the
    legacy ``::set-output`` workflow-command shape. Defensive
    against malformed scripts: a line that doesn't match either
    shape is silently skipped.
    """
    out: list[tuple[str, str]] = []
    for m in _GITHUB_OUTPUT_WRITE_RE.finditer(run_body):
        name = m.group("name1") or m.group("name2") or ""
        val = m.group("val1") or m.group("val2") or ""
        if name:
            out.append((name, val))
    return out


# ── Step output reference detector ─────────────────────────────────────


# Match ``${{ steps.<step_id>.outputs.<output_name> }}`` references.
# Allow whitespace inside the braces. Captures step id and output
# name for taint resolution.
_STEP_OUTPUT_REF_RE = re.compile(
    r"\$\{\{\s*steps\.(?P<step>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)


def _iter_step_output_refs(text: str) -> Iterator[tuple[str, str]]:
    """Yield ``(step_id, output_name)`` for each step-output reference."""
    for m in _STEP_OUTPUT_REF_RE.finditer(text):
        yield m.group("step"), m.group("output")


# ── Engine state ───────────────────────────────────────────────────────


@dataclass
class _GraphState:
    """Per-workflow taint graph.

    Internal state used during analysis. Each entry maps a
    ``(job_id, step_id, output_name)`` triple to the source(s) whose
    taint reached that output. Multiple sources can taint the same
    output (e.g., a step echoing two interpolated context fields),
    so values are sets.
    """

    # ``job_id -> step_id -> output_name -> tainted_sources``
    tainted_outputs: dict[str, dict[str, dict[str, list[TaintSource]]]] = (
        field(default_factory=dict)
    )

    def record_output(
        self, job_id: str, step_id: str, name: str, source: TaintSource,
    ) -> None:
        outputs = self.tainted_outputs.setdefault(
            job_id, {}
        ).setdefault(step_id, {}).setdefault(name, [])
        outputs.append(source)

    def lookup_output(
        self, job_id: str, step_id: str, name: str,
    ) -> list[TaintSource]:
        return self.tainted_outputs.get(
            job_id, {},
        ).get(step_id, {}).get(name, [])


# ── Public API ─────────────────────────────────────────────────────────


def analyze_workflow(
    doc: dict[str, Any],
) -> list[TaintPath]:
    """Build a taint graph for *doc* and return every source-to-sink path.

    Two passes:

      1. **Producer pass** — walk every step's ``run:`` body looking
         for ``$GITHUB_OUTPUT`` writes whose RHS interpolates an
         untrusted context. Record each tainted output in
         :class:`_GraphState`.

      2. **Consumer pass** — walk every step's ``run:`` body looking
         for ``steps.<id>.outputs.<name>`` references whose
         ``(id, name)`` was recorded in pass 1. Each reference
         emits a :class:`TaintPath` with the source location, the
         step-output hop, and the consuming sink location.

    Same-step writes-then-reads inside one ``run:`` body don't fire
    here (the source is in the same step that consumes the output;
    GHA-003 already flags this as direct interpolation). The engine's
    contribution is **across-step** flow.
    """
    if not isinstance(doc, dict):
        return []
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return []

    state = _GraphState()
    paths: list[TaintPath] = []

    # ── Pass 1: collect tainted step outputs. ─────────────────────
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            step_id = step.get("id")
            if not isinstance(step_id, str) or not step_id:
                continue
            run = step.get("run")
            if not isinstance(run, str) or not run.strip():
                continue
            for name, value in _extract_output_writes(run):
                for m in UNTRUSTED_CONTEXT_RE.finditer(value):
                    src = TaintSource(
                        expr=_strip_braces(m.group(0)),
                        location=f"{job_id}[{idx}]",
                    )
                    state.record_output(
                        str(job_id), step_id, name, src,
                    )

    # ── Pass 2: detect downstream consumers. ──────────────────────
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        if not isinstance(steps, list):
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            this_step_id = step.get("id") if isinstance(
                step.get("id"), str,
            ) else None
            for sink_field in ("run", "with"):
                body = _stringify_field(step.get(sink_field))
                if not body:
                    continue
                for ref_step, ref_output in _iter_step_output_refs(body):
                    if ref_step == this_step_id:
                        # Same-step self-reference, GHA-003 territory.
                        continue
                    sources = state.lookup_output(
                        str(job_id), ref_step, ref_output,
                    )
                    if not sources:
                        continue
                    for src in sources:
                        paths.append(TaintPath(
                            source=src,
                            hops=(
                                f"steps.{ref_step}.outputs.{ref_output}",
                            ),
                            sink_location=f"{job_id}[{idx}]",
                            sink_consumer=(
                                f"steps.{ref_step}.outputs.{ref_output}"
                            ),
                        ))
    return paths


def _strip_braces(token: str) -> str:
    """Render a ``${{ github.event.foo }}`` token as ``github.event.foo``."""
    inner = token.strip()
    if inner.startswith("${{") and inner.endswith("}}"):
        inner = inner[3:-2].strip()
    return inner


def _stringify_field(value: Any) -> str:
    """Coerce a YAML field to a string for regex scanning.

    ``run:`` is always a string; ``with:`` is a dict whose values are
    strings (or coerced to strings). For dicts, concatenate the
    string values so a tainted ``with:`` parameter still gets seen.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(
            v for v in value.values() if isinstance(v, str)
        )
    return ""


__all__ = [
    "TaintPath",
    "TaintSource",
    "analyze_workflow",
]
