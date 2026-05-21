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


# Match ``${{ needs.<job>.outputs.<name> }}`` references. Mirrors
# the step-output regex above; same whitespace tolerance and
# capture shape.
_NEEDS_OUTPUT_REF_RE = re.compile(
    r"\$\{\{\s*needs\.(?P<job>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)


def _iter_needs_output_refs(text: str) -> Iterator[tuple[str, str]]:
    """Yield ``(job_id, output_name)`` for each cross-job needs ref."""
    for m in _NEEDS_OUTPUT_REF_RE.finditer(text):
        yield m.group("job"), m.group("output")


# Match ``${{ fromJSON(needs.<job>.outputs.<name>) }}`` — the
# canonical matrix-expansion source. Whitespace inside the call is
# tolerated; the capture pulls the upstream job + output name.
_MATRIX_FROM_NEEDS_RE = re.compile(
    r"\$\{\{\s*fromJSON\s*\(\s*"
    r"needs\.(?P<job>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\.outputs\.(?P<output>[A-Za-z_][A-Za-z0-9_-]*)"
    r"\s*\)\s*\}\}"
)


# Match ``${{ matrix.<axis> }}`` references in run / with bodies.
_MATRIX_AXIS_REF_RE = re.compile(
    r"\$\{\{\s*matrix\.(?P<axis>[A-Za-z_][A-Za-z0-9_-]*)\s*\}\}"
)


def _iter_matrix_axis_refs(text: str) -> Iterator[str]:
    """Yield each ``matrix.<axis>`` consumed in *text*."""
    for m in _MATRIX_AXIS_REF_RE.finditer(text):
        yield m.group("axis")


# Shell reference to an env var (``$NAME`` / ``${NAME}``). Used by
# pass 1's env-bound-taint propagation: when an output write's RHS
# references a tainted env var, the output inherits the env var's
# original taint source.
_ENV_SHELL_REF_RE = re.compile(
    r"\$\{?(?P<name>[A-Z_][A-Z0-9_]*)\}?"
)


def _shell_referenced_env_vars(text: str) -> set[str]:
    """Names of ``$NAME`` / ``${NAME}`` references in *text*."""
    return {m.group("name") for m in _ENV_SHELL_REF_RE.finditer(text)}


def _tainted_env_vars(env_block: Any) -> dict[str, list[str]]:
    """Return ``{env_var_name: [tainted_source_expr, ...]}`` for an
    ``env:`` block whose values reference untrusted context.

    The mapping preserves the original ``${{ ... }}`` expression text
    (with braces stripped) so the path renderer can show the
    workflow author the original source. An env var bound to a value
    that doesn't match the untrusted catalog is omitted.
    """
    out: dict[str, list[str]] = {}
    if not isinstance(env_block, dict):
        return out
    for name, value in env_block.items():
        if not (isinstance(name, str) and isinstance(value, str)):
            continue
        sources = [
            _strip_braces(m.group(0))
            for m in UNTRUSTED_CONTEXT_RE.finditer(value)
        ]
        if sources:
            out[name] = sources
    return out


@dataclass
class _GraphState:
    """Per-workflow taint graph.

    Two kinds of tainted destinations:

      * ``tainted_outputs`` — step outputs published via
        ``$GITHUB_OUTPUT``. Keyed ``job_id -> step_id -> output_name``.
      * ``tainted_job_outputs`` — job-level outputs declared via
        ``jobs.<id>.outputs:`` and consumed in downstream jobs via
        ``${{ needs.<id>.outputs.<name> }}``. Keyed
        ``job_id -> output_name``. A job output inherits taint
        from any step output it references AND from any direct
        ``${{ github.event.* }}`` interpolation in its declared
        value.

    Both maps store the list of original :class:`TaintSource`
    instances so the path renderer can show where the data first
    entered the workflow.
    """

    # ``job_id -> step_id -> output_name -> tainted_sources``
    tainted_outputs: dict[str, dict[str, dict[str, list[TaintSource]]]] = (
        field(default_factory=dict)
    )
    # ``job_id -> output_name -> tainted_sources``
    tainted_job_outputs: dict[str, dict[str, list[TaintSource]]] = (
        field(default_factory=dict)
    )
    # ``job_id -> axis_name -> (upstream_job, upstream_output,
    #                           tainted_sources)`` — set once when
    # ``strategy.matrix.<axis> = fromJSON(needs.<job>.outputs.<name>)``
    # AND that upstream output is in ``tainted_job_outputs``. Consumed
    # by pass 3c.
    tainted_matrix_axes: dict[
        str, dict[str, tuple[str, str, list[TaintSource]]],
    ] = field(default_factory=dict)

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

    def record_job_output(
        self, job_id: str, name: str, sources: list[TaintSource],
    ) -> None:
        bucket = self.tainted_job_outputs.setdefault(job_id, {}).setdefault(
            name, [],
        )
        bucket.extend(sources)

    def lookup_job_output(
        self, job_id: str, name: str,
    ) -> list[TaintSource]:
        return self.tainted_job_outputs.get(job_id, {}).get(name, [])

    def record_matrix_axis(
        self, job_id: str, axis: str,
        upstream_job: str, upstream_output: str,
        sources: list[TaintSource],
    ) -> None:
        self.tainted_matrix_axes.setdefault(job_id, {})[axis] = (
            upstream_job, upstream_output, list(sources),
        )

    def lookup_matrix_axis(
        self, job_id: str, axis: str,
    ) -> tuple[str, str, list[TaintSource]] | None:
        return self.tainted_matrix_axes.get(job_id, {}).get(axis)


# ── Public API ─────────────────────────────────────────────────────────


def analyze_workflow(
    doc: dict[str, Any],
) -> list[TaintPath]:
    """Build a taint graph for *doc* and return every source-to-sink path.

    Three passes:

      1. **Step-output producer pass** — walk every step's ``run:``
         body looking for ``$GITHUB_OUTPUT`` writes whose RHS
         interpolates an untrusted context. Record each tainted
         output in :class:`_GraphState.tainted_outputs`.

      2. **Job-output propagation pass** — walk every job's
         ``outputs:`` mapping. For each ``output_name: <expression>``,
         a job output inherits taint when the expression carries
         either a ``${{ steps.<id>.outputs.<name> }}`` reference
         pointing at a tainted step output, or a direct
         ``${{ github.event.* }}`` interpolation. Recorded in
         :class:`_GraphState.tainted_job_outputs`.

      3. **Consumer pass** — walk every step's ``run:`` and ``with:``
         bodies. Two consumer shapes emit paths:

         - ``${{ steps.<id>.outputs.<name> }}`` whose ``(id, name)``
           was recorded in pass 1 (within the same job). One-hop
           path: ``source -> steps.<id>.outputs.<name> -> sink``.
         - ``${{ needs.<job>.outputs.<name> }}`` whose
           ``(job, name)`` was recorded in pass 2. Two-hop path:
           ``source -> steps.<id>.outputs.<name> ->
           jobs.<job>.outputs.<name> -> sink`` (rendered via
           ``hops``).

    Same-step writes-then-reads inside one ``run:`` body don't fire
    here (the source is in the same step that consumes the output;
    GHA-003 already flags this as direct interpolation). The engine's
    contribution is **across-step** and **across-job** flow.
    """
    if not isinstance(doc, dict):
        return []
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return []

    state = _GraphState()
    paths: list[TaintPath] = []

    # ── Pass 1: collect tainted step outputs. ─────────────────────
    # Taint enters the output write two ways:
    #  (a) direct: the RHS interpolates ``${{ github.event.* }}``.
    #  (b) indirect: the RHS references a shell env var
    #      (``$LABELS`` / ``${LABELS}``) whose step env binds it to
    #      an untrusted source. The matrix-injection shape
    #      (GitHub Security Lab) always takes this indirect route
    #      via the ``env:`` block.
    # Workflow-level env taint also propagates: jobs inherit it.
    wf_env_taint = _tainted_env_vars(doc.get("env"))
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_env_taint = dict(wf_env_taint)
        job_env_taint.update(_tainted_env_vars(job.get("env")))
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
            step_env_taint = dict(job_env_taint)
            step_env_taint.update(_tainted_env_vars(step.get("env")))
            for name, value in _extract_output_writes(run):
                # (a) Direct context interpolation in the RHS.
                for m in UNTRUSTED_CONTEXT_RE.finditer(value):
                    src = TaintSource(
                        expr=_strip_braces(m.group(0)),
                        location=f"{job_id}[{idx}]",
                    )
                    state.record_output(
                        str(job_id), step_id, name, src,
                    )
                # (b) Shell env-var reference in the RHS that points
                # at a tainted env binding.
                referenced = _shell_referenced_env_vars(value)
                for env_name in referenced & step_env_taint.keys():
                    for src_expr in step_env_taint[env_name]:
                        src = TaintSource(
                            expr=src_expr,
                            location=f"{job_id}[{idx}].env.{env_name}",
                        )
                        state.record_output(
                            str(job_id), step_id, name, src,
                        )

    # ── Pass 2: collect tainted job-level outputs. ────────────────
    # ``jobs.<id>.outputs:`` is the canonical channel for surfacing
    # a step output to downstream jobs that ``needs:`` this one.
    # The output value is a string-typed expression; if that
    # expression references a tainted step output OR interpolates
    # a context source directly, the job output inherits the
    # taint.
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        outputs = job.get("outputs")
        if not isinstance(outputs, dict):
            continue
        for output_name, expression in outputs.items():
            if not isinstance(output_name, str):
                continue
            if not isinstance(expression, str):
                continue
            propagated: list[TaintSource] = []
            # Step-output channel.
            for ref_step, ref_output in _iter_step_output_refs(expression):
                propagated.extend(
                    state.lookup_output(str(job_id), ref_step, ref_output),
                )
            # Direct ``${{ github.event.* }}`` channel: if the job
            # output declares the source inline, taint enters here
            # without going through a step output first.
            for m in UNTRUSTED_CONTEXT_RE.finditer(expression):
                propagated.append(TaintSource(
                    expr=_strip_braces(m.group(0)),
                    location=f"{job_id}.outputs.{output_name}",
                ))
            if propagated:
                state.record_job_output(
                    str(job_id), output_name, propagated,
                )

    # ── Pass 2.5: matrix axes fed by ``fromJSON(needs.<job>.outputs.<name>)``.
    # The matrix expansion shape is:
    #   strategy:
    #     matrix:
    #       <axis>: ${{ fromJSON(needs.<job>.outputs.<name>) }}
    # When the upstream job output is tainted (from pass 2), every
    # ``${{ matrix.<axis> }}`` reference in this job's steps becomes a
    # taint sink — the matrix value substitutes attacker-controlled
    # text into the consuming run body. The shape is the GitHub
    # Security Lab "matrix expansion injection" writeup.
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        strategy = job.get("strategy")
        if not isinstance(strategy, dict):
            continue
        matrix = strategy.get("matrix")
        if not isinstance(matrix, dict):
            continue
        for axis_name, axis_value in matrix.items():
            if not (
                isinstance(axis_name, str) and isinstance(axis_value, str)
            ):
                continue
            axis_match = _MATRIX_FROM_NEEDS_RE.search(axis_value)
            if axis_match is None:
                continue
            upstream_job = axis_match.group("job")
            upstream_output = axis_match.group("output")
            sources = state.lookup_job_output(upstream_job, upstream_output)
            if not sources:
                continue
            state.record_matrix_axis(
                str(job_id), axis_name,
                upstream_job, upstream_output, sources,
            )

    # ── Pass 3: detect downstream consumers (single + cross-job). ──
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
                # 3a. Same-job step-output consumer.
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
                # 3b. Cross-job needs.<job>.outputs.<name> consumer.
                for ref_job, ref_output in _iter_needs_output_refs(body):
                    sources = state.lookup_job_output(ref_job, ref_output)
                    if not sources:
                        continue
                    for src in sources:
                        paths.append(TaintPath(
                            source=src,
                            hops=(
                                f"steps.<producer>.outputs.{ref_output}",
                                f"jobs.{ref_job}.outputs.{ref_output}",
                            ),
                            sink_location=f"{job_id}[{idx}]",
                            sink_consumer=(
                                f"needs.{ref_job}.outputs.{ref_output}"
                            ),
                        ))
                # 3c. ``${{ matrix.<axis> }}`` consumer where the
                # axis was tainted in pass 2.5. The hops chain shows
                # the full producer -> job output -> fromJSON ->
                # matrix axis -> sink path so the reader sees the
                # whole expansion.
                for axis_ref in _iter_matrix_axis_refs(body):
                    bound = state.lookup_matrix_axis(str(job_id), axis_ref)
                    if bound is None:
                        continue
                    upstream_job, upstream_output, sources = bound
                    for src in sources:
                        paths.append(TaintPath(
                            source=src,
                            hops=(
                                f"steps.<producer>.outputs.{upstream_output}",
                                f"jobs.{upstream_job}.outputs.{upstream_output}",
                                f"strategy.matrix.{axis_ref} = "
                                f"fromJSON(needs.{upstream_job}."
                                f"outputs.{upstream_output})",
                            ),
                            sink_location=f"{job_id}[{idx}]",
                            sink_consumer=f"matrix.{axis_ref}",
                        ))

    # ── Pass 4: detect tainted ``with:`` forward into reusable
    # workflows. A job that uses ``uses: <callee>.yml`` and passes
    # ``${{ github.event.* }}`` (or a tainted step / job output) as
    # a ``with:`` input value is forwarding tainted data across the
    # reusable-workflow boundary. The callee may consume it via
    # ``${{ inputs.<name> }}`` in a ``run:`` body, which is the
    # actual injection sink, but caller-side analysis is enough to
    # flag the surface for review even when the callee body isn't
    # in the scan. ``hops`` carries a synthetic
    # ``with.<input>@uses:<callee>`` marker so TAINT-003's rule
    # layer can partition these paths from same-job / cross-job
    # ones (hop count == 1, but the synthetic ``uses:`` tag in the
    # sink_consumer string lets the rule key off the prefix).
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        callee = job.get("uses")
        if not isinstance(callee, str) or not callee.strip():
            continue
        with_block = job.get("with")
        if not isinstance(with_block, dict):
            continue
        for input_name, expression in with_block.items():
            if not isinstance(input_name, str):
                continue
            if not isinstance(expression, str):
                continue
            forward_sources: list[TaintSource] = []
            # Direct ``${{ github.event.* }}`` interpolation in the
            # forwarded value.
            for m in UNTRUSTED_CONTEXT_RE.finditer(expression):
                forward_sources.append(TaintSource(
                    expr=_strip_braces(m.group(0)),
                    location=f"{job_id}.with.{input_name}",
                ))
            # Indirect: forwarding a tainted step output or
            # cross-job ``needs.<job>.outputs.<name>``. Both
            # channels are already mapped in the engine state.
            for ref_step, ref_output in _iter_step_output_refs(expression):
                forward_sources.extend(
                    state.lookup_output(str(job_id), ref_step, ref_output),
                )
            for ref_job, ref_output in _iter_needs_output_refs(expression):
                forward_sources.extend(
                    state.lookup_job_output(ref_job, ref_output),
                )
            for src in forward_sources:
                paths.append(TaintPath(
                    source=src,
                    hops=(
                        f"jobs.{job_id}.with.{input_name}",
                    ),
                    sink_location=f"uses:{callee.strip()}",
                    sink_consumer=(
                        f"inputs.{input_name}@{callee.strip()}"
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
