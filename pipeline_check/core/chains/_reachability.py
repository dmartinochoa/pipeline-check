"""Dataflow reachability for attack chains (phase 2).

Phase 1 of the reachability work confirmed a chain by intersecting the
two legs' ``Finding.job_anchors``: if the injection leg and the impact
leg fired in the same job, the chain was "confirmed reachable". That's a
coarse co-location signal, it can't follow untrusted data from a source
in one job to a sink in another, and it can't tell a real
producer->consumer flow from two unrelated findings that happen to share
a job name.

Phase 2 walks the actual taint graph. The TAINT-NNN rules now expose
their source-to-sink edges as :class:`~pipeline_check.core.checks.base.TaintFlow`
records on each finding (``source_job -> sink_job`` plus the rendered
path). :func:`assess_reachability` builds a directed graph from those
edges and asks: starting from the injection leg's job(s), can untrusted
data reach the impact leg's job(s) by following one or more taint flows?
A hit is a *confirmed dataflow path* and carries the exact connecting
path string for the report. When no dataflow path exists the helper
falls back to the phase-1 shared-job signal so nothing the older chains
detected is regressed.

The graph is per-resource: taint flows only connect jobs inside one
workflow document, so callers pass the TAINT findings for a single
resource alongside that resource's two legs.
"""
from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..checks.base import Finding, TaintFlow


@dataclass(frozen=True, slots=True)
class Reachability:
    """Outcome of a reachability assessment between two chain legs.

    ``confirmed`` is the phase-1-compatible boolean a chain sets on
    ``Chain.confirmed_reachable``. ``via_dataflow`` distinguishes the
    stronger phase-2 result (a real source-to-sink taint path was found)
    from the weaker shared-job co-location fallback. ``path`` is the
    rendered connecting taint path when ``via_dataflow`` is true (empty
    otherwise); ``shared_jobs`` lists the jobs both legs occupy when the
    fallback fired. ``note`` is a one-line human rationale for the
    report.
    """

    confirmed: bool
    via_dataflow: bool
    note: str
    path: str = ""
    shared_jobs: tuple[str, ...] = field(default_factory=tuple)


def _collect_flows(taint_findings: Iterable[Finding]) -> list[TaintFlow]:
    """Flatten the taint flows carried by *taint_findings*."""
    flows: list[TaintFlow] = []
    for f in taint_findings:
        flows.extend(f.taint_flows)
    return flows


def _dataflow_path(
    flows: list[TaintFlow],
    source_jobs: set[str],
    sink_jobs: set[str],
) -> tuple[list[str], str] | None:
    """Return ``(job_path, rendered)`` if untrusted data reaches a sink.

    Builds a directed graph of ``source_job -> sink_job`` edges from
    *flows* and breadth-first searches from every job in *source_jobs*
    for any job in *sink_jobs*. Multi-hop is supported: one flow's sink
    feeding another flow's source chains into a longer path. Returns the
    job sequence plus the rendered taint path of the *final* edge (the
    one that lands in the sink) for the report, or ``None`` when no path
    exists.

    Self-edges (``source_job == sink_job``, the common single-job
    producer/consumer flow) count: if the source job is also a sink job
    the flow already connects the two legs.
    """
    if not flows or not source_jobs or not sink_jobs:
        return None

    adj: dict[str, list[TaintFlow]] = defaultdict(list)
    for fl in flows:
        adj[fl.source_job].append(fl)

    # Direct hit: a flow whose source is a source-leg job and whose sink
    # is a sink-leg job (covers the same-job self-edge case too).
    for fl in flows:
        if fl.source_job in source_jobs and fl.sink_job in sink_jobs:
            return [fl.source_job, fl.sink_job], fl.rendered

    # Multi-hop BFS over chained flows.
    seen: set[str] = set(source_jobs)
    # queue carries (current_job, job_path, last_rendered)
    queue: deque[tuple[str, list[str], str]] = deque(
        (j, [j], "") for j in sorted(source_jobs)
    )
    while queue:
        job, jpath, _last = queue.popleft()
        for fl in adj.get(job, ()):
            nxt = fl.sink_job
            if nxt in sink_jobs:
                return [*jpath, nxt], fl.rendered
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, [*jpath, nxt], fl.rendered))
    return None


def assess_reachability(
    taint_findings: Iterable[Finding],
    source_jobs: Iterable[str],
    sink_jobs: Iterable[str],
) -> Reachability:
    """Assess whether the injection leg can reach the impact leg.

    Prefers a phase-2 dataflow path (an executable source-to-sink taint
    connection) and falls back to the phase-1 shared-job signal.

    Parameters
    ----------
    taint_findings:
        The TAINT-NNN findings for the resource under analysis (they
        carry the :class:`TaintFlow` edges). Pass an empty iterable when
        the provider has no taint engine; the helper degrades to the
        shared-job check.
    source_jobs:
        Job anchors of the injection / untrusted-input leg.
    sink_jobs:
        Job anchors of the impact leg (deploy, privileged step, …).
    """
    src = {j for j in source_jobs if j}
    dst = {j for j in sink_jobs if j}
    flows = _collect_flows(taint_findings)

    hit = _dataflow_path(flows, src, dst)
    if hit is not None:
        job_path, rendered = hit
        chain_repr = " -> ".join(f"`{j}`" for j in job_path)
        note = (
            f"untrusted input reaches the sink via a taint path "
            f"({chain_repr})"
        )
        return Reachability(
            confirmed=True, via_dataflow=True, note=note, path=rendered,
        )

    shared = tuple(sorted(src & dst))
    if shared:
        shared_repr = ", ".join(f"`{j}`" for j in shared)
        return Reachability(
            confirmed=True,
            via_dataflow=False,
            note=f"injection and sink share job {shared_repr}",
            shared_jobs=shared,
        )

    return Reachability(confirmed=False, via_dataflow=False, note="")
