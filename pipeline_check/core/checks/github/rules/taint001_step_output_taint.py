"""TAINT-001. Untrusted input flows across step boundaries via step outputs.

GHA-003 already catches *direct* interpolation of
``${{ github.event.* }}`` inside a single ``run:`` body, plus
indirect taint through workflow / job / step ``env:`` inheritance
within that same step. What it doesn't catch is the multi-step
case:

  - name: extract
    id: extract
    run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT

  - name: use
    run: |
      echo "${{ steps.extract.outputs.title }}" | grep something

The ``extract`` step does write a tainted value to ``$GITHUB_OUTPUT``
(GHA-003 catches the inner ``${{ github.event.issue.title }}``
interpolation there). But the ``use`` step references a benign-
looking ``steps.extract.outputs.title`` token whose payload is
attacker-controlled, and *that* injection is what an attacker
actually exploits.

The detector here is a thin wrapper over the per-workflow taint
graph (``_taint_graph.analyze_workflow``). Every cross-step taint
path that lands in a ``run:`` or ``with:`` body emits a finding,
the description carries the full ``source → step.output → sink``
chain so a reader can audit all three locations at once.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_workflow

RULE = Rule(
    id="TAINT-001",
    title="Untrusted input flows across step boundaries via step outputs",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitise the value at the step that *writes* the "
        "``$GITHUB_OUTPUT`` entry. The canonical pattern is to "
        "interpolate the untrusted source into an ``env:`` "
        "variable on the producer step and reference the env var "
        "in the ``echo``: ``env: TITLE: ${{ github.event.issue."
        "title }}`` then ``echo \"title=$TITLE\" >> "
        "$GITHUB_OUTPUT``. After that, downstream steps reading "
        "``steps.<id>.outputs.title`` see a string-typed value "
        "with no GitHub-expression evaluation pass left to "
        "exploit. Removing the source entirely is the safest "
        "fix; if the value genuinely needs to flow downstream, "
        "round-trip it through an env var the way GHA-003 "
        "recommends so the shell quoting still applies."
    ),
    docs_note=(
        "GHA-003 detects the *direct* interpolation case "
        "(``${{ github.event.* }}`` inside a ``run:`` body) and "
        "the *single-step* env-inheritance case. TAINT-001 fills "
        "the cross-step gap: a producer step sets a tainted "
        "step output, and a consumer step (in the same job) "
        "interpolates it via ``${{ steps.<id>.outputs.<name> }}``. "
        "The producer's interpolation is GHA-003's finding; "
        "TAINT-001's finding lives at the consumer (the actual "
        "injection sink) and carries the full chain in its "
        "description so a reader sees both sides at once.\n\n"
        "v1 limitations: only same-job step outputs are tracked; "
        "``jobs.<id>.outputs.*`` (cross-job propagation) and "
        "reusable-workflow input/output forwarding are tracked "
        "as future work in ``ROADMAP.md``. The producer pass "
        "matches the canonical ``echo \"name=...\" >> "
        "$GITHUB_OUTPUT`` shape and the legacy ``::set-output "
        "name=...::`` workflow-command form."
    ),
    known_fp=(
        "If the producer step deliberately runs a sanitiser "
        "between the interpolation and the ``$GITHUB_OUTPUT`` "
        "write (``echo \"$TITLE\" | tr -dc 'a-zA-Z0-9 ' >> "
        "$GITHUB_OUTPUT``), the consumer is no longer "
        "exploitable. The rule's regex doesn't model that "
        "transformation and will still fire; suppress via "
        "ignore-file scoped to the consumer step name when "
        "this is the deliberate shape. The producer's GHA-003 "
        "finding then carries the residual signal that the "
        "sanitiser is load-bearing.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # TAINT-001 is the single-job case: source step output -> sink
    # step in the same job. Cross-job propagation is TAINT-002's
    # territory; reusable-workflow forwarding is TAINT-003's. The
    # path classifier here is hop length plus the absence of the
    # ``with.`` marker that TAINT-003's pass-4 emits.
    same_job_paths = [
        p for p in analyze_workflow(doc)
        if len(p.hops) == 1 and not p.hops[0].startswith("jobs.")
    ]
    if not same_job_paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No cross-step taint path detected via "
                "``$GITHUB_OUTPUT`` propagation within a single job."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in same_job_paths]
    desc = (
        f"{len(same_job_paths)} cross-step taint path(s) reach a "
        f"downstream sink in the same job: "
        f"{'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    # Extract the sink-side job IDs so chain rules can intersect them
    # with deploy / privileged-step job sets to confirm reachability.
    # ``sink_location`` is ``job_id[step_idx]``, the prefix before
    # ``[`` is the job ID. Preserve order, drop duplicates.
    anchor_jobs: dict[str, None] = {}
    for p in same_job_paths:
        anchor_jobs[p.sink_location.split("[", 1)[0]] = None
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        job_anchors=tuple(anchor_jobs),
        path_evidence=tuple(rendered),
    )
