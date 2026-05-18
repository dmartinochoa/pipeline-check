"""TAINT-002. Untrusted input flows across jobs via ``jobs.<id>.outputs:``.

The cross-job sibling of TAINT-001. ``jobs.<id>.outputs:`` is the
canonical channel for surfacing a step output to a downstream job
that ``needs:`` the producing one. The hop reads:

  source                                 (e.g. github.event.issue.title)
    -> steps.<producer>.outputs.<name>   (intra-job step output)
    -> jobs.<producer-job>.outputs.<n>   (job-level export)
    -> needs.<producer-job>.outputs.<n>  (consumer reference)
    -> sink                              (run / with body)

GHA-003 catches the producer step's interpolation. TAINT-001
catches the same-job step-output flow. TAINT-002 catches the
cross-job version, which is the more common pattern in real
workflows: an "extract" job pulls untrusted metadata into outputs
and a "build" / "deploy" job consumes them via ``needs.extract``.
The shape that bit Salesforce / TJ-Action / numerous other CI
incidents always involved this cross-job transition because the
write-step and read-step are usually owned by different teams,
and the audit needs to traverse the ``jobs.X.outputs:`` boundary
to see the connection.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_workflow

RULE = Rule(
    id="TAINT-002",
    title="Untrusted input flows across jobs via ``jobs.<id>.outputs:``",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitise the value at the producer step *before* it lands "
        "in ``$GITHUB_OUTPUT``. Once the value is in a job output "
        "the consuming job has no expression-level escaping pass "
        "left, ``${{ needs.<job>.outputs.<name> }}`` substitutes "
        "the string verbatim into the consumer's shell. The "
        "canonical safe pattern is to copy the untrusted source "
        "into the producer step's ``env:`` block, reference the "
        "env var quoted in ``echo \"name=$VAR\" >> $GITHUB_OUTPUT``, "
        "and only then surface it through the job output. The "
        "consuming job should still treat the value as tainted "
        "(use it in env-var form, not interpolated directly into "
        "shell)."
    ),
    docs_note=(
        "TAINT-001 catches step-output flow within a single job; "
        "TAINT-002 catches the cross-job transition. Engine "
        "shape: walk every job's ``outputs:`` mapping looking for "
        "values that interpolate either a tainted step output or "
        "a direct ``${{ github.event.* }}`` source. Tainted job "
        "outputs are matched against every "
        "``${{ needs.<job>.outputs.<name> }}`` reference in any "
        "downstream job's ``run:`` / ``with:`` body. Each match "
        "emits a TAINT-002 finding with the full chain in the "
        "description.\n\n"
        "Same-step interpolations (the producer's own use of "
        "``${{ github.event.* }}`` inside its ``run:``) are still "
        "GHA-003's responsibility; TAINT-002's value is the "
        "cross-job hop the single-step rule can't see."
    ),
    known_fp=(
        "Sanitisation between the source interpolation and the "
        "$GITHUB_OUTPUT write isn't modeled. If the producer "
        "step runs ``echo \"$TITLE\" | tr -dc 'a-zA-Z0-9 '`` "
        "before redirecting to GITHUB_OUTPUT, the consumer is "
        "no longer exploitable but TAINT-002 will still fire; "
        "suppress via ignore-file scoped to the consumer job's "
        "workflow file when this is the deliberate shape.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Cross-job paths are distinguished by ``hops`` length: the
    # engine uses ``len == 1`` for same-job paths and ``len == 2``
    # for cross-job paths (steps -> job-output hop chain). Filter
    # to the cross-job set so TAINT-001 and TAINT-002 don't
    # double-fire on the same workflow.
    cross_job_paths = [p for p in analyze_workflow(doc) if len(p.hops) >= 2]
    if not cross_job_paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No cross-job taint path detected via "
                "``jobs.<id>.outputs:`` propagation."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in cross_job_paths]
    desc = (
        f"{len(cross_job_paths)} cross-job taint path(s) reach a "
        f"downstream sink via ``jobs.<id>.outputs:``: "
        f"{'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    # Sink-side job IDs from cross-job paths. Same shape contract as
    # TAINT-001 (sink_location = ``job_id[step_idx]``); chain rules
    # intersect this with the deploy-job set surfaced by GHA-014.
    anchor_jobs: dict[str, None] = {}
    for p in cross_job_paths:
        anchor_jobs[p.sink_location.split("[", 1)[0]] = None
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        job_anchors=tuple(anchor_jobs),
        path_evidence=tuple(rendered),
    )
