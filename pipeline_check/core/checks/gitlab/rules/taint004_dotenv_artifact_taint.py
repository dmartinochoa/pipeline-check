"""TAINT-004. Untrusted input flows across GitLab jobs via dotenv artifacts.

The GitLab analogue of ``TAINT-002``. ``artifacts.reports.dotenv``
is GitLab's canonical mechanism for surfacing a producer job's
output as a regular ``$VAR`` shell variable in any downstream
job that ``needs:`` (or ``dependencies:``) the producer. The
injection shape:

  extract:
    script:
      - echo "TITLE=$CI_COMMIT_TITLE" > taint.env
    artifacts:
      reports:
        dotenv: taint.env

  build:
    needs: [extract]
    script:
      - echo "$TITLE"

GL-002 catches the producer step's interpolation. TAINT-004
catches the actual injection sink at the consumer (``$TITLE``
looks like any other shell variable until you trace it back
through the dotenv artifact).

This is the same threat shape as TAINT-002 in the GHA family
but routed through GitLab's mechanism instead of
``jobs.<id>.outputs:``. The detector lives in
``pipeline_check.core.checks.gitlab._taint_graph.analyze_pipeline``.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_pipeline

RULE = Rule(
    id="TAINT-004",
    title="Untrusted input flows across jobs via dotenv artifact",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitise the value at the producer job before it lands "
        "in the dotenv file. The canonical safe pattern is to "
        "copy the ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` "
        "source into an intermediate shell variable, run a "
        "sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a "
        "freeform title), and only then write the cleaned value "
        "to dotenv. The consuming job should still treat the "
        "auto-imported variable as tainted, reference it quoted "
        "(``\"$TITLE\"``) and never inline into a command "
        "without re-quoting. Removing the dotenv entirely is "
        "the strongest fix; if the value genuinely needs to "
        "flow downstream, validate the sanitiser is doing what "
        "you think before relying on it."
    ),
    docs_note=(
        "Detection is a two-pass walk over the pipeline. Pass 1 "
        "looks for jobs whose scripts write ``KEY=value`` to a "
        "file declared under ``artifacts.reports.dotenv:`` and "
        "whose ``value`` interpolates an attacker-controllable "
        "GitLab predefined variable (the ``UNTRUSTED_VAR_RE`` "
        "vocabulary GL-002 already uses). Pass 2 walks every job "
        "with a ``needs:`` / ``dependencies:`` link to a "
        "producer and looks for ``$KEY`` references in scripts "
        "that match a tainted leak.\n\n"
        "v1 limitations: ``extends:`` job-template inheritance "
        "and cross-pipeline ``include:`` are not yet tracked. "
        "The dotenv path matching is literal (``./taint.env`` "
        "and ``taint.env`` are treated as the same path), no "
        "glob expansion is performed."
    ),
    known_fp=(
        "If the producer job runs a sanitiser between the "
        "tainted source interpolation and the dotenv write "
        "(``echo \"$CI_COMMIT_TITLE\" | tr -dc 'a-zA-Z0-9 ' "
        "> taint.env``), the consumer is no longer exploitable "
        "but TAINT-004 still fires. Suppress via ignore-file "
        "scoped to the consumer job's pipeline file when this "
        "is the deliberate shape; the sanitiser is then "
        "load-bearing and any future regression in it would "
        "re-expose the consumer.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    paths = analyze_pipeline(doc)
    if not paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No cross-job taint path detected via "
                "``artifacts.reports.dotenv`` propagation."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in paths]
    desc = (
        f"{len(paths)} cross-job taint path(s) reach a downstream "
        f"sink via dotenv artifact: {'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
