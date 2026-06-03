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
        "Sanitize the value at the producer job before it lands "
        "in the dotenv file. The canonical safe pattern is to "
        "copy the ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` "
        "source into an intermediate shell variable, run a "
        "sanitizer (``tr -dc 'a-zA-Z0-9 '`` is enough for a "
        "freeform title), and only then write the cleaned value "
        "to dotenv. The consuming job should still treat the "
        "auto-imported variable as tainted, reference it quoted "
        "(``\"$TITLE\"``) and never inline into a command "
        "without re-quoting. Removing the dotenv entirely is "
        "the strongest fix; if the value genuinely needs to "
        "flow downstream, validate the sanitizer is doing what "
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
        "If the producer job runs a sanitizer between the "
        "tainted source interpolation and the dotenv write "
        "(``echo \"$CI_COMMIT_TITLE\" | tr -dc 'a-zA-Z0-9 ' "
        "> taint.env``), the consumer is no longer exploitable "
        "but TAINT-004 still fires. Suppress via ignore-file "
        "scoped to the consumer job's pipeline file when this "
        "is the deliberate shape; the sanitizer is then "
        "load-bearing and any future regression in it would "
        "re-expose the consumer.",
    ),
    exploit_example=(
        "# Vulnerable: an ``extract`` job writes an untrusted\n"
        "# source (``$CI_COMMIT_MESSAGE``) into a dotenv report\n"
        "# artifact. GitLab automatically loads dotenv reports\n"
        "# as env vars in dependent jobs; the consumer job then\n"
        "# inlines the value into a shell command unquoted, and\n"
        "# any metacharacters in the source execute there.\n"
        "extract:\n"
        "  script:\n"
        "    - echo \"MSG=$CI_COMMIT_MESSAGE\" > deploy.env\n"
        "  artifacts:\n"
        "    reports:\n"
        "      dotenv: deploy.env\n"
        "use:\n"
        "  needs: [extract]\n"
        "  script:\n"
        "    - ./gen-notes --message $MSG\n"
        "\n"
        "# Safe: sanitize at the producer before writing the\n"
        "# dotenv file, and quote at the consumer. The cleaned\n"
        "# value is safe to inline; the consumer's env binding\n"
        "# is properly quoted.\n"
        "extract:\n"
        "  script:\n"
        "    - clean=$(echo \"$CI_COMMIT_MESSAGE\" | tr -dc 'a-zA-Z0-9 -')\n"
        "    - echo \"MSG=$clean\" > deploy.env\n"
        "  artifacts:\n"
        "    reports:\n"
        "      dotenv: deploy.env\n"
        "use:\n"
        "  needs: [extract]\n"
        "  script:\n"
        "    - ./gen-notes --message \"$MSG\""
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
    # Sink-side consumer jobs. GitLab's TaintPath.sink_location is
    # ``"<job_name>:script[<idx>]"``. ``rsplit`` on the trailing
    # ``":"`` so job names that legitimately contain ``":"`` (e.g.
    # ``deploy:prod``) survive the strip; only the trailing
    # ``:script[<idx>]`` segment gets shed. The GHA twin splits on
    # ``"["`` because its format differs. The reachability-aware
    # AC-022 chain intersects these with GL-004's ungated-deploy
    # job IDs to confirm an end-to-end path.
    anchor_jobs: dict[str, None] = {}
    for p in paths:
        anchor_jobs[p.sink_location.rsplit(":", 1)[0]] = None
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
        job_anchors=tuple(anchor_jobs),
        path_evidence=tuple(rendered),
        taint_flows=tuple(p.to_flow() for p in paths),
    )
