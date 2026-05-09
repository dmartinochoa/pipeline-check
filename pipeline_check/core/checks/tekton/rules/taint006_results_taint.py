"""TAINT-006. Untrusted input flows across Tekton tasks via ``results``.

The Tekton analogue of ``TAINT-002`` (GHA jobs.outputs),
``TAINT-004`` (GitLab dotenv), and ``TAINT-005`` (Buildkite
meta-data). The cross-task channel here is Tekton's
``$(tasks.<task-name>.results.<result-name>)`` substitution:

  apiVersion: tekton.dev/v1beta1
  kind: Pipeline
  spec:
    params:
      - name: pr-title
    tasks:
      - name: extract
        params:
          - name: title
            value: "$(params.pr-title)"
        taskSpec:
          params:
            - name: title
          results:
            - name: clean
          steps:
            - script: |
                echo "$(params.title)" > $(results.clean.path)
                # ^^ TKN-003 catches this
      - name: build
        runAfter: [extract]
        params:
          - name: title
            value: "$(tasks.extract.results.clean)"
        taskSpec:
          params:
            - name: title
          steps:
            - script: |
                echo $(params.title)
                # ^^ TAINT-006 catches this — cross-task injection

TKN-003 catches the producer step's interpolation. TAINT-006
catches the actual injection at the consumer task's script.

The detector lives in
``pipeline_check.core.checks.tekton._taint_graph.analyze_pipeline_doc``.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_pipeline_doc
from ..base import TektonContext

RULE = Rule(
    id="TAINT-006",
    title="Untrusted input flows across tasks via Tekton ``results``",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitise the value at the producer task before it "
        "lands in ``$(results.<name>.path)``. The canonical "
        "safe pattern is to copy the ``$(params.<name>)`` source "
        "into an intermediate shell variable, run a sanitiser "
        "(``tr -dc 'a-zA-Z0-9 '`` for a freeform title), and "
        "only then write the cleaned value to the result file. "
        "The consumer task should still treat its own param as "
        "tainted: surface ``$(params.<name>)`` into a quoted "
        "shell variable (``TITLE=\"$(params.title)\"``) before "
        "interpolating elsewhere. Removing the cross-task "
        "results forwarding is the strongest fix; if the value "
        "genuinely needs to flow downstream, validate the "
        "sanitiser is doing what you think before relying on "
        "it."
    ),
    docs_note=(
        "Detection walks every ``Pipeline`` document. Pass 1 "
        "looks for tasks whose inline ``taskSpec.steps[*].script`` "
        "writes to ``$(results.<X>.path)`` AND interpolates a "
        "``$(params.<Y>)`` reference, recording ``X`` as a "
        "tainted result for that producer task. Pass 2 walks "
        "every task for ``params:`` whose ``value:`` is "
        "``$(tasks.<producer>.results.<X>)`` — when ``(producer, "
        "X)`` matches a tainted result and the consumer's "
        "``taskSpec.steps[*].script`` references "
        "``$(params.<consumer-name>)`` (where consumer-name is "
        "the param the result was forwarded into), TAINT-006 "
        "fires.\n\n"
        "v1 limitations: only inline ``taskSpec:`` is walked. "
        "``taskRef:`` references to externally-defined Tasks "
        "aren't resolved (would need the same cross-document "
        "machinery as the GHA ``--resolve-remote`` flow). "
        "``finally:`` blocks aren't walked yet."
    ),
    known_fp=(
        "If the producer task runs a sanitiser between the "
        "tainted ``$(params.X)`` interpolation and the "
        "``$(results.Y.path)`` write, the consumer is no longer "
        "exploitable but TAINT-006 still fires. Suppress via "
        "ignore-file scoped to the consumer task name when "
        "this is the deliberate shape; the sanitiser is then "
        "load-bearing.",
    ),
)


def check(ctx: TektonContext) -> Finding:
    all_paths = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind != "Pipeline":
            continue
        examined += 1
        all_paths.extend(analyze_pipeline_doc(doc))

    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Pipeline documents to check.",
            recommendation="No action required.", passed=True,
        )
    if not all_paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description=(
                "No cross-task taint path detected via "
                "``$(tasks.<X>.results.<Y>)`` propagation."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in all_paths]
    desc = (
        f"{len(all_paths)} cross-task taint path(s) reach a "
        f"downstream sink via Tekton results: "
        f"{'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
