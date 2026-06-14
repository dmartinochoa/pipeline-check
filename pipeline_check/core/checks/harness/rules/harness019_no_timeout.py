"""HARNESS-019. Pipeline step lacks an explicit timeout."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_stages, iter_steps, step_label

RULE = Rule(
    id="HARNESS-019",
    title="Pipeline step lacks an explicit timeout",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-400",),
    recommendation=(
        "Set an explicit ``timeout`` on every step, or on the enclosing "
        "stage to bound all of its steps at once: ``timeout: 10m`` / "
        "``timeout: 1h``. Without one a hung step falls back to Harness's "
        "default and can pin a build VM / delegate far longer than the job "
        "needs, wasting capacity and delaying the queue. For genuinely long "
        "jobs set a generous explicit value (``2h``, ``6h``) rather than "
        "leaving it implicit."
    ),
    docs_note=(
        "Harness ``timeout`` is a string duration (``10m``, ``1h30m``) that "
        "sits beside ``spec`` on a step and on a stage. The rule walks every "
        "step (across CI and CD stages, through ``parallel`` / ``stepGroup`` "
        "nesting) and flags a step that carries no ``timeout`` of its own "
        "and whose enclosing stage carries none either, since a stage-level "
        "timeout bounds all of its steps. A runtime input (``<+input>``) "
        "counts as set. A best-practice / missing-control rule (LOW, dropped "
        "by ``--no-best-practice``); the Harness analog of TKN-006 / "
        "GHA-015 / GCB-005."
    ),
)


def _is_meaningful_timeout(value: Any) -> bool:
    """A ``timeout`` is only "set" when its value is a non-empty literal.

    ``timeout: ""`` / ``timeout: null`` parse as the key being present but
    the value effectively unset, so Harness falls back to its default;
    treat those as "no timeout". A runtime input (``<+input>``) is a
    non-empty string, so it counts as set (the user supplies a concrete
    value at run time).
    """
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    return True


def check(pipeline: HarnessPipeline) -> Finding:
    # A pipeline-level timeout (where present) or a stage-level timeout
    # bounds the steps beneath it, so a step only offends when nothing
    # above it and nothing on it sets a timeout.
    pipeline_bounded = _is_meaningful_timeout(pipeline.data.get("timeout"))
    stage_bounded = {
        stage_id: _is_meaningful_timeout(stage.get("timeout"))
        for stage_id, stage in iter_stages(pipeline)
    }
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        if pipeline_bounded or stage_bounded.get(stage_id):
            continue
        if _is_meaningful_timeout(step.get("timeout")):
            continue
        offenders.append(step_label(stage_id, step))
    passed = not offenders
    desc = (
        "Every step is bounded by an explicit timeout."
        if passed else
        f"{len(offenders)} step(s) without an explicit timeout: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. A hung step otherwise runs "
        f"to the Harness default and pins the build VM / delegate."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
