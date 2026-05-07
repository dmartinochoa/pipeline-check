"""TKN-006 — ``Pipeline`` / ``PipelineRun`` / ``TaskRun`` lacks a timeout."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TektonContext

RULE = Rule(
    id="TKN-006",
    title="Tekton run lacks an explicit timeout",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-400",),
    recommendation=(
        "Set ``spec.timeouts.pipeline`` (or ``spec.timeout`` on a "
        "TaskRun) on every PipelineRun and TaskRun. A misbehaving "
        "step otherwise pins a build pod for the cluster's default "
        "timeout (1h). For long jobs, set a generous explicit value "
        "(``2h``, ``6h``) rather than leaving it implicit."
    ),
    docs_note=(
        "Applies to ``PipelineRun``, ``TaskRun``, and ``Pipeline``. "
        "For Pipelines, the rule looks for ``spec.tasks[].timeout`` "
        "as evidence of intent. ``Task`` / ``ClusterTask`` themselves "
        "don't carry a timeout — the timeout lives on the concrete run."
    ),
)


def _has_run_timeout(spec: dict[str, Any]) -> bool:
    if "timeout" in spec:
        return True
    timeouts = spec.get("timeouts")
    if isinstance(timeouts, dict) and timeouts:
        return True
    return False


def _pipeline_has_per_task_timeouts(spec: dict[str, Any]) -> bool:
    tasks = spec.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        return False
    for t in tasks:
        if isinstance(t, dict) and "timeout" in t:
            return True
    return False


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("PipelineRun", "TaskRun", "Pipeline"):
            continue
        examined += 1
        spec = doc.data.get("spec") or {}
        if not isinstance(spec, dict):
            spec = {}
        if doc.kind in ("PipelineRun", "TaskRun"):
            ok = _has_run_timeout(spec)
        else:
            ok = _has_run_timeout(spec) or _pipeline_has_per_task_timeouts(spec)
        if not ok:
            offenders.append(f"{doc.kind}/{doc.name}")
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No PipelineRun / TaskRun / Pipeline documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every Run / Pipeline declares a timeout."
        if passed else
        f"{len(offenders)} run(s) without a timeout: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A hung step otherwise "
        f"holds the pod until the cluster default expires."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
