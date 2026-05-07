"""BK-006 — Steps must declare ``timeout_in_minutes``."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-006",
    title="Step has no timeout_in_minutes",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-400",),
    recommendation=(
        "Set ``timeout_in_minutes:`` on every command step. A "
        "compromised dependency or a hung test can otherwise hold an "
        "agent indefinitely, blocking parallel pipelines and running "
        "up self-hosted-runner cost. Pick a value generous enough for "
        "the slowest legitimate run (e.g. 30 for a typical build, 90 "
        "for an integration suite)."
    ),
    docs_note=(
        "Buildkite has no implicit timeout; agents will wait forever. "
        "Set ``timeout_in_minutes:`` per step. The pipeline-level "
        "default counts — a global ``steps:`` block with "
        "``timeout_in_minutes:`` is fine, since Buildkite copies it "
        "to each step."
    ),
    known_fp=(
        "Steps that genuinely need >24h (rare; database migrations, "
        "ML training jobs) — set ``timeout_in_minutes: 1440`` "
        "explicitly so the absence of a timeout is intentional.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        # Steps with a non-empty command are the relevant target.
        # Steps with no command (group containers, plugin-only steps
        # whose plugin is short-running) get a pass.
        if not step_commands(step):
            continue
        # ``timeout_in_minutes: null`` / ``0`` / negative / non-numeric
        # are equivalent to "no timeout"; only a positive integer
        # actually bounds the run.
        timeout = step.get("timeout_in_minutes")
        if (
            "timeout_in_minutes" not in step
            or not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or timeout <= 0
        ):
            offenders.append(step_label(step, idx))
    passed = not offenders
    desc = (
        "Every command step declares timeout_in_minutes."
        if passed else
        f"{len(offenders)} step(s) have no timeout_in_minutes: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A hung or compromised "
        f"step otherwise pins the agent indefinitely."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
