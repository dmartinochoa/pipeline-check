"""GHA-038. ``ACTIONS_ALLOW_UNSECURE_COMMANDS=true`` re-enables retired commands."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-038",
    title="Workflow re-enables retired ::set-env / ::add-path commands",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-77", "CWE-77"),
    recommendation=(
        "Drop the ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` env "
        "definition entirely, then migrate any leftover "
        "``::set-env::`` / ``::add-path::`` workflow commands to "
        "the file-redirect form (``echo \"X=$VAL\" >> "
        "\"$GITHUB_ENV\"`` and ``echo \"$DIR\" >> "
        "\"$GITHUB_PATH\"``). GitHub disabled the legacy commands "
        "in 2020 specifically because they share the runner's "
        "stdout as a control channel: any log line starting with "
        "``::`` could inject environment variables, prepend to "
        "PATH, or set step outputs. Setting the override flag "
        "back to ``true`` re-opens that injection channel for "
        "the entire workflow scope."
    ),
    docs_note=(
        "Detection fires when ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` "
        "is set to ``true`` (or the string ``\"true\"``) at the "
        "workflow ``env:`` level, the job ``env:`` level, or any "
        "step's ``env:`` block.\n\n"
        "Sister rule GHA-031 catches direct uses of ``::set-"
        "output::`` / ``::save-state::`` in step scripts. "
        "GHA-038 catches the explicit re-enable flag, which is "
        "the strictly worse case: it implicitly accepts every "
        "``::set-env::`` / ``::add-path::`` line that lands on "
        "the runner's stdout from any tool the step invokes, "
        "not just the workflow author's own ``echo`` commands. "
        "A downloaded build log, a container's startup banner, "
        "an upstream test runner's output, all become injection "
        "vectors."
    ),
    known_fp=(
        "Some legacy actions (last-updated pre-2020) still emit "
        "``::set-env::`` lines and rely on the override to be "
        "set. Replace the action rather than suppressing this "
        "rule, the security exposure outweighs the cost of an "
        "alternative action.",
    ),
)


_FLAG_NAME = "ACTIONS_ALLOW_UNSECURE_COMMANDS"


def _is_truthy(raw: Any) -> bool:
    if raw is True:
        return True
    if isinstance(raw, str) and raw.strip().strip('"').strip("'").lower() == "true":
        return True
    return False


def _scan_env(env: Any) -> bool:
    """True when *env* sets the unsafe flag to a truthy value."""
    if not isinstance(env, dict):
        return False
    return _is_truthy(env.get(_FLAG_NAME))


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    if _scan_env(doc.get("env")):
        offenders.append("workflow.env")
    for job_id, job in iter_jobs(doc):
        if _scan_env(job.get("env")):
            offenders.append(f"jobs.{job_id}.env")
        for idx, step in enumerate(iter_steps(job)):
            if _scan_env(step.get("env")):
                step_label = step.get("name") or step.get("id") or f"steps[{idx}]"
                offenders.append(f"jobs.{job_id}.{step_label}.env")
    passed = not offenders
    desc = (
        "Workflow does not set ACTIONS_ALLOW_UNSECURE_COMMANDS=true."
        if passed else
        f"{len(offenders)} env block(s) set "
        f"ACTIONS_ALLOW_UNSECURE_COMMANDS=true: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The flag re-enables "
        f"retired ``::set-env::`` / ``::add-path::`` workflow "
        f"commands which inject through the runner's stdout."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
