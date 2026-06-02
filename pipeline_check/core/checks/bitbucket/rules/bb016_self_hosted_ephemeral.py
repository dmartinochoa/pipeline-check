"""BB-016, self-hosted runners should use ephemeral or Docker-based images."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="BB-016",
    title="Self-hosted runner without ephemeral marker",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-269",),
    recommendation=(
        "Use Docker-based self-hosted runners or configure runners to "
        "tear down between jobs. Add 'ephemeral' to `runs-on` labels "
        "or use Bitbucket's runner images that are rebuilt per-job."
    ),
    docs_note=(
        "Self-hosted runners that persist between jobs leak filesystem "
        "and process state. A PR-triggered step writes to a well-known "
        "path; a subsequent deploy step on the same runner reads it. "
        "Detects `runs-on: self.hosted` without an `ephemeral` marker "
        "or Docker image override."
    ),
)


def _step_is_non_ephemeral_self_hosted(step: dict[str, Any]) -> bool:
    """Return True when the step uses a self.hosted runner without ephemeral."""
    runs_on = step.get("runs-on")
    if runs_on is None:
        return False
    # Normalize to a list of lowercase label strings.
    if isinstance(runs_on, str):
        labels = [runs_on.lower()]
    elif isinstance(runs_on, list):
        labels = [str(lbl).lower() for lbl in runs_on]
    else:
        return False
    if "self.hosted" not in labels:
        return False
    # Only suppress if 'ephemeral' appears in this step's own runs-on labels.
    return "ephemeral" not in labels


def check(path: str, doc: dict[str, Any]) -> Finding:
    non_ephemeral = [
        loc for loc, step in iter_steps(doc)
        if _step_is_non_ephemeral_self_hosted(step)
    ]
    passed = not non_ephemeral
    desc = (
        "No non-ephemeral self-hosted runner usage detected."
        if passed
        else "Pipeline uses `self.hosted` runners without an "
        "ephemeral configuration. Runners may persist state between jobs."
    )
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation,
        passed=passed,
    )
