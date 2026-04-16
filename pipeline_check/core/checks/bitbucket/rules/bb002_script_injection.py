"""BB-002 — scripts must not interpolate $BITBUCKET_* ref/PR variables."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, is_quoted_assignment
from ...rule import Rule
from ..base import iter_steps, step_scripts
from ._helpers import UNTRUSTED_VAR_RE


RULE = Rule(
    id="BB-002",
    title="Script injection via attacker-controllable context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    recommendation=(
        "Always double-quote interpolations of ref-derived variables "
        "(`\"$BITBUCKET_BRANCH\"`). Avoid passing them to `eval`, "
        "`sh -c`, or unquoted command arguments."
    ),
    docs_note=(
        "$BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are "
        "populated from SCM event metadata the attacker controls. "
        "Interpolating them unquoted into a shell command lets a "
        "crafted branch/tag name execute inline."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, step in iter_steps(doc):
        for line in step_scripts(step):
            if UNTRUSTED_VAR_RE.search(line) and not is_quoted_assignment(line):
                offenders.append(loc)
                break
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable ref / PR variables."
        if passed else
        f"Script(s) in step(s) {', '.join(sorted(set(offenders)))} "
        f"interpolate $BITBUCKET_BRANCH / $BITBUCKET_TAG / "
        f"$BITBUCKET_PR_* directly into shell commands. A crafted "
        f"branch or tag name can execute inline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
