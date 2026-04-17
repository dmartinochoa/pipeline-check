"""BB-002 — scripts must not interpolate $BITBUCKET_* ref/PR variables."""
from __future__ import annotations

import re
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
    cwe=("CWE-78",),
    recommendation=(
        "Always double-quote interpolations of ref-derived variables "
        "(`\"$BITBUCKET_BRANCH\"`). Avoid passing them to `eval`, "
        "`sh -c`, or unquoted command arguments."
    ),
    docs_note=(
        "$BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are "
        "populated from SCM event metadata the attacker controls. "
        "Interpolating them unquoted into a shell command lets a "
        "crafted branch or tag name can execute inline."
    ),
)

# Matches ``export VAR=...$BITBUCKET_BRANCH...`` or ``VAR=...$BITBUCKET_BRANCH...``
_EXPORT_RE = re.compile(r"(?:export\s+)?(\w+)=")


def _tainted_exports(lines: list[str]) -> set[str]:
    """Return variable names assigned from untrusted BITBUCKET_* values."""
    tainted: set[str] = set()
    for line in lines:
        m = _EXPORT_RE.match(line.strip())
        if m and UNTRUSTED_VAR_RE.search(line):
            tainted.add(m.group(1))
    return tainted


def _var_ref_in_scripts(lines: list[str], var_names: set[str]) -> bool:
    """Return True if any *line* unsafely references a tainted variable."""
    for name in var_names:
        ref_re = re.compile(rf"\$\{{?{re.escape(name)}\}}?")
        for line in lines:
            if not ref_re.search(line):
                continue
            if is_quoted_assignment(line):
                continue
            stripped = re.sub(r'"[^"]*"', "", line)
            if ref_re.search(stripped):
                return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, step in iter_steps(doc):
        scripts = step_scripts(step)
        # 1. Direct interpolation of untrusted predefined vars.
        direct_hit = False
        for line in scripts:
            if UNTRUSTED_VAR_RE.search(line) and not is_quoted_assignment(line):
                offenders.append(loc)
                direct_hit = True
                break
        if direct_hit:
            continue
        # 2. Indirect: script exports tainted value into a local var
        #    then references that var unquoted in a later line.
        tainted = _tainted_exports(scripts)
        if tainted and _var_ref_in_scripts(scripts, tainted):
            offenders.append(loc)
    passed = not offenders
    desc = (
        "No script interpolates attacker-controllable ref / PR variables."
        if passed else
        f"Script(s) in step(s) {', '.join(sorted(set(offenders)))} "
        f"interpolate $BITBUCKET_BRANCH / $BITBUCKET_TAG / "
        f"$BITBUCKET_PR_* directly or via exported variables into "
        f"shell commands. A crafted branch or tag name can execute inline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
