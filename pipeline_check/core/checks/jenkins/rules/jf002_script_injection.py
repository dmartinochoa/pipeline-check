"""JF-002 — shell steps must not interpolate attacker-controllable env vars."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import SHELL_STEP_RE, UNTRUSTED_ENV_RE

RULE = Rule(
    id="JF-002",
    title="Script step interpolates attacker-controllable env var",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Switch the affected `sh`/`bat`/`powershell` step to a "
        "single-quoted string (Groovy doesn't interpolate single "
        "quotes), and pass values through a quoted shell variable "
        "(`sh 'echo \"$BRANCH\"'` after `withEnv([...])`)."
    ),
    docs_note=(
        "$BRANCH_NAME / $GIT_BRANCH / $TAG_NAME / $CHANGE_* are "
        "populated from SCM event metadata the attacker controls. "
        "Single-quoted Groovy strings don't interpolate so they're "
        "safe; only double-quoted / triple-double-quoted bodies are "
        "flagged."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    offenders: list[str] = []
    for m in SHELL_STEP_RE.finditer(jf.text):
        body = (
            m.group("triple_d") or m.group("triple_s")
            or m.group("dq") or m.group("sq") or ""
        )
        if m.group("sq") is not None or m.group("triple_s") is not None:
            continue
        if UNTRUSTED_ENV_RE.search(body):
            line_no = jf.text[: m.start()].count("\n") + 1
            offenders.append(f"line {line_no}")
    passed = not offenders
    desc = (
        "No shell step interpolates attacker-controllable Jenkins env vars."
        if passed else
        f"Shell step(s) at {', '.join(offenders)} interpolate "
        f"$BRANCH_NAME / $CHANGE_TITLE / $TAG_NAME directly into a "
        f"double-quoted command. A crafted branch or tag name can "
        f"execute inline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
