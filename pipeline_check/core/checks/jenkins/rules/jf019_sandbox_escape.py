"""JF-019 — Groovy sandbox escape pattern detected."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

_SANDBOX_ESCAPE_RE = re.compile(
    r"Runtime\.getRuntime|Class\.forName|\.classLoader|ProcessBuilder|@Grab\b"
)

RULE = Rule(
    id="JF-019",
    title="Groovy sandbox escape pattern detected",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    recommendation=(
        "Remove direct Runtime/ClassLoader calls. Use Jenkins pipeline "
        "steps instead. Avoid @Grab for untrusted dependencies."
    ),
    docs_note=(
        "Detects Groovy patterns that bypass the Jenkins script security "
        "sandbox: `Runtime.getRuntime()`, `Class.forName()`, "
        "`.classLoader`, `ProcessBuilder`, and `@Grab`. These give the "
        "pipeline (or an attacker who controls its source) unrestricted "
        "access to the Jenkins controller JVM — full RCE."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    # Case-sensitive — Java/Groovy class names are case-sensitive.
    matches = _SANDBOX_ESCAPE_RE.findall(jf.text)
    passed = not matches
    desc = (
        "No Groovy sandbox escape patterns detected in this Jenkinsfile."
        if passed else
        f"Groovy sandbox escape pattern detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
