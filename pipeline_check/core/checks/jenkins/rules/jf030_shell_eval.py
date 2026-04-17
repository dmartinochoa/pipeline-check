"""JF-030 — dangerous shell idioms in Jenkins pipeline ``sh`` / ``bat`` steps."""
from __future__ import annotations

from ..._primitives import shell_eval
from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-030",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick "
        "exec with direct command invocation. Validate any value "
        "feeding a dynamic command at the boundary, or pass "
        "arguments as a list to a real ``sh`` step so the shell "
        "is not re-invoked."
    ),
    docs_note=(
        "Complements JF-002 (script injection from untrusted build "
        "parameters). Fires on intrinsically risky shell idioms — "
        "``eval``, ``sh -c \"$X\"``, backtick exec — regardless of "
        "whether the input source is currently trusted."
    ),
    known_fp=(
        "``sh 'eval \"$(ssh-agent -s)\"'`` and similar "
        "``eval \"$(<literal-tool>)\"`` bootstrap idioms are "
        "intentionally NOT flagged — the substituted command is "
        "literal, only its output is eval'd.",
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    hits = shell_eval.scan(jf.text_no_comments)
    passed = not hits
    desc = (
        "No dangerous shell idioms detected in this Jenkinsfile."
        if passed else
        f"{len(hits)} dangerous shell idiom(s) detected: "
        f"{', '.join(sorted({h.snippet for h in hits})[:3])}"
        f"{'…' if len({h.snippet for h in hits}) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
