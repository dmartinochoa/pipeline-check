"""GHA-028 — dangerous shell idioms (eval, ``sh -c "$VAR"``, backtick var).

Complements GHA-003. GHA-003 traces taint from attacker-controllable
context into ``run:`` blocks; this rule fires on intrinsically risky
idioms — ``eval``, ``sh -c "$VAR"``, backtick command substitution
with a variable — regardless of whether the input source is
attacker-controllable. The content of the variable at runtime
decides whether the shell invocation escapes the current process;
flagging the idiom forces the author to sanitise at the boundary.
"""
from __future__ import annotations

from typing import Any

from ..._primitives import shell_eval
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GHA-028",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick "
        "exec of variables with direct command invocation. If the "
        "command really must be dynamic, pass arguments as array "
        "members (``\"${ARGS[@]}\"``) or validate the input against "
        "an allow-list before invocation."
    ),
    docs_note=(
        "``eval``, ``sh -c \"$X\"``, and `` `$X` `` all re-parse the "
        "variable's value as shell syntax. If the value contains "
        "``;``, ``&&``, ``|``, backticks, or ``$()``, those "
        "metacharacters execute. Even when the variable source "
        "looks controlled today, relocating the script or adding a "
        "new caller can silently expose it to untrusted input."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar "
        "``eval \"$(<literal-tool> <literal-args>)\"`` bootstrap "
        "idioms are intentionally NOT flagged — the substituted "
        "command is literal, only its output is eval'd. The rule "
        "only fires when the substituted command references a "
        "variable.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    hits = shell_eval.scan(blob)
    passed = not hits
    desc = (
        "No dangerous shell idioms detected in this workflow."
        if passed else
        f"{len(hits)} dangerous shell idiom(s) detected: "
        f"{', '.join(sorted({h.snippet for h in hits})[:3])}"
        f"{'…' if len({h.snippet for h in hits}) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
