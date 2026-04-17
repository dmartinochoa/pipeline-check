"""GL-026 — dangerous shell idioms (eval, ``sh -c "$VAR"``, backtick var).

Complements GL-002 (script injection via untrusted MR context). GL-002
traces taint from attacker-controlled CI variables into ``script:``
blocks; this rule fires on intrinsically risky idioms regardless of
source, on the same rationale as GHA-028.
"""
from __future__ import annotations

from typing import Any

from ..._primitives import shell_eval
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GL-026",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick "
        "exec of variables with direct command invocation. If the "
        "command must be dynamic, pass arguments as array members or "
        "validate the input against an allow-list at the boundary."
    ),
    docs_note=(
        "``eval``, ``sh -c \"$X\"``, and `` `$X` `` all re-parse the "
        "variable's value as shell syntax. Once a CI variable feeds "
        "into one of these idioms, any ``;``, ``&&``, ``|``, backtick, "
        "or ``$()`` in the value executes — even if the variable's "
        "source is currently trusted, future refactors may expose it."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar "
        "``eval \"$(<literal-tool>)\"`` bootstrap idioms are "
        "intentionally NOT flagged — the substituted command is "
        "literal, only its output is eval'd.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    hits = shell_eval.scan(blob)
    passed = not hits
    desc = (
        "No dangerous shell idioms detected in this pipeline."
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
