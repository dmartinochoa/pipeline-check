"""BB-026 — dangerous shell idioms in Bitbucket Pipelines script steps."""
from __future__ import annotations

from typing import Any

from ..._primitives import shell_eval
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="BB-026",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick "
        "exec with direct command invocation. Validate or allow-list "
        "any value that must feed a dynamic command at the boundary."
    ),
    docs_note=(
        "Complements BB-002 (script injection from untrusted PR "
        "context). This rule fires on intrinsically risky idioms — "
        "``eval``, ``sh -c \"$X\"``, backtick exec — regardless of "
        "whether the input source is currently trusted."
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
