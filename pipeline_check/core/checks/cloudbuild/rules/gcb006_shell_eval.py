"""GCB-006 — dangerous shell idioms (``eval``, ``sh -c $VAR``, backtick exec).

Reuses the shared ``_primitives.shell_eval`` detector so Cloud Build
benefits from the same pattern catalogue as GHA-028 / GL-026 / BB-026 /
ADO-027 / CC-027 / JF-030.
"""
from __future__ import annotations

from typing import Any

from ..._primitives import shell_eval
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="GCB-006",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick "
        "exec with direct command invocation. Validate or allow-list "
        "any value that must feed a dynamic command at the boundary. "
        "In Cloud Build these idioms typically appear in ``args: "
        "[-c, ...]`` entries under a bash entrypoint."
    ),
    docs_note=(
        "Complements GCB-004 (dynamicSubstitutions + user substitution "
        "in args). GCB-006 fires on intrinsically risky shell idioms — "
        "``eval``, ``sh -c \"$X\"``, backtick exec — regardless of "
        "whether the substitution source is currently trusted."
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
        "No dangerous shell idioms detected in this cloudbuild.yaml."
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
