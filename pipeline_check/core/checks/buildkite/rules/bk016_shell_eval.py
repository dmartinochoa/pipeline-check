"""BK-016, dangerous shell idioms in Buildkite step commands."""
from __future__ import annotations

from typing import Any

from ..._primitives import shell_eval
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="BK-016",
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
        "Complements BK-003 (untrusted Buildkite variable interpolated "
        "in a command). This rule fires on intrinsically risky idioms, "
        "``eval``, ``sh -c \"$X\"``, backtick exec, regardless of "
        "whether the input source is currently trusted, because the "
        "idiom hands a value full shell-grammar reach. The Buildkite "
        "analog of GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar "
        "``eval \"$(<literal-tool>)\"`` bootstrap idioms are "
        "intentionally NOT flagged, the substituted command is "
        "literal, only its output is eval'd.",
    ),
    exploit_example=(
        "# Vulnerable: ``eval`` on a variable that came from a\n"
        "# pipeline env / build metadata gives that value full\n"
        "# shell-grammar reach. ``sh -c $RAW`` on an unquoted\n"
        "# variable is the same shape.\n"
        "steps:\n"
        "  - command:\n"
        "      - eval \"$BUILD_CMD\"\n"
        "      - sh -c $RAW_HOOK\n"
        "\n"
        "# Safe: invoke a script you own with the value as a\n"
        "# quoted argument; let the script validate against an\n"
        "# allow-list. Never eval values from outside the step.\n"
        "steps:\n"
        "  - command:\n"
        "      - ./scripts/dispatch.sh \"$BUILD_CMD\""
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
