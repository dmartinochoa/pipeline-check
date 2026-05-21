"""CC-027, dangerous shell idioms in CircleCI command steps."""
from __future__ import annotations

from typing import Any

from ..._primitives import shell_eval
from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="CC-027",
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
        "Complements CC-002 (script injection from untrusted context). "
        "Fires on intrinsically risky shell idioms, ``eval``, "
        "``sh -c \"$X\"``, backtick exec, regardless of whether the "
        "input source is currently trusted."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar "
        "``eval \"$(<literal-tool>)\"`` bootstrap idioms are "
        "intentionally NOT flagged, the substituted command is "
        "literal, only its output is eval'd.",
    ),
    exploit_example=(
        "# Vulnerable: ``eval`` on a parameter value, or ``sh -c``\n"
        "# on an unquoted variable, gives the value full shell-\n"
        "# grammar reach. A pipeline parameter or upstream env\n"
        "# var carrying metacharacters executes them.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  dispatch:\n"
        "    docker:\n"
        "      - image: alpine@sha256:abc123...\n"
        "    steps:\n"
        "      - run: |\n"
        "          eval \"$BUILD_CMD\"\n"
        "          sh -c $RAW_HOOK\n"
        "\n"
        "# Safe: replace dynamic shell evaluation with an\n"
        "# explicit dispatcher over an allow-list, or invoke a\n"
        "# script you own that does its own validation. Never\n"
        "# eval values that came from outside the step body.\n"
        "version: 2.1\n"
        "jobs:\n"
        "  dispatch:\n"
        "    docker:\n"
        "      - image: alpine@sha256:abc123...\n"
        "    steps:\n"
        "      - run: ./scripts/dispatch.sh \"$BUILD_CMD\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    hits = shell_eval.scan(blob)
    passed = not hits
    desc = (
        "No dangerous shell idioms detected in this config."
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
