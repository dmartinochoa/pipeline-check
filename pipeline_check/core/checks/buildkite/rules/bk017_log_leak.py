"""BK-017. Secret-named variable echoed to the build log."""
from __future__ import annotations

from typing import Any

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-017",
    title="Secret-named variable echoed / printed in a step command",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in step commands. Buildkite redacts "
        "the values of pipeline secrets / known env in the log, but only "
        "the exact string. Encoded, truncated, or derived forms bypass the "
        "redaction, and ``set -x`` / ``env`` / ``printenv`` dump the raw "
        "value before redaction can catch it. Log a boolean instead "
        "(``[ -n \"$TOKEN\" ] && echo set || echo unset``), and avoid "
        "``set -x`` while a credential variable is in scope."
    ),
    docs_note=(
        "Scans every ``command`` / ``commands`` entry on every step for a "
        "secret-named variable handed to ``echo`` / ``printf`` / ``cat`` / "
        "``tee``, for an ``env`` / ``printenv`` dump, and for ``set -x`` "
        "with a secret-named variable in scope (the shared ``log_leak`` "
        "detector, with GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032 / "
        "JF-042 / HARNESS-013). Variable names matching common secret "
        "patterns (PASSWORD / TOKEN / SECRET / API_KEY / CREDENTIAL) "
        "trigger the rule. The Buildkite analog of GL-036 / CC-032."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            hits = scan_script_for_leaked_secrets(cmd)
            for h in hits:
                offenders.append(f"{step_label(step, idx)}: {h}")
    passed = not offenders
    desc = (
        "No step command prints a secret-named variable to the log."
        if passed else
        f"{len(offenders)} step-command log leak(s) detected: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
