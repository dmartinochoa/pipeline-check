"""ADO-027, dangerous shell idioms in Azure Pipelines script steps."""
from __future__ import annotations

from typing import Any

from ..._primitives import shell_eval
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="ADO-027",
    title="Dangerous shell idiom (eval, sh -c variable, backtick exec)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-95",),
    recommendation=(
        "Replace ``eval \"$VAR\"`` / ``sh -c \"$VAR\"`` / backtick "
        "exec with direct command invocation. Validate any value "
        "that must feed a dynamic command at the boundary."
    ),
    docs_note=(
        "Complements ADO-002 (script injection from untrusted PR "
        "context). Fires on intrinsically risky shell idioms, "
        "``eval``, ``sh -c \"$X\"``, backtick exec, regardless of "
        "whether the input source is currently trusted."
    ),
    known_fp=(
        "``eval \"$(ssh-agent -s)\"`` and similar "
        "``eval \"$(<literal-tool>)\"`` bootstrap idioms are "
        "intentionally NOT flagged, the substituted command is "
        "literal, only its output is eval'd.",
    ),
    exploit_example=(
        "# Vulnerable: ``eval \"$BUILD_CMD\"`` on a value that came\n"
        "# from a variable group / runtime parameter gives the\n"
        "# value full shell-grammar reach. ``sh -c $RAW`` on an\n"
        "# unquoted variable is the same shape.\n"
        "parameters:\n"
        "  - name: cmd\n"
        "    type: string\n"
        "steps:\n"
        "  - bash: |\n"
        "      eval \"${{ parameters.cmd }}\"\n"
        "\n"
        "# Safe: replace dynamic shell evaluation with an explicit\n"
        "# dispatcher over an allow-list, or invoke a script you\n"
        "# own that does its own validation. Never eval values\n"
        "# from runtime parameters.\n"
        "parameters:\n"
        "  - name: target\n"
        "    type: string\n"
        "    values: [staging, prod]\n"
        "steps:\n"
        "  - bash: ./scripts/deploy.sh \"${{ parameters.target }}\""
    ),
)


#: Explicit-task equivalents of the shortcut script keys. Their inline
#: shell body lives under ``inputs.script`` (``targetType: inline``).
_SHELL_TASK_PREFIXES = ("bash@", "cmdline@", "powershell@", "pwsh@")


def _step_script_body(step: dict[str, Any]) -> str:
    for key in ("script", "bash", "powershell", "pwsh"):
        val = step.get(key)
        if isinstance(val, str):
            return val
    # Explicit-task form: ``task: Bash@3`` / ``CmdLine@2`` / ``PowerShell@2``
    # put the shell body under ``inputs.script``, a mainstream ADO style.
    task = step.get("task")
    if isinstance(task, str) and task.lower().startswith(_SHELL_TASK_PREFIXES):
        inputs = step.get("inputs")
        if isinstance(inputs, dict):
            script = inputs.get("script")
            if isinstance(script, str):
                return script
    return ""


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits: list[shell_eval.ShellEvalFinding] = []
    for _job_loc, job in iter_jobs(doc):
        for _step_loc, step in iter_steps(job):
            body = _step_script_body(step)
            if body.strip():
                hits.extend(shell_eval.scan(body.lower()))
    passed = not hits
    snippets = sorted({h.snippet for h in hits})
    desc = (
        "No dangerous shell idioms detected in this pipeline."
        if passed else
        f"{len(hits)} dangerous shell idiom(s) detected: "
        f"{', '.join(snippets[:3])}"
        f"{'…' if len(snippets) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
