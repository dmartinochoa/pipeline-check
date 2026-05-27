"""ADO-031. Script step echoes a secret variable to the build log."""
from __future__ import annotations

from typing import Any

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="ADO-031",
    title="Secret variable echoed / printed in a script step",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in pipeline scripts. Azure "
        "Pipelines masks variables marked ``issecret=true`` in logs, "
        "but only exact-match substrings. Encoded, truncated, or "
        "derived forms bypass the mask, and raw API log downloads "
        "are not masked. Log a boolean instead. Avoid ``set -x`` "
        "when secret-bound variables are in scope."
    ),
    docs_note=(
        "Scans ``script:``, ``bash:``, ``powershell:``, and ``pwsh:`` "
        "step bodies. Azure template expressions ``$(VAR)`` are "
        "matched alongside POSIX ``$VAR`` / ``${VAR}`` forms.\n\n"
        "Variables declared with ``issecret: true`` in the pipeline "
        "YAML are treated as known secrets (highest confidence). "
        "Variables whose names match common secret patterns "
        "(PASSWORD, TOKEN, API_KEY, etc.) are flagged heuristically."
    ),
    exploit_example=(
        "# Vulnerable: echoes a secret variable via Azure syntax.\n"
        "steps:\n"
        "  - bash: echo \"Token is $(DEPLOY_TOKEN)\"\n"
        "\n"
        "# Safe: test existence without printing.\n"
        "steps:\n"
        "  - bash: |\n"
        "      if [ -n \"$DEPLOY_TOKEN\" ]; then\n"
        "        echo DEPLOY_TOKEN is configured\n"
        "      fi"
    ),
)


def _collect_secret_var_names(doc: dict[str, Any]) -> frozenset[str]:
    """Collect variable names declared with ``issecret: true``."""
    names: set[str] = set()
    variables = doc.get("variables")
    if isinstance(variables, list):
        for v in variables:
            if isinstance(v, dict) and v.get("name"):
                if str(v.get("issecret", "")).lower() == "true":
                    names.add(str(v["name"]))
    return frozenset(names)


def _step_script_body(step: dict[str, Any]) -> str:
    for key in ("script", "bash", "powershell", "pwsh"):
        val = step.get(key)
        if isinstance(val, str):
            return val
    return ""


def check(path: str, doc: dict[str, Any]) -> Finding:
    secret_names = _collect_secret_var_names(doc)
    offenders: list[str] = []
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            body = _step_script_body(step)
            if not body.strip():
                continue
            hits = scan_script_for_leaked_secrets(
                body,
                known_secret_names=secret_names,
                ado_mode=True,
            )
            for h in hits:
                offenders.append(f"{job_loc}.{step_loc}: {h}")
    passed = not offenders
    desc = (
        "No script step prints a secret variable to the build log."
        if passed else
        f"{len(offenders)} leak(s) detected: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
