"""BB-032. Script echoes a secret-named variable to the build log."""
from __future__ import annotations

from typing import Any

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts

RULE = Rule(
    id="BB-032",
    title="Secret-named variable echoed / printed in a script block",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in pipeline scripts. Bitbucket's "
        "log masking covers secured variables, but only when the "
        "full value appears as a contiguous string. Base64-encoded, "
        "URL-encoded, or partial substrings bypass the mask. Log a "
        "boolean instead (``[ -n \"$X\" ] && echo set || echo unset``). "
        "Avoid ``set -x`` when secret-bound variables are in scope."
    ),
    docs_note=(
        "Scans every ``script:`` line across all pipeline steps. "
        "Variable names matching common secret patterns (PASSWORD, "
        "TOKEN, API_KEY, SECRET, CREDENTIAL) trigger the rule when "
        "they appear as arguments to ``echo``, ``printf``, ``cat``, "
        "or ``tee``. Also fires on ``printenv`` / ``env`` (full "
        "environment dump) and ``set -x`` with secret-named variables "
        "in scope."
    ),
    exploit_example=(
        "# Vulnerable: echoes a secured variable to the log.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - echo \"Key is $API_KEY\"\n"
        "\n"
        "# Safe: check existence without printing the value.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        script:\n"
        "          - '[ -n \"$API_KEY\" ] && echo API_KEY is set'"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for location, step in iter_steps(doc):
        scripts = step_scripts(step)
        body = "\n".join(scripts)
        if not body.strip():
            continue
        hits = scan_script_for_leaked_secrets(body)
        for h in hits:
            offenders.append(f"{location}: {h}")
    passed = not offenders
    desc = (
        "No script block prints a secret-named variable to the log."
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
