"""GL-036. Script body echoes a secret-named variable to the build log."""
from __future__ import annotations

from typing import Any

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts

RULE = Rule(
    id="GL-036",
    title="Secret-named variable echoed / printed in a script block",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in CI scripts. GitLab's log "
        "masking only covers variables explicitly marked as masked "
        "in the UI, and only when the full value appears as a "
        "contiguous string. Base64-encoded, URL-encoded, or "
        "partial substrings bypass the mask. Log a boolean instead "
        "(``[ -n \"$X\" ] && echo set || echo unset``). Avoid "
        "``set -x`` when secret-bound variables are in scope."
    ),
    docs_note=(
        "Detects three shapes in ``script:``, ``before_script:``, "
        "and ``after_script:`` blocks:\n\n"
        "1. ``echo`` / ``printf`` / ``cat`` / ``tee`` of a variable "
        "whose name matches common secret patterns (PASSWORD, TOKEN, "
        "API_KEY, SECRET, CREDENTIAL, etc.).\n"
        "2. ``printenv`` / ``env`` commands that dump the entire "
        "environment (which includes CI/CD variables that may hold "
        "secrets).\n"
        "3. ``set -x`` (shell trace) enabled alongside any reference "
        "to a secret-named variable."
    ),
    exploit_example=(
        "# Vulnerable: echoes a variable likely holding a secret.\n"
        "deploy:\n"
        "  script:\n"
        "    - echo \"Token is $DEPLOY_TOKEN\"\n"
        "    - curl -H \"Authorization: Bearer $DEPLOY_TOKEN\" $URL\n"
        "\n"
        "# Safe: confirm the variable is set without printing it.\n"
        "deploy:\n"
        "  script:\n"
        "    - |\n"
        "      if [ -n \"$DEPLOY_TOKEN\" ]; then\n"
        "        echo \"DEPLOY_TOKEN is set\"\n"
        "      fi\n"
        "    - curl -H \"Authorization: Bearer $DEPLOY_TOKEN\" $URL"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_name, job in iter_jobs(doc):
        scripts = job_scripts(job)
        body = "\n".join(scripts)
        if not body.strip():
            continue
        hits = scan_script_for_leaked_secrets(body)
        for h in hits:
            offenders.append(f"{job_name}: {h}")
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
