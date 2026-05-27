"""CC-032. Run step echoes a secret-named variable to the build log."""
from __future__ import annotations

from typing import Any

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands

RULE = Rule(
    id="CC-032",
    title="Secret-named variable echoed / printed in a run step",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in CI scripts. CircleCI masks "
        "context variables in logs, but only exact-match substrings. "
        "Encoded, truncated, or derived forms bypass the mask. Log "
        "a boolean instead (``[ -n \"$X\" ] && echo set || echo unset``). "
        "Avoid ``set -x`` when secret-bound variables are in scope."
    ),
    docs_note=(
        "Scans every ``run:`` command across all jobs. Variable names "
        "matching common secret patterns (PASSWORD, TOKEN, API_KEY, "
        "SECRET, CREDENTIAL) trigger the rule when they appear as "
        "arguments to ``echo``, ``printf``, ``cat``, or ``tee``. "
        "Also fires on ``printenv`` / ``env`` (full environment dump) "
        "and ``set -x`` with secret-named variables in scope."
    ),
    exploit_example=(
        "# Vulnerable: echoes a context variable to the log.\n"
        "jobs:\n"
        "  deploy:\n"
        "    docker:\n"
        "      - image: cimg/base:current\n"
        "    steps:\n"
        "      - run: echo \"Token is $DEPLOY_TOKEN\"\n"
        "\n"
        "# Safe: check existence without printing.\n"
        "jobs:\n"
        "  deploy:\n"
        "    docker:\n"
        "      - image: cimg/base:current\n"
        "    steps:\n"
        "      - run: '[ -n \"$DEPLOY_TOKEN\" ] && echo set || echo unset'"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for cmd in iter_run_commands(job):
            hits = scan_script_for_leaked_secrets(cmd)
            for h in hits:
                offenders.append(f"{job_id}: {h}")
    passed = not offenders
    desc = (
        "No run step prints a secret-named variable to the log."
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
