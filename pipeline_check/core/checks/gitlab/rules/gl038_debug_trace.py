"""GL-038. CI_DEBUG_TRACE / CI_DEBUG_SERVICES dumps secrets to the job log."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

# GitLab debug-logging variables that expand the full environment (every
# CI/CD variable, including masked secrets and protected tokens) into the
# job trace. GitLab's trace masking is best-effort and does not cover the
# debug dump.
_DEBUG_VARS = ("CI_DEBUG_TRACE", "CI_DEBUG_SERVICES")
# GitLab enables debug logging when the variable is a truthy string. A
# bool ``true`` (some authors write it unquoted) counts too.
_TRUTHY = frozenset({"true", "1", "yes", "on"})


def _is_truthy(value: Any) -> bool:
    # bool first: bool is a subclass of int, so a bare ``true`` stays a
    # bool. YAML parses an unquoted ``1`` as int, which GitLab still reads
    # as the string "1", so coerce int/str alike before matching.
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, str)):
        return str(value).strip().lower() in _TRUTHY
    return False


def _var_scalar(raw: Any) -> Any:
    # GitLab variables are either a bare scalar or the typed form
    # ``{value: "true", description: "..."}``.
    if isinstance(raw, dict):
        return raw.get("value")
    return raw


def _debug_vars_in(block: Any) -> list[str]:
    """Return the debug var names set truthy in a ``variables:`` mapping."""
    if not isinstance(block, dict):
        return []
    return [
        name for name in _DEBUG_VARS
        if name in block and _is_truthy(_var_scalar(block[name]))
    ]


RULE = Rule(
    id="GL-038",
    title="CI_DEBUG_TRACE / debug logging dumps secrets to the job log",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Remove ``CI_DEBUG_TRACE`` / ``CI_DEBUG_SERVICES`` (or set them "
        "to ``false``) anywhere they ship in the repo. Debug trace "
        "expands the entire environment, including masked CI/CD "
        "variables and protected secrets, into the job log, where "
        "anyone with Reporter access (or the trace API) can read it. "
        "GitLab's log masking does not cover the debug dump. If you "
        "need a one-off debug run, enable it transiently from the "
        "pipeline UI on a job with no secrets in scope rather than "
        "committing it to ``.gitlab-ci.yml``."
    ),
    docs_note=(
        "Fires when ``CI_DEBUG_TRACE`` or ``CI_DEBUG_SERVICES`` is set "
        "to a truthy value (``\"true\"``, ``1``, ...) in the global "
        "``variables:`` block or any job's ``variables:`` block. Both "
        "the bare scalar form (``CI_DEBUG_TRACE: \"true\"``) and the "
        "typed form (``CI_DEBUG_TRACE: {value: \"true\"}``) are "
        "matched. It inverts a logging / visibility control into a "
        "secret-exfiltration channel: the job trace itself leaks every "
        "secret in scope, masking and all."
    ),
    exploit_example=(
        "# Vulnerable: debug trace dumps every variable to the log.\n"
        "variables:\n"
        "  CI_DEBUG_TRACE: \"true\"\n"
        "deploy:\n"
        "  script:\n"
        "    - deploy --token \"$PROD_TOKEN\"\n"
        "\n"
        "# Attack: any user with Reporter access opens the job trace (or\n"
        "# hits the trace API) and reads $PROD_TOKEN, $CI_JOB_TOKEN, and\n"
        "# every other masked variable in plaintext. Masking does not\n"
        "# apply to the debug dump.\n"
        "\n"
        "# Safe: never commit debug trace. Remove it (or set false).\n"
        "deploy:\n"
        "  script:\n"
        "    - deploy --token \"$PROD_TOKEN\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for name in _debug_vars_in(doc.get("variables")):
        offenders.append(f"global variables: {name}")
    for job_name, job in iter_jobs(doc):
        for name in _debug_vars_in(job.get("variables")):
            offenders.append(f"{job_name}: {name}")
    passed = not offenders
    desc = (
        "No job enables CI_DEBUG_TRACE / CI_DEBUG_SERVICES."
        if passed else
        f"{len(offenders)} debug-logging variable(s) enabled, dumping "
        f"the full environment (including masked secrets) to the job "
        f"log: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
