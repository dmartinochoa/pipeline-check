"""ADO-032. ``checkout`` with persistCredentials leaks the pipeline token."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

_TRUTHY = frozenset({"true", "1", "yes", "on"})


def _truthy(value: Any) -> bool:
    return value is True or (
        isinstance(value, str) and value.strip().lower() in _TRUTHY
    )


RULE = Rule(
    id="ADO-032",
    title="checkout persistCredentials leaves the pipeline token in .git/config",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-522", "CWE-200"),
    recommendation=(
        "Drop ``persistCredentials: true`` from ``checkout`` steps "
        "(the default is ``false``). When set, Azure Pipelines writes "
        "the ``System.AccessToken`` (the pipeline's OAuth token) into "
        "``.git/config`` as an ``AUTHORIZATION: bearer`` extraheader "
        "after fetch, where every later step, including code from an "
        "untrusted PR, can read and reuse it to push or reach other "
        "repos. If a step genuinely needs to push back, scope a "
        "dedicated credential to that step instead of persisting the "
        "ambient token for the whole job."
    ),
    docs_note=(
        "The Azure analogue of the GitHub ``persist-credentials`` / "
        "ArtiPACKED leak (GHA-037). Fires on any ``checkout`` step "
        "(``checkout: self`` / a repository resource) that sets "
        "``persistCredentials: true``. The persisted token survives in "
        "``.git/config`` for the rest of the job, so a later "
        "``git config --get http.<host>.extraheader`` (or attacker-"
        "controlled build code) recovers it. Both the bare boolean and "
        "the quoted-string form are matched."
    ),
    exploit_example=(
        "# Vulnerable: persistCredentials writes the token to .git/config.\n"
        "steps:\n"
        "  - checkout: self\n"
        "    persistCredentials: true\n"
        "  - script: |\n"
        "      # any later step (or untrusted PR code) can read it:\n"
        "      git config --get http.https://dev.azure.com.extraheader\n"
        "\n"
        "# Attack: the System.AccessToken sits in .git/config as an\n"
        "# AUTHORIZATION bearer header. A compromised dependency or a\n"
        "# malicious PR build step base64-decodes it and reuses it to\n"
        "# push to the repo or reach other repos in the project.\n"
        "\n"
        "# Safe: leave persistCredentials at its default (false).\n"
        "steps:\n"
        "  - checkout: self"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            if "checkout" not in step:
                continue
            if _truthy(step.get("persistCredentials")):
                target = step.get("checkout")
                offenders.append(f"{job_loc}.{step_loc}: checkout {target}")
    passed = not offenders
    desc = (
        "No checkout step persists the pipeline token (persistCredentials)."
        if passed else
        f"{len(offenders)} checkout step(s) set ``persistCredentials: "
        f"true``, writing the pipeline OAuth token into .git/config for "
        f"every later step to read: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
