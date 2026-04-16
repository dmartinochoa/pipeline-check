"""ADO-004 — deployment jobs must bind an environment."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

_DEPLOY_CMD_RE = re.compile(
    r"(?:kubectl\s+apply|terraform\s+apply|aws\s+s3\s+cp"
    r"|docker\s+push|helm\s+(?:upgrade|install)"
    r"|gcloud\s+(?:app\s+deploy|run\s+deploy|functions\s+deploy))",
    re.IGNORECASE,
)

_DEPLOY_NAME_RE = re.compile(r"(?i)(deploy|release|publish|promote)")

RULE = Rule(
    id="ADO-004",
    title="Deployment job missing environment binding",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Add `environment: <name>` to every `deployment:` job. "
        "Configure approvals, required branches, and business-hours "
        "checks on the matching Environment in the ADO UI."
    ),
    docs_note=(
        "Without an `environment:` binding, ADO cannot enforce "
        "approvals, checks, or deployment history against a named "
        "resource. Every `deployment:` job should bind one."
    ),
)


def _job_has_deploy_commands(job: dict[str, Any]) -> bool:
    """Return True if any step in the job runs a deploy-like command."""
    for _, step in iter_steps(job):
        for key in ("script", "bash", "pwsh", "powershell"):
            body = step.get(key)
            if isinstance(body, str) and _DEPLOY_CMD_RE.search(body):
                return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    for job_loc, job in iter_jobs(doc):
        is_deploy = isinstance(job.get("deployment"), str)
        if not is_deploy:
            # Also check job name and script bodies for deploy commands.
            job_name = job.get("job") or job_loc
            is_deploy = (
                bool(_DEPLOY_NAME_RE.search(str(job_name)))
                or _job_has_deploy_commands(job)
            )
        if not is_deploy:
            continue
        if not job.get("environment"):
            ungated.append(job_loc)
    passed = not ungated
    desc = (
        "Every deployment job binds an `environment`."
        if passed else
        f"{len(ungated)} deployment job(s) have no `environment:` "
        f"binding: {', '.join(ungated)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
