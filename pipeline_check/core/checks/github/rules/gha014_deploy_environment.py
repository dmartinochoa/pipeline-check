"""GHA-014 — deploy jobs should bind a GitHub environment."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

_DEPLOY_RE = re.compile(r"(?i)\b(deploy|release|publish|promote)\b")

_DEPLOY_CMD_RE = re.compile(
    r"(?:kubectl\s+(?:apply|create|set\s+image|rollout\s+restart)"
    r"|terraform\s+(?:apply|destroy)"
    r"|aws\s+(?:s3\s+(?:cp|sync)|cloudformation\s+deploy|ecs\s+update-service)"
    r"|docker\s+push"
    r"|helm\s+(?:upgrade|install)"
    r"|gcloud\s+(?:app\s+deploy|run\s+deploy|functions\s+deploy)"
    r"|ansible-playbook"
    r"|serverless\s+deploy"
    r"|az\s+(?:webapp\s+deploy|functionapp\s+deploy|containerapp\s+update))",
    re.IGNORECASE,
)


RULE = Rule(
    id="GHA-014",
    title="Deploy job missing environment binding",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Add `environment: <name>` to jobs that deploy. Configure "
        "required reviewers, wait timers, and branch-protection rules "
        "on the matching GitHub environment."
    ),
    docs_note=(
        "Without an `environment:` binding, a deploy job can't "
        "be gated by required reviewers, deployment-branch policies, "
        "or wait timers. Any push to the triggering branch will "
        "deploy immediately."
    ),
)


def _job_has_deploy_commands(job: dict[str, Any]) -> bool:
    """Return True if any step runs a deploy-like command."""
    for step in iter_steps(job):
        run = step.get("run")
        if isinstance(run, str) and _DEPLOY_CMD_RE.search(run):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    for job_id, job in iter_jobs(doc):
        is_deploy = bool(_DEPLOY_RE.search(job_id))
        if not is_deploy:
            is_deploy = _job_has_deploy_commands(job)
        if not is_deploy:
            continue
        if not job.get("environment"):
            ungated.append(job_id)
    passed = not ungated
    desc = (
        "Every deploy job binds a GitHub environment."
        if passed else
        f"{len(ungated)} deploy job(s) have no `environment:` binding: "
        f"{', '.join(ungated)}. Without an environment, the job "
        f"cannot be gated by required reviewers or branch policies."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
