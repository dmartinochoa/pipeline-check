"""GL-029 — Manual deploy jobs must set ``allow_failure: false``.

GitLab's default ``allow_failure`` for a ``when: manual`` job is
``true`` — meaning the pipeline reports success even when the manual
job was never clicked. A ``deploy: when: manual`` without
``allow_failure: false`` is therefore a *visual* gate only; any
downstream job (and the pipeline overall) proceeds as though the
human approved.

This rule fires on the subset of jobs already classified as deploy-
like by GL-004's heuristics — stage or name contains
``deploy``/``release``/``publish``/``promote``, or the script invokes
a known deploy command — that also declare ``when: manual`` (directly
or via ``rules:``) but leave ``allow_failure`` unset or ``true``.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts
from ._helpers import DEPLOY_RE, rules_manual

# Mirror GL-004's deploy-command heuristic so the two rules agree on
# which jobs are "deploy-like". Kept as a local copy (rather than an
# import of a private from GL-004) to avoid a cross-rule dependency.
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
    id="GL-029",
    title="Manual deploy job defaults to allow_failure: true",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-284",),
    recommendation=(
        "Add ``allow_failure: false`` to every deploy-like ``when: "
        "manual`` job. GitLab defaults ``allow_failure`` to *true* "
        "for manual jobs, which makes the pipeline report success "
        "whether or not the operator clicks — exactly the opposite of "
        "the gate you meant to add."
    ),
    docs_note=(
        "This is the most common GitLab deployment gotcha: a manual "
        "``deploy`` job looks like a gate in the UI, but the pipeline "
        "reports success on the first run because the job is marked "
        "allow_failure by default. Downstream jobs (and the overall "
        "pipeline status) proceed as though the human approved."
    ),
)


def _is_deploy_like(name: str, job: dict[str, Any]) -> bool:
    stage = job.get("stage")
    if isinstance(stage, str) and DEPLOY_RE.search(stage):
        return True
    if DEPLOY_RE.search(name):
        return True
    return any(_DEPLOY_CMD_RE.search(line) for line in job_scripts(job))


def _is_manual(job: dict[str, Any]) -> bool:
    if job.get("when") == "manual":
        return True
    return rules_manual(job.get("rules"))


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        if not _is_deploy_like(name, job):
            continue
        if not _is_manual(job):
            continue
        # allow_failure must be explicitly False — unset or True both
        # default to "the pipeline proceeds regardless".
        if job.get("allow_failure") is not False:
            offenders.append(name)
    passed = not offenders
    desc = (
        "Every manual deploy job explicitly sets ``allow_failure: false``."
        if passed else
        f"{len(offenders)} manual deploy job(s) rely on the default "
        f"``allow_failure: true`` and therefore do not block the "
        f"pipeline if unclicked: {', '.join(offenders)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
