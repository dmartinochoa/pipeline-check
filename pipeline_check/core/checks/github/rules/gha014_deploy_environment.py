"""GHA-014, deploy jobs should bind a GitHub environment."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.deploy_names import DEPLOY_RE as _DEPLOY_RE
from ..._primitives.local_mock import env_targets_local_mock
from ..._primitives.oci_refs import extract_image_anchors_from_workflow
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

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
    known_fp=(
        "Integration-test jobs that run ``terraform apply`` or "
        "``kubectl apply`` against a local mock (LocalStack, Moto, "
        "kind, k3d) aren't real deploys. The rule auto-suppresses a "
        "step whose env carries ``AWS_ENDPOINT_URL`` or ``KUBE_API_URL`` "
        "pointing at a localhost address.",
    ),
)


def _job_targets_local_mock(job: dict[str, Any]) -> bool:
    """True when this job's deploy commands all run against a local mock.

    The signal is an ``AWS_ENDPOINT_URL`` (or sibling) pointing at a
    localhost address anywhere in the job: the job-level ``env``, or
    *any* step's ``env``. Workflow authors typically set the endpoint
    on a downstream verification step (the actual ``terraform apply``
    inherits the endpoint from a hardcoded provider config or a
    previously-set env) rather than re-pasting it on every step, so
    a job-wide scan is what matches real-world workflow shape.
    """
    if env_targets_local_mock(job.get("env")):
        return True
    for step in iter_steps(job):
        if env_targets_local_mock(step.get("env")):
            return True
    return False


def _job_has_deploy_commands(job: dict[str, Any]) -> bool:
    """Return True if any step runs a deploy-like command against a real target.

    Skips the whole job if any of its envs (job-level or any step's)
    pointed at a localhost mock. See :func:`_job_targets_local_mock`
    for the rationale; in practice the env is set on a verification
    step downstream of the ``terraform apply``, which is enough signal.
    """
    if _job_targets_local_mock(job):
        return False
    for step in iter_steps(job):
        run = step.get("run")
        if isinstance(run, str) and _DEPLOY_CMD_RE.search(run):
            return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    locations: list[Location] = []
    for job_id, job in iter_jobs(doc):
        is_deploy = bool(_DEPLOY_RE.search(job_id))
        if not is_deploy:
            is_deploy = _job_has_deploy_commands(job)
        if not is_deploy:
            continue
        if not job.get("environment"):
            ungated.append(job_id)
            # Anchor on the offending job entry so the user lands on
            # the line where ``environment:`` should be added.
            line = _line_of(job)
            if line is not None:
                locations.append(Location(
                    path=path, start_line=line, end_line=line,
                ))
    passed = not ungated
    desc = (
        "Every deploy job binds a GitHub environment."
        if passed else
        f"{len(ungated)} deploy job(s) have no `environment:` binding: "
        f"{', '.join(ungated)}. Without an environment, the job "
        f"cannot be gated by required reviewers or branch policies."
    )
    # ResourceAnchor phase 1: emit oci_image anchors for every image
    # this workflow's deploy steps reference (``kubectl set image``,
    # ``helm upgrade --set image=``, ``docker push``, etc. in any
    # offending job's ``run:`` block). AC-005 intersects these with
    # GHA-006's unsigned-build anchors on the canonical ``oci_image``
    # kind, confirming the deploy that lacks an environment gate IS
    # the same image the unsigned build ships. Only emit on a failing
    # finding.
    anchors = (
        extract_image_anchors_from_workflow(doc) if not passed else ()
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        # ``job_anchors`` carries the ungated deploy-job IDs so the
        # reachability-aware chain engine can intersect them with the
        # jobs an injection rule (GHA-003 / TAINT-001 / TAINT-002)
        # fired in. Empty tuple on a passed finding.
        job_anchors=tuple(ungated),
        resource_anchors=anchors,
    )
