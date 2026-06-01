"""GHA-112. Self-hosted deploy job not gated by a protected environment.

A deploy that runs on a self-hosted runner without an ``environment:``
binding is GHA-014's ungated-deploy gap on persistent infrastructure.
Two things stack:

  * **Self-hosted runner.** The job runs on a runner the org owns and
    keeps online across jobs (vs an ephemeral GitHub-hosted VM). It
    holds standing deploy credentials (a kubeconfig, a long-lived cloud
    role, SSH keys to prod) and usually sits inside the network it
    deploys to.
  * **No environment gate.** With no ``environment:`` GitHub can't
    require a reviewer, enforce a deployment-branch policy, or apply a
    wait timer. Any push to the triggering branch deploys immediately.

Together: a low-privilege trigger (a push, a self-merged PR) reaches
persistent org infrastructure that ships to production with standing
credentials and no human approval. An attacker who lands a commit, or
who compromises the shared runner, deploys at will.

GHA-014 (MEDIUM) flags the missing ``environment:`` on any deploy; this
rule is the HIGH self-hosted case, where the blast radius is the org's
own infrastructure and the same runner persists across the untrusted
and the privileged jobs. Both fire on a self-hosted ungated deploy and
the environment binding fixes both. Complements GHA-012 (ephemeral),
GHA-068 (deprecated runner image), and GHA-105 (self-hosted reachable
from a PR trigger).
"""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import DEPLOY_CMD_RE, DEPLOY_RE
from ..._primitives.local_mock import env_targets_local_mock
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-112",
    title="Self-hosted deploy job not gated by a protected environment",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1", "CICD-SEC-7"),
    esf=("ESF-C-APPROVAL", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-284", "CWE-269"),
    recommendation=(
        "Bind the deploy job to a protected `environment:` with "
        "required reviewers and a deployment-branch policy, and prefer "
        "ephemeral self-hosted runners (actions-runner-controller, "
        "`--ephemeral`) so a job can't inherit state or credentials "
        "from a previous one. Best: run the deploy from a dedicated, "
        "minimally-scoped runner pool that only the gated job can "
        "reach, and keep untrusted-trigger jobs (fork PRs) off the "
        "self-hosted fleet entirely (see GHA-105)."
    ),
    docs_note=(
        "Fires when a job (1) runs on a self-hosted runner (the "
        "`self-hosted` label on any `runs-on` shape: string, list, or "
        "`{ group, labels }` dict), (2) is a deploy, by job-name "
        "(`deploy` / `release` / `publish` / `promote`) or by a deploy "
        "command in a `run:` step (`kubectl apply`, `terraform apply`, "
        "`helm upgrade`, `aws ... deploy`, `gcloud ... deploy`, etc.), "
        "and (3) has no `environment:` binding. A job whose deploy "
        "commands all target a local mock (LocalStack / kind via "
        "`AWS_ENDPOINT_URL` / `KUBE_API_URL` at a localhost address) is "
        "treated as a test, not a deploy. Overlaps GHA-014 on the "
        "missing-environment axis but is scoped to the higher-severity "
        "self-hosted case; the same `environment:` fix clears both."
    ),
    known_fp=(
        "A self-hosted job named `release` (or running a deploy "
        "command) that targets a staging / preview account where an "
        "approval gate is intentionally skipped. Bind a separate "
        "`environment:` for non-prod with no required reviewers so the "
        "intent is explicit in the workflow, or suppress with a "
        "rationale. Defaults to MEDIUM confidence because deploy "
        "detection is a name / command heuristic.",
    ),
    incident_refs=(
        "OWASP CICD-SEC-1 (Insufficient Flow Control Mechanisms) and "
        "CICD-SEC-7 (Insecure System Configuration): persistent "
        "self-hosted runners that deploy without an approval gate let a "
        "single low-privilege trigger reach production infrastructure.",
    ),
    exploit_example=(
        "# Vulnerable: a self-hosted deploy job with no environment.\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: [self-hosted, linux, prod]\n"
        "    steps:\n"
        "      - run: kubectl apply -f k8s/   # standing kubeconfig on the runner\n"
        "\n"
        "# Attack: the runner is persistent org infrastructure with a\n"
        "# standing kubeconfig, and there's no `environment:` to require\n"
        "# a reviewer or a deployment-branch policy. Any commit that\n"
        "# lands on main, a self-merged PR, a push from a compromised\n"
        "# contributor, or an attacker who compromised the shared\n"
        "# runner, deploys to the prod cluster with no approval.\n"
        "\n"
        "# Safe: gate the deploy behind a protected environment and run\n"
        "# it on an ephemeral, deploy-only runner pool.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: [self-hosted, ephemeral, deploy]\n"
        "    environment: production   # required reviewers configured here\n"
        "    steps:\n"
        "      - run: kubectl apply -f k8s/"
    ),
)


def _runs_on_self_hosted(job: dict[str, Any]) -> bool:
    runs_on = job.get("runs-on")
    labels: list[str] = []
    if isinstance(runs_on, str):
        labels = [runs_on]
    elif isinstance(runs_on, list):
        labels = [str(x) for x in runs_on]
    elif isinstance(runs_on, dict):
        ll = runs_on.get("labels")
        if isinstance(ll, list):
            labels = [str(x) for x in ll]
        elif isinstance(ll, str):
            labels = [ll]
    return "self-hosted" in {lbl.lower() for lbl in labels}


def _job_targets_local_mock(job: dict[str, Any]) -> bool:
    if env_targets_local_mock(job.get("env")):
        return True
    return any(env_targets_local_mock(s.get("env")) for s in iter_steps(job))


def _is_deploy_job(job_id: str, job: dict[str, Any]) -> bool:
    if _job_targets_local_mock(job):
        return False
    if DEPLOY_RE.search(job_id):
        return True
    return any(
        isinstance(s.get("run"), str) and DEPLOY_CMD_RE.search(s["run"])
        for s in iter_steps(job)
    )


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending: list[str] = []
    for job_id, job in iter_jobs(doc):
        if not _runs_on_self_hosted(job):
            continue
        if job.get("environment"):
            continue
        if _is_deploy_job(job_id, job):
            offending.append(job_id)
    passed = not offending
    desc = (
        "No self-hosted deploy job runs without a protected environment."
        if passed else
        f"{len(offending)} self-hosted deploy job(s) have no "
        f"`environment:` gate: {', '.join(offending)}. The deploy runs "
        f"on persistent org infrastructure with standing credentials "
        f"and no required reviewer, so any push to the triggering "
        f"branch (or a compromise of the shared runner) ships to "
        f"production unattended."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=tuple(offending),
    )
