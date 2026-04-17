"""CC-030 — Workflow job carries ``context:`` but is not gated.

A CircleCI context holds secrets (API tokens, cloud credentials).
Binding a context to a job grants the job's steps access to those
secrets. If the job has no branch filter and no manual-approval
predecessor, *any* push — including feature branches, personal
branches, and (depending on project settings) fork PRs — runs with
those secrets loaded. This rule fires when that condition holds.

Distinct from:

- **CC-004** — flags jobs that declare secret-looking variables
  inline instead of using a context. CC-030 assumes the context
  pattern is right and audits the gating around it.
- **CC-009** — flags *deploy-like* jobs without approval. CC-030
  doesn't care about the job name; a test job pulling a production
  secret is the same threat model.
- **CC-013** — flags deploys without branch filters; CC-030 requires
  *either* a branch filter *or* an approval predecessor, not both.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_workflow_jobs

RULE = Rule(
    id="CC-030",
    title="Workflow job uses context without branch filter or approval gate",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS", "ESF-C-APPROVAL"),
    cwe=("CWE-732",),
    recommendation=(
        "Either add ``filters.branches.only: [<protected branches>]`` "
        "to restrict when the context-bound job runs, or require a "
        "``type: approval`` job in ``requires:`` so a human gates the "
        "secret-carrying execution. Without either gate, every push to "
        "the project loads the context's secrets into an ephemeral "
        "runner where any compromised step can exfiltrate them."
    ),
    docs_note=(
        "CircleCI contexts are the recommended way to store shared "
        "secrets, but binding a context to a job is only half of least-"
        "privilege — the other half is controlling *when* the binding "
        "activates. Unrestricted workflow entries with ``context:`` "
        "turn every branch push into a secret-read event."
    ),
)


def _has_branch_filter(job_cfg: dict[str, Any]) -> bool:
    """True when the job entry declares a non-empty ``filters.branches.only``."""
    filters = job_cfg.get("filters") or {}
    if not isinstance(filters, dict):
        return False
    branches = filters.get("branches") or {}
    if not isinstance(branches, dict):
        return False
    only = branches.get("only")
    if only is None:
        return False
    if isinstance(only, str):
        return bool(only.strip())
    if isinstance(only, list):
        return any(isinstance(x, str) and x.strip() for x in only)
    return False


def _approval_jobs_in_workflow(doc: dict[str, Any], workflow_name: str) -> set[str]:
    """Return the set of approval-typed job names defined in *workflow_name*."""
    names: set[str] = set()
    for wf_name, job_name, job_cfg in iter_workflow_jobs(doc):
        if wf_name != workflow_name:
            continue
        if job_cfg.get("type") == "approval":
            names.add(job_name)
    return names


def _requires_has_approval(
    job_cfg: dict[str, Any], approval_job_names: set[str]
) -> bool:
    """True when the job's ``requires`` list names an approval predecessor."""
    requires = job_cfg.get("requires") or []
    if isinstance(requires, str):
        requires = [requires]
    if not isinstance(requires, list):
        return False
    return any(r in approval_job_names for r in requires)


def _has_context(job_cfg: dict[str, Any]) -> bool:
    ctx = job_cfg.get("context")
    if isinstance(ctx, str):
        return bool(ctx.strip())
    if isinstance(ctx, list):
        return any(isinstance(c, str) and c.strip() for c in ctx)
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # Cache approval-name lookups per workflow — iter_workflow_jobs can
    # visit the same workflow many times as it walks jobs.
    approvals_by_workflow: dict[str, set[str]] = {}
    for wf_name, job_name, job_cfg in iter_workflow_jobs(doc):
        if not _has_context(job_cfg):
            continue
        # Approval jobs themselves don't execute steps and don't load
        # the context secrets into a shell — exclude them.
        if job_cfg.get("type") == "approval":
            continue
        if _has_branch_filter(job_cfg):
            continue
        approvals = approvals_by_workflow.get(wf_name)
        if approvals is None:
            approvals = _approval_jobs_in_workflow(doc, wf_name)
            approvals_by_workflow[wf_name] = approvals
        if _requires_has_approval(job_cfg, approvals):
            continue
        offenders.append(f"{wf_name}/{job_name}")
    passed = not offenders
    desc = (
        "Every context-bound workflow job has a branch filter or an "
        "approval predecessor."
        if passed else
        f"{len(offenders)} workflow job(s) use a context without a "
        f"branch filter or approval gate: {', '.join(offenders)}. Any "
        f"push to the project loads the context's secrets into an "
        f"ephemeral runner."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
