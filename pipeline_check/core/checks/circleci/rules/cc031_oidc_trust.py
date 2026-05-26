"""CC-031. OIDC role assumption without branch filter or approval gate.

Narrows CC-030 to specifically the OIDC-role-assumption shape. CC-030
catches every ungated context binding (MEDIUM); CC-031 catches the
narrower case where a workflow job passes a ``role_arn`` /
``oidc_role_arn`` parameter to an orb, which is a higher-consequence
finding (HIGH) because the blast radius is the entire trusted cloud
account, not just the secrets in a CircleCI context.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_workflow_jobs

#: Parameter names that pass a cloud-role ARN into an orb job at the
#: workflow-binding layer. Detection signal is intentionally name-
#: based, every common AWS / Azure / GCP CircleCI orb uses one of
#: these conventions and the parameter shape is stable.
_OIDC_ROLE_PARAMS = (
    "role-arn",
    "aws-role-arn",
    "oidc-role-arn",
    "aws-oidc-role-arn",
)


def _has_oidc_role_param(job_cfg: dict[str, Any]) -> bool:
    """True when the workflow job binding passes any of the OIDC-role
    parameter names. Values are not validated, the *presence* of
    the parameter is the signal that role assumption happens."""
    return any(p in job_cfg for p in _OIDC_ROLE_PARAMS)


def _has_branch_filter(job_cfg: dict[str, Any]) -> bool:
    """True when the job entry declares a non-empty ``filters.branches.only``."""
    filters = job_cfg.get("filters") or {}
    if not isinstance(filters, dict):
        return False
    branches = filters.get("branches") or {}
    if not isinstance(branches, dict):
        return False
    only = branches.get("only")
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
    requires = job_cfg.get("requires") or []
    if isinstance(requires, str):
        requires = [requires]
    if not isinstance(requires, list):
        return False
    return any(r in approval_job_names for r in requires)


RULE = Rule(
    id="CC-031",
    title="OIDC role assumption without branch filter or approval gate",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Restrict every workflow job that passes a cloud ``role_arn`` "
        "(or equivalent OIDC parameter) to a protected branch list, "
        "or require a ``type: approval`` predecessor. Without either "
        "gate, any push triggers a cloud-role assumption with the full "
        "blast radius of the IdP-side trust policy."
    ),
    docs_note=(
        "Pairs with IAM-008. IAM-008 verifies the cloud-side trust "
        "policy pins audience + subject; this rule verifies the "
        "CircleCI-side workflow can't drive the role assumption "
        "from any branch. Distinct from CC-030 (broad context "
        "binding, MEDIUM); CC-031 narrows to OIDC role assumption "
        "and is HIGH because role-bound credentials reach further "
        "than the project-scoped secrets in a context."
    ),
    exploit_example=(
        "# Vulnerable: ``aws-cli/oidc-assume-role`` runs from a\n"
        "# job with no branch filter and no approval gate. The\n"
        "# AWS trust policy on the assumed role accepts any OIDC\n"
        "# token from the project, including tokens minted by\n"
        "# PR builds. A fork-PR build assumes the prod role and\n"
        "# does whatever the role permits.\n"
        "version: 2.1\n"
        "orbs:\n"
        "  aws-cli: circleci/aws-cli@4.1.3\n"
        "workflows:\n"
        "  deploy:\n"
        "    jobs:\n"
        "      - aws-cli/oidc-assume-role:\n"
        "          role-arn: arn:aws:iam::123:role/prod-deploy\n"
        "          # no branch filter, no approval gate\n"
        "\n"
        "# Safe: branch-filter to ``main`` (or the release\n"
        "# branches you trust) AND add a hold step requiring\n"
        "# human approval. The OIDC token mint is now gated\n"
        "# behind both source-branch and human gates.\n"
        "version: 2.1\n"
        "orbs:\n"
        "  aws-cli: circleci/aws-cli@4.1.3\n"
        "workflows:\n"
        "  deploy:\n"
        "    jobs:\n"
        "      - hold:\n"
        "          type: approval\n"
        "          filters: { branches: { only: main } }\n"
        "      - aws-cli/oidc-assume-role:\n"
        "          requires: [hold]\n"
        "          role-arn: arn:aws:iam::123:role/prod-deploy\n"
        "          filters: { branches: { only: main } }"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    approvals_by_workflow: dict[str, set[str]] = {}
    for wf_name, job_name, job_cfg in iter_workflow_jobs(doc):
        if not _has_oidc_role_param(job_cfg):
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
        "Every workflow job that requests OIDC role assumption is "
        "gated by a branch filter or an approval predecessor."
        if passed else
        f"{len(offenders)} workflow job(s) request OIDC role assumption "
        f"with no branch filter or approval gate: "
        f"{', '.join(offenders)}. Any push to the project drives a "
        f"cloud-role assumption."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
