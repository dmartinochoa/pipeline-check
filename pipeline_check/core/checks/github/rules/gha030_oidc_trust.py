"""GHA-030. OIDC token requested without environment-protected job."""
from __future__ import annotations

from typing import Any

from ..._primitives.anchors import iam_role, iam_role_name
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

#: ``uses:`` prefixes that exchange the GHA OIDC token for cloud
#: credentials. A job that invokes any of these without an attached
#: ``environment:`` is unprotected, any branch with push access (or
#: a fork PR, depending on the trigger) can drive the role assumption.
_OIDC_CRED_STEPS = (
    "aws-actions/configure-aws-credentials",
    "azure/login",
    "google-github-actions/auth",
)


def _job_has_id_token(job: dict[str, Any], workflow: dict[str, Any]) -> bool:
    """Return True if *job* effectively has ``id-token: write``.

    GitHub's permission semantics: a job-level ``permissions:`` block
    REPLACES the workflow-level block (it does not merge). Without a
    job-level block, the job inherits the workflow's permissions; with
    one, only the keys the job declares apply.
    """
    job_perms = job.get("permissions")
    if isinstance(job_perms, dict):
        return job_perms.get("id-token") == "write"
    if isinstance(job_perms, str):
        return job_perms == "write-all"
    wf_perms = workflow.get("permissions")
    if isinstance(wf_perms, dict):
        return wf_perms.get("id-token") == "write"
    if isinstance(wf_perms, str):
        return wf_perms == "write-all"
    return False


def _job_invokes_oidc_step(job: dict[str, Any]) -> bool:
    """Return True if any step uses an OIDC cloud-credentials action."""
    for step in iter_steps(job):
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        action = uses.split("@", 1)[0]
        if any(action.startswith(prefix) for prefix in _OIDC_CRED_STEPS):
            return True
    return False


def _job_aws_role_anchors(job: dict[str, Any]) -> list[ResourceAnchor]:
    """Extract canonical IAM role anchors from this job's AWS OIDC step(s).

    Walks every ``aws-actions/configure-aws-credentials`` step in the
    job and reads its ``with.role-to-assume``. Full ARNs become
    ``iam_role`` anchors that cross-provider chains (AC-016) can
    intersect with IAM-002's role-ARN anchors; bare role names emit
    the looser ``iam_role_name`` kind, which won't fuzzy-match into
    ``iam_role`` (canonicalizer carve-out) and falls back to
    co-occurrence in the chain engine. Templated values
    (``${{ secrets.ROLE_ARN }}``, ``${{ vars.* }}``) can't be
    resolved at scan time, so they produce no anchor — better to
    emit nothing than a placeholder that silently misses.
    """
    anchors: list[ResourceAnchor] = []
    for step in iter_steps(job):
        uses = step.get("uses")
        if not isinstance(uses, str):
            continue
        action = uses.split("@", 1)[0]
        if not action.startswith("aws-actions/configure-aws-credentials"):
            continue
        with_block = step.get("with") or {}
        if not isinstance(with_block, dict):
            continue
        raw = with_block.get("role-to-assume")
        if not isinstance(raw, str):
            continue
        raw = raw.strip()
        if not raw or "${{" in raw:
            # Templated reference; the live value is only known at
            # runtime, so we can't canonicalize it.
            continue
        built = iam_role(raw) or iam_role_name(raw)
        if built is not None:
            anchors.append(built)
    return anchors


RULE = Rule(
    id="GHA-030",
    title="OIDC token requested without environment-protected job",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Bind every job that exchanges the GHA OIDC token for cloud "
        "credentials to a protected ``environment:`` (e.g. "
        "``environment: production``). Environment protections layer "
        "in branch restrictions, required reviewers, and deployment "
        "windows that the IdP-side trust policy cannot enforce alone."
    ),
    docs_note=(
        "Pairs with IAM-008. IAM-008 verifies the AWS-side trust "
        "policy pins audience + subject; this rule verifies the "
        "GitHub-side workflow can't request the token from any "
        "branch without a deployment gate. A misconfiguration on "
        "either side defeats the OIDC story."
    ),
    exploit_example=(
        "# Vulnerable: a job requests an OIDC token (``id-token:\n"
        "# write``) without an ``environment:`` binding. The token\n"
        "# can be minted from any branch or any PR trigger; if the\n"
        "# AWS / GCP / Azure trust policy permits any subject from\n"
        "# the repo, a fork-PR build assumes prod.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "      contents: read\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<sha>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123:role/prod-deploy\n"
        "          aws-region: us-east-1\n"
        "\n"
        "# Safe: bind the job to a protected environment that\n"
        "# requires reviewer approval. The OIDC token is only\n"
        "# mintable after the human gate fires AND the cloud-side\n"
        "# trust policy pins ``sub`` to the protected environment.\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    environment: production   # required-reviewers gate\n"
        "    permissions:\n"
        "      id-token: write\n"
        "      contents: read\n"
        "    steps:\n"
        "      - uses: aws-actions/configure-aws-credentials@<sha>\n"
        "        with:\n"
        "          role-to-assume: arn:aws:iam::123:role/prod-deploy\n"
        "          aws-region: us-east-1"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # ResourceAnchor phase 1: collect the IAM role ARNs the offending
    # jobs assume so AC-016 can intersect with IAM-002's role anchors.
    # Order-preserving dict de-dupes when multiple offending jobs
    # name the same role.
    role_anchors: dict[str, ResourceAnchor] = {}
    for job_id, job in iter_jobs(doc):
        if not _job_has_id_token(job, doc):
            continue
        if not _job_invokes_oidc_step(job):
            continue
        if "environment" in job:
            continue
        offenders.append(job_id)
        for anchor in _job_aws_role_anchors(job):
            role_anchors[anchor.identity] = anchor
    passed = not offenders
    desc = (
        "Every job that requests an OIDC token to assume a cloud role "
        "is bound to a protected environment."
        if passed else
        f"Job(s) {', '.join(offenders)} request ``id-token: write`` and "
        f"invoke a cloud-credentials action (configure-aws-credentials, "
        f"azure/login, or google-github-actions/auth) without an "
        f"``environment:`` binding. Without an environment, branch "
        f"protections and required reviewers don't gate the role "
        f"assumption."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=tuple(role_anchors.values()),
    )
