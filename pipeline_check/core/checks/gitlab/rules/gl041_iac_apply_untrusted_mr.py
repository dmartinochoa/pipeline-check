"""GL-041. Unattended IaC apply on an untrusted merge-request trigger."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import IAC_APPLY_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts
from ._helpers import job_runs_on_mr

RULE = Rule(
    id="GL-041",
    title="IaC apply on an untrusted merge-request trigger",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-78"),
    recommendation=(
        "Never run `terraform apply` (or `cloudformation deploy` / "
        "`cdk deploy` / `pulumi up` / `sam deploy`) in a job reachable "
        "from a merge-request pipeline. Apply executes the MR branch's "
        "IaC, so an `external` data source, a `local-exec` provisioner, "
        "or a hijacked provider runs arbitrary code on the runner with "
        "whatever cloud credentials (often an OIDC role via "
        "`id_tokens:`) the apply uses. On merge requests run a read-only "
        "`plan` and post it for review; gate the apply on a protected "
        "branch (`if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`) with "
        "`when: manual` or an `environment:` so it runs against merged, "
        "reviewed code."
    ),
    docs_note=(
        "Fires when a job runs an unattended IaC apply "
        "(`terraform`/`terragrunt apply` or `destroy`, `aws "
        "cloudformation deploy`/`create-stack`/`update-stack`/"
        "`execute-change-set`, `cdk deploy`, `pulumi up`, `sam deploy`) "
        "AND the job is reachable on a merge-request pipeline (its own "
        "`rules:` admit `merge_request_event`, its legacy `only:` "
        "includes `merge_requests`, or it inherits a `workflow:` that "
        "admits MR pipelines). Applying an MR author's IaC is the "
        "plan/apply-on-untrusted-input RCE class. GL-004 already flags "
        "this as an ungated deploy; GL-041 names the apply-RCE shape and "
        "raises it to CRITICAL when the trigger is merge-request reach."
    ),
    exploit_example=(
        "# Vulnerable: applies the MR branch's Terraform on every MR.\n"
        "terraform_apply:\n"
        "  stage: deploy\n"
        "  id_tokens:\n"
        "    AWS_TOKEN:              # cloud OIDC consumed by the apply\n"
        "      aud: https://gitlab.example.com\n"
        "  script:\n"
        "    - terraform init\n"
        "    - terraform apply -auto-approve\n"
        "  rules:\n"
        "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
        "\n"
        "# Attack: an MR adds a malicious `external` data source or a\n"
        "# `local-exec` provisioner. `terraform apply` executes it on the\n"
        "# runner with the OIDC cloud credentials in scope, so the MR\n"
        "# author gets arbitrary code execution plus the cloud role,\n"
        "# without the change ever being reviewed or merged.\n"
        "\n"
        "# Safe: plan-only (for review) on MRs; apply post-merge on the\n"
        "# default branch behind a manual gate.\n"
        "terraform_plan:\n"
        "  stage: test\n"
        "  script:\n"
        "    - terraform init\n"
        "    - terraform plan\n"
        "  rules:\n"
        "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
        "terraform_apply:\n"
        "  stage: deploy\n"
        "  environment: production\n"
        "  script:\n"
        "    - terraform apply -auto-approve\n"
        "  rules:\n"
        "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n"
        "      when: manual"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        if not job_runs_on_mr(doc, job):
            continue
        if any(IAC_APPLY_RE.search(line) for line in job_scripts(job)):
            offenders.append(name)
    passed = not offenders
    desc = (
        "No unattended IaC apply runs in a merge-request-reachable job."
        if passed else
        f"{len(offenders)} job(s) run an unattended IaC apply on a "
        f"merge-request-reachable pipeline: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. An MR author's IaC "
        f"executes at apply time with the job's cloud credentials, "
        f"before the change is reviewed or merged."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        # The offending job IDs so the reachability-aware chain engine can
        # intersect them with an injection leg's jobs. Empty on a pass.
        job_anchors=tuple(offenders),
    )
