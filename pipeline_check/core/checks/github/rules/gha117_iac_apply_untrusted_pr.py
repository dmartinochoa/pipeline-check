"""GHA-117. Unattended IaC apply on an untrusted pull_request trigger."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import IAC_APPLY_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers

# Triggers a PR author controls: ``pull_request`` runs the PR head's code;
# ``pull_request_target`` does the same but with the base repo's secrets
# and a write token in scope, so it is strictly worse.
_UNTRUSTED_PR_TRIGGERS = frozenset({"pull_request", "pull_request_target"})

RULE = Rule(
    id="GHA-117",
    title="IaC apply on an untrusted pull_request trigger",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-78"),
    recommendation=(
        "Never run ``terraform apply`` (or ``cloudformation deploy`` / "
        "``cdk deploy`` / ``pulumi up`` / ``sam deploy``) on a "
        "``pull_request`` or ``pull_request_target`` trigger. Apply "
        "executes the PR's IaC, an ``external`` data source, a "
        "``local-exec`` provisioner, or a hijacked provider runs "
        "arbitrary code on the runner with whatever cloud credentials "
        "(often an OIDC ``id-token``) the apply uses. On PRs run a "
        "read-only ``plan`` and post it for review; gate the apply on a "
        "separate ``push`` / ``workflow_dispatch`` trigger against the "
        "merged, reviewed code, behind a protected ``environment:``."
    ),
    docs_note=(
        "Fires when a workflow is triggered by ``pull_request`` or "
        "``pull_request_target`` AND a ``run:`` step invokes an "
        "unattended IaC apply (``terraform``/``terragrunt apply`` or "
        "``destroy``, ``aws cloudformation deploy``/``create-stack``/"
        "``update-stack``/``execute-change-set``, ``cdk deploy``, "
        "``pulumi up``, ``sam deploy``). Applying attacker-controlled IaC "
        "is the plan/apply-on-untrusted-input RCE class. Distinct from "
        "GHA-111, which requires an agentic CLI in the loop; here the "
        "untrusted input is the PR's own IaC."
    ),
    exploit_example=(
        "# Vulnerable: applies the PR's Terraform on every pull request.\n"
        "on: pull_request\n"
        "permissions:\n"
        "  id-token: write          # cloud OIDC consumed by the apply\n"
        "jobs:\n"
        "  apply:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: terraform init && terraform apply -auto-approve\n"
        "\n"
        "# Attack: a PR adds a malicious ``external`` data source or a\n"
        "# ``local-exec`` provisioner. ``terraform apply`` executes it on\n"
        "# the runner with the OIDC cloud credentials in scope, so the PR\n"
        "# author gets arbitrary code execution plus the cloud role.\n"
        "\n"
        "# Safe: plan-only (for review) on PRs; apply post-merge behind a\n"
        "# protected environment.\n"
        "on: pull_request\n"
        "jobs:\n"
        "  plan:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: terraform init && terraform plan"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    pr_triggers = sorted(triggers & _UNTRUSTED_PR_TRIGGERS)
    offenders: list[str] = []
    if pr_triggers:
        for job_id, job in iter_jobs(doc):
            for idx, step in enumerate(iter_steps(job)):
                run = step.get("run")
                if isinstance(run, str) and IAC_APPLY_RE.search(run):
                    offenders.append(f"{job_id}.steps[{idx}]")
    passed = not offenders
    desc = (
        "No unattended IaC apply runs on an untrusted pull_request trigger."
        if passed else
        f"{len(offenders)} step(s) run an unattended IaC apply on a "
        f"`{', '.join(pr_triggers)}` trigger: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. A PR author's IaC "
        f"executes at apply time with the job's cloud credentials."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
