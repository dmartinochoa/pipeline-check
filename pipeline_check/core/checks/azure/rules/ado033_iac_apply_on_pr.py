"""ADO-033, IaC apply on a PR-validated pipeline."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import IAC_APPLY_RE
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="ADO-033",
    title="IaC apply on a PR-validated pipeline",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-78"),
    recommendation=(
        "Never run `terraform apply` (or `cloudformation deploy` / "
        "`cdk deploy` / `pulumi up` / `sam deploy` / `terragrunt apply`) "
        "in a pipeline that opts into PR validation (`pr:`). The PR "
        "branch's IaC executes at apply time, so an `external` data "
        "source, a `local-exec` provisioner, or a hijacked provider runs "
        "arbitrary code on the agent with whatever cloud credentials "
        "(often a federated service connection) the apply uses, before "
        "the change is reviewed or merged. On PR validation run a "
        "read-only `plan`; move the `apply` onto the default-branch "
        "(`trigger:`) leg, gated by a protected `environment:`."
    ),
    docs_note=(
        "Fires when a pipeline declares PR validation (`pr:` set to "
        "anything other than `none` / `false`) and any `script:` / "
        "`bash:` / `pwsh:` / `powershell:` step (or a task's "
        "`inputs.script`) runs an IaC apply command. A `pr:`-validated "
        "pipeline runs the PR branch's YAML and scripts, so the apply "
        "executes untrusted IaC. This is the Azure DevOps analog of "
        "GHA-117 / GL-041 / BB-033. A pipeline with no `pr:` key (or "
        "`pr: none`) is out of scope, matching ADO-011 / ADO-019."
    ),
    known_fp=(
        "A pipeline that runs `apply` only against a short-lived, "
        "fully-sandboxed review environment with no production-adjacent "
        "credentials. Even then the apply executes unreviewed IaC on the "
        "agent; prefer `plan` on PR validation. Suppress with a rationale "
        "naming the sandbox scope.",
    ),
    exploit_example=(
        "# Vulnerable: pipeline opts into PR validation and applies.\n"
        "trigger: [main]\n"
        "pr: [main]   # PR-validated: runs the PR branch's scripts\n"
        "steps:\n"
        "  - script: |\n"
        "      terraform init\n"
        "      terraform apply -auto-approve\n"
        "\n"
        "# Attack: a contributor opens a PR whose .tf adds\n"
        "#   data \"external\" \"x\" { program = [\"sh\",\"-c\",\"curl ...|sh\"] }\n"
        "# apply executes it on the agent with the service-connection role.\n"
        "\n"
        "# Safe: plan on PR validation, apply only on the default branch.\n"
        "trigger: [main]\n"
        "pr: [main]\n"
        "stages:\n"
        "  - stage: Validate\n"
        "    jobs:\n"
        "      - job: plan\n"
        "        steps:\n"
        "          - script: terraform plan\n"
        "  - stage: Apply\n"
        "    condition: eq(variables['Build.SourceBranch'], 'refs/heads/main')\n"
        "    jobs:\n"
        "      - deployment: apply\n"
        "        environment: prod\n"
        "        strategy:\n"
        "          runOnce:\n"
        "            deploy:\n"
        "              steps:\n"
        "                - script: terraform apply -auto-approve"
    ),
)


def _on_pr(doc: dict[str, Any]) -> bool:
    """True if the pipeline opts into PR validation (mirrors ADO-011)."""
    pr = doc.get("pr")
    return bool(
        (isinstance(pr, list) and pr)
        or isinstance(pr, dict)
        or (isinstance(pr, str) and pr.lower() not in ("none", "false"))
    )


def _step_scripts(step: dict[str, Any]) -> list[str]:
    """Every inline script body in *step* (shorthands + ``inputs.script``)."""
    bodies = [
        step[key] for key in ("script", "bash", "pwsh", "powershell")
        if isinstance(step.get(key), str)
    ]
    inputs = step.get("inputs")
    if isinstance(inputs, dict) and isinstance(inputs.get("script"), str):
        bodies.append(inputs["script"])
    return bodies


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not _on_pr(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not declare PR validation.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            if any(IAC_APPLY_RE.search(body) for body in _step_scripts(step)):
                offenders.append(f"{job_loc}.{step_loc}")
    passed = not offenders
    desc = (
        "No PR-validated step runs an unattended IaC apply."
        if passed else
        f"{len(offenders)} step(s) on a PR-validated pipeline run an "
        f"unattended IaC apply: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The PR branch's IaC "
        f"executes at apply time with the job's cloud credentials, "
        f"before the change is reviewed or merged."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
