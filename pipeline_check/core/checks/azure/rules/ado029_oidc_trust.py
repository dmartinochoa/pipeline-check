"""ADO-029. Service-connection-using job without environment or branch gate."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

#: Tasks that consume an Azure service connection (the workload-
#: identity federation point for ADO). The ``inputs.azureSubscription``
#: / ``inputs.ConnectedServiceName`` field references the connection,
#: which carries the federation trust.
_AZURE_SC_TASK_PREFIXES = (
    "AzureCLI@",
    "AzurePowerShell@",
    "AzureKeyVault@",
    "AzureFileCopy@",
    "AzureWebApp@",
    "AzureRmWebAppDeployment@",
    "AzureContainerApps@",
    "AzureFunctionApp@",
    "AzureResourceManagerTemplateDeployment@",
)


def _step_uses_service_connection(step: dict[str, Any]) -> bool:
    """True when *step* invokes an Azure-task that consumes a service
    connection through ``inputs.azureSubscription`` or
    ``inputs.ConnectedServiceName``."""
    task = step.get("task")
    if not isinstance(task, str):
        return False
    if not any(task.startswith(prefix) for prefix in _AZURE_SC_TASK_PREFIXES):
        return False
    inputs = step.get("inputs") or {}
    if not isinstance(inputs, dict):
        return False
    return bool(inputs.get("azureSubscription")) or bool(inputs.get("ConnectedServiceName"))


def _job_has_branch_condition(job: dict[str, Any]) -> bool:
    """True when the job's ``condition:`` references ``Build.SourceBranch``.

    ADO ``condition:`` expressions are free-form strings; the
    canonical "deploy only on main" idiom is
    ``eq(variables['Build.SourceBranch'], 'refs/heads/main')``, any
    ``Build.SourceBranch`` mention in the condition is taken as a
    branch gate (false positives are acceptable; false negatives are
    not).
    """
    cond = job.get("condition")
    return isinstance(cond, str) and "Build.SourceBranch" in cond


RULE = Rule(
    id="ADO-029",
    title="Service-connection-using job without environment or branch gate",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Every job that consumes an Azure service connection (via "
        "``AzureCLI@``, ``AzurePowerShell@``, ``AzureKeyVault@``, "
        "``AzureWebApp@``, etc.) must either be a ``deployment:`` "
        "job bound to an ``environment:`` (which carries approval "
        "checks and audit) or carry a ``condition:`` that pins "
        "``Build.SourceBranch`` to a protected ref. Without one of "
        "those gates, any branch push drives the federated assume-"
        "role on Azure AD."
    ),
    docs_note=(
        "Pairs with IAM-008 (the AWS-side OIDC rule). Azure's "
        "equivalent trust path runs through service connections that "
        "map to Azure AD federated identity credentials. The "
        "ADO-side gate is either a deployment + environment or a "
        "branch-pinned condition; this rule flags jobs that have "
        "neither."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, job in iter_jobs(doc):
        # Deployment jobs bound to an environment are gated by
        # environment approvals, silent pass.
        is_deployment = "deployment" in job and job.get("environment") is not None
        if is_deployment:
            continue
        if _job_has_branch_condition(job):
            continue
        for step_loc, step in iter_steps(job):
            if _step_uses_service_connection(step):
                offenders.append(f"{loc}.{step_loc}: {step.get('task')}")
                break
    passed = not offenders
    desc = (
        "Every service-connection-using job is bound to a deployment "
        "environment or has a Build.SourceBranch condition."
        if passed else
        f"Service-connection use is ungated in: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Without a deployment "
        f"environment or branch condition, any push drives the "
        f"federated role assumption."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
