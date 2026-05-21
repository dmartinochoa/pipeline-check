"""ADO-001, tasks must pin a full semver, not a floating major."""
from __future__ import annotations

from typing import Any

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import TASK_PIN_RE

RULE = Rule(
    id="ADO-001",
    title="Task reference not pinned to specific version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) "
        "or extension-published-version. Track task updates explicitly "
        "via Azure DevOps extension settings rather than letting `@1` "
        "drift."
    ),
    docs_note=(
        "Floating-major task references (`@1`, `@2`) can roll forward "
        "silently when the task publisher ships a breaking or malicious "
        "update. Pass when every `task:` reference carries a two- or "
        "three-segment semver."
    ),
    exploit_example=(
        "# Vulnerable: ``AzureCLI@2`` resolves to whatever\n"
        "# Microsoft ships as version 2 at job-start time. A\n"
        "# Microsoft-pushed update silently changes the task body;\n"
        "# more importantly, custom Marketplace tasks at floating\n"
        "# major version are repointable by their publisher.\n"
        "steps:\n"
        "  - task: AzureCLI@2\n"
        "    inputs:\n"
        "      azureSubscription: prod-sub\n"
        "      scriptType: bash\n"
        "      scriptLocation: inlineScript\n"
        "      inlineScript: az deploy ...\n"
        "\n"
        "# Safe: pin to a specific patch version (``AzureCLI@2.245.0``)\n"
        "# or use ``AzureCLI@2.x`` only for first-party Microsoft\n"
        "# tasks where Marketplace publish controls are stronger.\n"
        "# Renovate's azure-pipelines updater bumps these.\n"
        "steps:\n"
        "  - task: AzureCLI@2.245.0\n"
        "    inputs:\n"
        "      azureSubscription: prod-sub\n"
        "      scriptType: bash\n"
        "      scriptLocation: inlineScript\n"
        "      inlineScript: az deploy ..."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unpinned: list[str] = []
    locations: list[Location] = []
    for job_loc, job in iter_jobs(doc):
        for step_loc, step in iter_steps(job):
            ref = step.get("task")
            if not isinstance(ref, str) or "@" not in ref:
                continue
            if not TASK_PIN_RE.search(ref):
                unpinned.append(f"{job_loc}.{step_loc}: {ref}")
                line = _line_of(step) if isinstance(step, dict) else None
                locations.append(
                    Location(path=path, start_line=line, end_line=line)
                )
    passed = not unpinned
    desc = (
        "Every `task:` reference is pinned to a specific version."
        if passed else
        f"{len(unpinned)} `task:` reference(s) pinned to a major-only "
        f"version: {', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}. A floating major tag can "
        f"roll forward silently when the task publisher ships a "
        f"breaking or malicious update."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
