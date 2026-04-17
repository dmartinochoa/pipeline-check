"""GHA-010 — local `uses: ./path` forbidden on untrusted-trigger workflows."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers
from ._helpers import UNTRUSTED_TRIGGERS

RULE = Rule(
    id="GHA-010",
    title="Local action (./path) on untrusted-trigger workflow",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-PIN-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Move the action to a separate repo under your control and "
        "reference it by SHA-pinned `uses: org/repo@<sha>`, or split "
        "the workflow so the privileged work runs only on "
        "`pull_request` (read-only token, no secrets) where "
        "PR-controlled action.yml can't escalate."
    ),
    docs_note=(
        "`uses: ./path/to/action` resolves the action against the "
        "CHECKED-OUT workspace. On `pull_request_target` / "
        "`workflow_run`, that workspace can be PR-controlled — "
        "meaning the attacker supplies the `action.yml` that runs "
        "with default-branch privilege."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    if not triggers & UNTRUSTED_TRIGGERS:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow has no untrusted trigger.",
            recommendation="No action required.", passed=True,
        )
    offending: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            if isinstance(uses, str) and uses.startswith(("./", "../")):
                offending.append(f"{job_id}[{idx}]: {uses}")
    passed = not offending
    desc = (
        "No local-path actions referenced from an untrusted-trigger workflow."
        if passed else
        f"Workflow with untrusted trigger "
        f"({', '.join(sorted(triggers & UNTRUSTED_TRIGGERS))}) "
        f"references local action(s) at: {', '.join(offending[:5])}"
        f"{'…' if len(offending) > 5 else ''}. The action.yml is "
        f"resolved against the checked-out workspace, which on this "
        f"trigger may be PR-controlled — letting the attacker ship "
        f"arbitrary action code into the privileged context."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
