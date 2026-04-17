"""BB-004 — deploy-like steps must declare `deployment:`."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_scripts
from ._helpers import DEPLOY_RE

_DEPLOY_CMD_RE = re.compile(
    r"(?:kubectl\s+(?:apply|create|set\s+image|rollout\s+restart)"
    r"|terraform\s+(?:apply|destroy)"
    r"|aws\s+(?:s3\s+(?:cp|sync)|cloudformation\s+deploy|ecs\s+update-service)"
    r"|docker\s+push"
    r"|helm\s+(?:upgrade|install)"
    r"|gcloud\s+(?:app\s+deploy|run\s+deploy|functions\s+deploy)"
    r"|ansible-playbook"
    r"|serverless\s+deploy"
    r"|az\s+(?:webapp\s+deploy|functionapp\s+deploy|containerapp\s+update))",
    re.IGNORECASE,
)

RULE = Rule(
    id="BB-004",
    title="Deploy step missing `deployment:` environment gate",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Add `deployment: production` (or `staging` / `test`) to the "
        "step. Configure the matching environment in the repo's "
        "Deployments settings with required reviewers and secured "
        "variables."
    ),
    docs_note=(
        "A step whose name or invoked pipe matches `deploy` / "
        "`release` / `publish` / `promote` should declare a "
        "`deployment:` field so Bitbucket enforces deployment-scoped "
        "variables, approvals, and history."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    for loc, step in iter_steps(doc):
        name = step.get("name") or ""
        if not isinstance(name, str):
            name = ""
        is_deploy = bool(DEPLOY_RE.search(name))
        script = step.get("script")
        if not is_deploy and isinstance(script, list):
            for entry in script:
                if isinstance(entry, dict):
                    v = entry.get("pipe")
                    if isinstance(v, str) and DEPLOY_RE.search(v):
                        is_deploy = True
                        break
                elif isinstance(entry, str) and "pipe:" in entry and DEPLOY_RE.search(entry):
                    is_deploy = True
                    break
        # Also check for deploy-like commands in script bodies.
        if not is_deploy:
            is_deploy = any(
                _DEPLOY_CMD_RE.search(line) for line in step_scripts(step)
            )
        if not is_deploy:
            continue
        if not step.get("deployment"):
            ungated.append(loc)
    passed = not ungated
    desc = (
        "All deploy-like steps declare a `deployment:` environment."
        if passed else
        f"{len(ungated)} deploy-like step(s) have no `deployment:` "
        f"field: {', '.join(ungated)}. Without it, Bitbucket cannot "
        f"enforce deployment-scoped variables, approvals, or "
        f"deployment history."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
