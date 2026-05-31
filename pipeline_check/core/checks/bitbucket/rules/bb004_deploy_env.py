"""BB-004, deploy-like steps must declare `deployment:`."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.oci_refs import extract_image_anchors_from_strings
from ...base import Finding, ResourceAnchor, Severity
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
    exploit_example=(
        "# Vulnerable: a deploy step with no deployment: environment.\n"
        "pipelines:\n"
        "  branches:\n"
        "    main:\n"
        "      - step:\n"
        "          name: Deploy to prod\n"
        "          script:\n"
        "            - aws s3 sync ./dist s3://prod-site\n"
        "\n"
        "# Attack: with no `deployment:` field, Bitbucket can't scope\n"
        "# deployment variables, require a reviewer, or record\n"
        "# deployment history. Any push to main ships straight to\n"
        "# production, no approval and no audit trail.\n"
        "\n"
        "# Safe: declare a deployment environment (required reviewers\n"
        "# configured in the repo's Deployments settings).\n"
        "      - step:\n"
        "          name: Deploy to prod\n"
        "          deployment: production\n"
        "          script:\n"
        "            - aws s3 sync ./dist s3://prod-site"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    ungated_steps: list[dict[str, Any]] = []
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
            ungated_steps.append(step)
    passed = not ungated
    desc = (
        "All deploy-like steps declare a `deployment:` environment."
        if passed else
        f"{len(ungated)} deploy-like step(s) have no `deployment:` "
        f"field: {', '.join(ungated)}. Without it, Bitbucket cannot "
        f"enforce deployment-scoped variables, approvals, or "
        f"deployment history."
    )
    # ResourceAnchor phase 1 (AC-005): emit oci_image anchors for
    # images the UNGATED deploy steps reference. Scoping to ungated
    # steps only so a gated step's image in the same pipeline doesn't
    # lend its identity to an AC-005 confirmation about an ungated
    # leg. Only on failing finding.
    anchors: tuple[ResourceAnchor, ...] = ()
    if not passed:
        seen: dict[str, ResourceAnchor] = {}
        for step in ungated_steps:
            for a in extract_image_anchors_from_strings(step):
                seen.setdefault(a.identity, a)
        anchors = tuple(seen.values())
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=anchors,
    )
