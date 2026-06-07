"""ADO-004, deployment jobs must bind an environment."""
from __future__ import annotations

import re
from typing import Any

from ..._primitives.deploy_names import DEPLOY_CMD_RE as _DEPLOY_CMD_RE
from ..._primitives.oci_refs import extract_image_anchors_from_strings
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

_DEPLOY_NAME_RE = re.compile(r"(?i)\b(deploy|release|publish|promote)\b")

RULE = Rule(
    id="ADO-004",
    title="Deployment job missing environment binding",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Add `environment: <name>` to every `deployment:` job. "
        "Configure approvals, required branches, and business-hours "
        "checks on the matching Environment in the ADO UI."
    ),
    docs_note=(
        "Without an `environment:` binding, ADO cannot enforce "
        "approvals, checks, or deployment history against a named "
        "resource. Every `deployment:` job should bind one."
    ),
    known_fp=(
        "The deploy-name regex (``deploy`` / ``release`` / "
        "``publish`` / ``promote``) flags jobs whose names "
        "include those tokens for non-deploy reasons (e.g. "
        "``release-notes-build`` that only generates a "
        "changelog). The deploy-command regex similarly fires on "
        "test pipelines that exercise ``kubectl apply --dry-run`` "
        "or ``helm template`` for validation. Suppress those jobs "
        "per-resource via ``--ignore-file`` once you've verified "
        "they don't actually mutate any environment.",
    ),
    exploit_example=(
        "# Vulnerable: a deployment job with no environment: binding.\n"
        "jobs:\n"
        "  - deployment: DeployProd\n"
        "    pool: { vmImage: ubuntu-latest }\n"
        "    strategy:\n"
        "      runOnce:\n"
        "        deploy:\n"
        "          steps:\n"
        "            - script: aws s3 sync ./dist s3://prod-site\n"
        "\n"
        "# Attack: with no `environment:`, ADO can't enforce approvals,\n"
        "# branch-control checks, or business-hours gates. Any run on\n"
        "# the trigger branch rolls out to production with no reviewer\n"
        "# and no deployment record.\n"
        "\n"
        "# Safe: bind an environment (approvals + checks configured on\n"
        "# the Environment resource in the ADO UI).\n"
        "  - deployment: DeployProd\n"
        "    environment: production\n"
        "    pool: { vmImage: ubuntu-latest }\n"
        "    strategy:\n"
        "      runOnce:\n"
        "        deploy:\n"
        "          steps:\n"
        "            - script: aws s3 sync ./dist s3://prod-site"
    ),
)


def _job_has_deploy_commands(job: dict[str, Any]) -> bool:
    """Return True if any step in the job runs a deploy-like command."""
    for _, step in iter_steps(job):
        for key in ("script", "bash", "pwsh", "powershell"):
            body = step.get(key)
            if isinstance(body, str) and _DEPLOY_CMD_RE.search(body):
                return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    ungated_jobs: list[dict[str, Any]] = []
    for job_loc, job in iter_jobs(doc):
        is_deploy = isinstance(job.get("deployment"), str)
        if not is_deploy:
            # Also check job name and script bodies for deploy commands.
            job_name = job.get("job") or job_loc
            is_deploy = (
                bool(_DEPLOY_NAME_RE.search(str(job_name)))
                or _job_has_deploy_commands(job)
            )
        if not is_deploy:
            continue
        if not job.get("environment"):
            ungated.append(job_loc)
            ungated_jobs.append(job)
    passed = not ungated
    desc = (
        "Every deployment job binds an `environment`."
        if passed else
        f"{len(ungated)} deployment job(s) have no `environment:` "
        f"binding: {', '.join(ungated)}."
    )
    # ResourceAnchor phase 1 (AC-005): emit oci_image anchors for
    # images the UNGATED deployment jobs reference. Scoping to
    # ungated jobs only so a gated job's image in the same
    # pipeline doesn't lend its identity to an AC-005
    # confirmation. Only on failing finding.
    anchors: tuple[ResourceAnchor, ...] = ()
    if not passed:
        seen: dict[str, ResourceAnchor] = {}
        for job in ungated_jobs:
            for a in extract_image_anchors_from_strings(job):
                seen.setdefault(a.identity, a)
        anchors = tuple(seen.values())
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=anchors,
    )
