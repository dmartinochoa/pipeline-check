"""GL-004, deploy jobs must be gated by manual approval or environment."""
from __future__ import annotations

from typing import Any

from ..._primitives.deploy_names import DEPLOY_CMD_RE as _DEPLOY_CMD_RE
from ..._primitives.oci_refs import extract_image_anchors_from_strings
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from ..base import iter_jobs, job_scripts
from ._helpers import DEPLOY_RE, rules_fully_manual

RULE = Rule(
    id="GL-004",
    title="Deploy job lacks manual approval or environment gate",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Add `when: manual` (optionally with `rules:` for protected "
        "branches) or bind the job to an `environment:` with a "
        "deployment tier so approvals and audit are enforced by "
        "GitLab's environment controls."
    ),
    docs_note=(
        "A job whose stage or name contains `deploy` / `release` / "
        "`publish` / `promote` should either require manual approval "
        "or declare an `environment:` binding. Otherwise any push to "
        "the trigger branch ships to the target."
    ),
    exploit_example=(
        "# Vulnerable: a deploy job with no manual gate or environment:.\n"
        "deploy_prod:\n"
        "  stage: deploy\n"
        "  script:\n"
        "    - aws s3 sync ./dist s3://prod-site\n"
        "\n"
        "# Attack: nothing gates this. With no `when: manual` and no\n"
        "# `environment:`, GitLab runs it on every pipeline for the\n"
        "# trigger branch, so any push (a self-approved MR, a typo'd\n"
        "# hotfix, a compromised account) ships straight to production\n"
        "# with no approval and no environment audit trail.\n"
        "\n"
        "# Safe: require manual approval and bind an environment for the\n"
        "# audit trail plus protected-branch policy.\n"
        "deploy_prod:\n"
        "  stage: deploy\n"
        "  environment: production\n"
        "  when: manual\n"
        "  allow_failure: false\n"
        "  script:\n"
        "    - aws s3 sync ./dist s3://prod-site"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    ungated_jobs: list[dict[str, Any]] = []
    for name, job in iter_jobs(doc):
        stage = job.get("stage")
        # Cast each ``DEPLOY_RE.search(...)`` to bool so the variable's
        # inferred type stays ``bool`` across both assignments. mypy
        # otherwise widens to ``Match[str] | None | bool``, which then
        # fails the second assignment.
        is_deploy: bool = bool(
            (isinstance(stage, str) and DEPLOY_RE.search(stage))
            or DEPLOY_RE.search(name)
        )
        if not is_deploy:
            # Also check for deploy-like commands in scripts.
            is_deploy = any(
                _DEPLOY_CMD_RE.search(line) for line in job_scripts(job)
            )
        if not is_deploy:
            continue
        manual = (
            job.get("when") == "manual"
            or rules_fully_manual(job.get("rules"))
        )
        has_env = bool(job.get("environment"))
        if not (manual or has_env):
            ungated.append(name)
            ungated_jobs.append(job)
    passed = not ungated
    desc = (
        "All deploy-like jobs are gated by manual approval or environment."
        if passed else
        f"{len(ungated)} deploy job(s) run automatically without a manual "
        f"gate or `environment:` binding: {', '.join(ungated)}. Any push "
        f"to the trigger branch will ship to the target."
    )
    # ResourceAnchor phase 1 (AC-005): emit oci_image anchors for
    # images the UNGATED deploy jobs reference. Scoping to ungated
    # jobs only so a gated job's image in the same .gitlab-ci.yml
    # doesn't lend its identity to an AC-005 confirmation about an
    # ungated leg. Only on a failing finding — a fully gated
    # pipeline isn't a chain leg.
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
        # ``job_anchors`` carries the ungated deploy-job IDs so the
        # reachability-aware chain engine (AC-022) can intersect them
        # with the jobs GL-002 fired in. Empty tuple on a passed finding.
        job_anchors=tuple(ungated),
        resource_anchors=anchors,
    )
