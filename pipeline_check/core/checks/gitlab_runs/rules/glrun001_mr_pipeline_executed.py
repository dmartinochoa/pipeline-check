"""GLRUN-001. A merge-request pipeline actually executed (surface is live).

Aggregate forensic signal: how many recent pipelines ran on a
merge-request event (``source: merge_request_event`` /
``external_pull_request_event``), meaning a contributor's proposed code
executed in CI. When the project enables "run pipelines for fork merge
requests," this is fork code running in the project's CI context; even for
same-project merge requests it is the surface a poisoned-pipeline attack
exercises. This is forensic awareness/context, the GitLab analog of the
``runs`` provider's RUN-002 (privileged trigger fired): it confirms from
run history that the merge-request pipeline surface is live, which the
static ``.gitlab-ci.yml`` scan cannot establish on its own.

Metadata-only (the pipeline list's ``source`` field), so it needs no log
download. The fork-origin subset (the high-severity case) is deferred to a
later GLRUN rule that resolves the merge request's source vs target
project.
"""
from __future__ import annotations

from collections import Counter

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabRunsContext, project_resource

RULE = Rule(
    id="GLRUN-001",
    title="Merge-request pipeline exercised in run history",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    recommendation=(
        "Review the jobs that run on merge-request pipelines and confirm "
        "none execute contributor-controlled content while holding CI/CD "
        "variables or a deploy token. If 'Run pipelines for fork merge "
        "requests' is enabled, treat those pipelines as running untrusted "
        "code: scope protected variables and runners away from them, and "
        "require a maintainer to approve fork-MR pipelines before they run."
    ),
    docs_note=(
        "Sourced from the GitLab REST API (``GET /projects/:id/"
        "pipelines``). Counts recent pipelines whose ``source`` is "
        "``merge_request_event`` or ``external_pull_request_event``. This "
        "is forensic context (the merge-request pipeline surface is live "
        "in production), which the static ``.gitlab-ci.yml`` scan cannot "
        "confirm on its own. The fork-originated subset (the high-severity "
        "case) is a separate, deeper check."
    ),
)


def check(ctx: GitLabRunsContext) -> list[Finding]:
    mr = [p for p in ctx.pipelines if p.from_merge_request]
    if not mr:
        return [Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=project_resource(ctx),
            description=(
                "No merge-request pipelines in the "
                f"{len(ctx.pipelines)} most recent pipeline(s)."
            ),
            recommendation=RULE.recommendation,
            passed=True,
        )]
    counts = Counter(p.source for p in mr)
    summary = ", ".join(f"{src}={n}" for src, n in sorted(counts.items()))
    return [Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=project_resource(ctx),
        description=(
            f"{len(mr)} recent pipeline(s) ran on a merge-request event "
            f"({summary}). Contributor-proposed code executed in CI; audit "
            "those jobs for what variables / runners / tokens were in scope "
            "and whether fork merge-request pipelines are enabled."
        ),
        recommendation=RULE.recommendation,
        passed=False,
    )]
