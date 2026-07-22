"""CC-009. Deploy-like workflow jobs should have a manual approval gate."""
from __future__ import annotations

from typing import Any

from ..._primitives.oci_refs import extract_image_anchors_from_strings
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, ResourceAnchor, Severity
from ...rule import Rule
from ..base import iter_workflow_jobs
from ._helpers import DEPLOY_RE

RULE = Rule(
    id="CC-009",
    title="Deploy job missing manual approval gate",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL", "ESF-C-ENV-SEP"),
    cwe=("CWE-284",),
    recommendation=(
        "Add a `type: approval` job that precedes the deploy job in "
        "the workflow, and list it in the deploy job's `requires:`. "
        "This ensures a human must click Approve in the CircleCI UI "
        "before production changes roll out."
    ),
    docs_note=(
        "In CircleCI, manual approval is implemented by adding a job "
        "with `type: approval` to the workflow and making the deploy "
        "job require it. Without this gate, any push to the triggering "
        "branch deploys immediately with no human review."
    ),
    exploit_example=(
        "# Vulnerable: a deploy job with no approval gate.\n"
        "workflows:\n"
        "  release:\n"
        "    jobs:\n"
        "      - deploy:\n"
        "          context: prod\n"
        "\n"
        "# Attack: nothing precedes `deploy` in the workflow, so any\n"
        "# push to the triggering branch rolls it out immediately, no\n"
        "# human clicks Approve in the CircleCI UI. A self-merged change\n"
        "# ships to production unreviewed.\n"
        "\n"
        "# Safe: insert a type: approval job and require it.\n"
        "workflows:\n"
        "  release:\n"
        "    jobs:\n"
        "      - hold:\n"
        "          type: approval\n"
        "      - deploy:\n"
        "          context: prod\n"
        "          requires: [hold]"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    ungated: list[str] = []
    locations: list[Location] = []
    # Build a per-workflow map of approval job names.
    workflows = doc.get("workflows") or {}
    if not isinstance(workflows, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No workflows declared in the config.",
            recommendation="No action required.", passed=True,
        )
    ungated_job_defs: list[dict[str, Any]] = []
    jobs_top = doc.get("jobs")
    jobs_top = jobs_top if isinstance(jobs_top, dict) else {}
    for wf_name, job_name, job_cfg in iter_workflow_jobs(doc):
        if not DEPLOY_RE.search(job_name):
            continue
        # The deploy job itself might be an approval type.
        if job_cfg.get("type") == "approval":
            continue
        # Check if any of the job's `requires:` entries are approval jobs.
        requires = job_cfg.get("requires") or []
        if not isinstance(requires, list):
            requires = [requires]
        # Collect all approval job names in this workflow.
        approval_jobs: set[str] = set()
        for _, other_name, other_cfg in iter_workflow_jobs(doc):
            if other_cfg.get("type") == "approval":
                approval_jobs.add(other_name)
        if any(
            isinstance(req, str) and req in approval_jobs for req in requires
        ):
            continue
        ungated.append(f"{wf_name}/{job_name}")
        # Anchor on the workflow's job entry, that's where the
        # ``requires: [<approval-job>]`` line should be added.
        line = _line_of(job_cfg) if isinstance(job_cfg, dict) else None
        locations.append(Location(
            path=path, start_line=line, end_line=line,
        ))
        # The workflow entry is a ref; the actual step body lives
        # under ``jobs.<job_name>``. Pull that definition for
        # scoped anchor extraction.
        job_def = jobs_top.get(job_name)
        if isinstance(job_def, dict):
            ungated_job_defs.append(job_def)
    passed = not ungated
    desc = (
        "Every deploy job is gated by a manual approval step."
        if passed else
        f"{len(ungated)} deploy job(s) have no manual approval gate: "
        f"{', '.join(ungated)}. Without an approval step, any push to "
        f"the triggering branch deploys immediately with no human review."
    )
    # ResourceAnchor phase 1 (AC-005): emit oci_image anchors for
    # images the UNGATED deploy jobs reference. Scoped to the
    # ungated job definitions so a gated job's image in the same
    # config doesn't lend its identity to an AC-005 confirmation
    # about an ungated leg. Only on failing finding.
    anchors: tuple[ResourceAnchor, ...] = ()
    if not passed:
        seen: dict[str, ResourceAnchor] = {}
        for jd in ungated_job_defs:
            for a in extract_image_anchors_from_strings(jd):
                seen.setdefault(a.identity, a)
        anchors = tuple(seen.values())
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        resource_anchors=anchors,
    )
