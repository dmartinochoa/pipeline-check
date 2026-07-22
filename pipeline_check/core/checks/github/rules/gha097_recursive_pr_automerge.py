"""GHA-097. Workflow creates a PR and auto-merges it, forming a loop."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location, workflow_triggers

RULE = Rule(
    id="GHA-097",
    title="Recursive PR auto-merge loop",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-674",),
    recommendation=(
        "Break the loop by removing the auto-merge call from the same "
        "workflow that creates the PR, or by gating the merge on a "
        "separate approval-required environment. If the automation "
        "genuinely needs both create and merge (e.g. a dependency-"
        "update bot), ensure the created PR targets a non-default "
        "branch that does not re-trigger the same workflow, and "
        "require at least one human reviewer before the merge "
        "completes."
    ),
    docs_note=(
        "Fires when a workflow that triggers on ``pull_request`` or "
        "``pull_request_target`` also contains a step that creates or "
        "updates a PR (``gh pr create``, ``peter-evans/create-pull-"
        "request``, or similar) AND a step that enables auto-merge "
        "(``gh pr merge --auto``, ``pascalgn/automerge-action``, or "
        "the repo-level ``auto_merge`` API call).\n\n"
        "The topology creates a persistence loop: the workflow's own "
        "PR triggers the workflow again on the next cycle, allowing "
        "an attacker who controls the PR content to maintain code "
        "injection across merges without further interaction. This "
        "is the OSC&R PER-1 (Recursive PR) attack pattern."
    ),
    known_fp=(
        "Dependency-update bots (Renovate, Dependabot) sometimes "
        "create and auto-merge PRs in a single workflow. If the PR "
        "targets a non-default branch or requires human approval "
        "via an environment gate, the loop is broken and the rule "
        "is a false positive. Suppress with a rationale naming the "
        "gating mechanism.",
    ),
    exploit_example=(
        "# Vulnerable: workflow triggers on PR, creates a new PR,\n"
        "# and auto-merges it, creating a self-sustaining loop.\n"
        "on: pull_request\n"
        "jobs:\n"
        "  update:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: make generate-config\n"
        "      - uses: peter-evans/create-pull-request@<sha>\n"
        "        with:\n"
        "          title: 'chore: regenerate config'\n"
        "      - run: gh pr merge --auto --squash\n"
        "        env:\n"
        "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
        "\n"
        "# Safe: separate the create and merge into different\n"
        "# workflows with an environment approval gate between them."
    ),
)


_PR_CREATE_ACTIONS = (
    "peter-evans/create-pull-request",
    "repo-sync/pull-request",
    "devops-infra/action-pull-request",
    "vsoch/pull-request-action",
    "thomaseizinger/create-pull-request",
)

_AUTOMERGE_ACTIONS = (
    "pascalgn/automerge-action",
    "peter-evans/enable-pull-request-automerge",
    "reitermarkus/automerge",
)

_PR_CREATE_CLI_RE = re.compile(
    r"gh\s+pr\s+create\b",
)

_AUTOMERGE_CLI_RE = re.compile(
    r"gh\s+pr\s+merge\s+.*--auto\b",
)

#: The GraphQL ``enablePullRequestAutoMerge`` mutation, and the
#: ``auto_merge`` field set through ``gh api``. These are the API-call
#: shapes the docs_note names alongside the CLI form.
_AUTOMERGE_API_RE = re.compile(
    r"\benablePullRequestAutoMerge\b"
    r"|\bgh\s+api\b[^\n]*\bauto_merge\b",
)


def _is_pr_trigger(doc: dict[str, Any]) -> bool:
    triggers = workflow_triggers(doc)
    return any(t in ("pull_request", "pull_request_target") for t in triggers)


def _action_slug(uses: str) -> str:
    return uses.split("@", 1)[0].strip().lower()


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not _is_pr_trigger(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow does not trigger on pull_request or "
                "pull_request_target."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    creates_pr = False
    auto_merges = False
    create_labels: list[str] = []
    merge_labels: list[str] = []
    locations = []

    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            name = step.get("name") or step.get("id") or f"steps[{idx}]"
            label = f"{job_id}.{name}"
            uses = step.get("uses")
            run = step.get("run")

            if isinstance(uses, str):
                slug = _action_slug(uses)
                if any(slug == a or slug.startswith(a + "/")
                       for a in _PR_CREATE_ACTIONS):
                    creates_pr = True
                    create_labels.append(label)
                    locations.append(step_location(path, step))
                if any(slug == a or slug.startswith(a + "/")
                       for a in _AUTOMERGE_ACTIONS):
                    auto_merges = True
                    merge_labels.append(label)
                    locations.append(step_location(path, step))

            if isinstance(run, str):
                if _PR_CREATE_CLI_RE.search(run):
                    creates_pr = True
                    create_labels.append(label)
                    locations.append(step_location(path, step))
                if _AUTOMERGE_CLI_RE.search(run) or _AUTOMERGE_API_RE.search(run):
                    auto_merges = True
                    merge_labels.append(label)
                    locations.append(step_location(path, step))

    passed = not (creates_pr and auto_merges)
    if passed:
        desc = (
            "Workflow triggers on a PR event but does not both create "
            "and auto-merge a PR in the same run."
        )
    else:
        desc = (
            f"PR-triggered workflow creates a PR "
            f"({', '.join(create_labels[:3])}) and auto-merges "
            f"({', '.join(merge_labels[:3])}), forming a self-"
            f"sustaining loop. An attacker controlling the PR "
            f"content can maintain code injection across merge cycles."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
