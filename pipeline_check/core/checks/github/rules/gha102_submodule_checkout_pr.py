"""GHA-102. ``actions/checkout`` with ``submodules: recursive`` on a PR trigger.

A contributor PR can modify ``.gitmodules`` to point a submodule at an
attacker-controlled repository. With ``submodules: true`` or
``submodules: recursive``, the checkout action clones that repo into
the workspace. Any build step that follows (``npm ci``, ``make``,
``cargo build``, ``pip install``) executes attacker-controlled code
via lifecycle scripts, Makefiles, or build.rs files.

The pairing is the signal: ``submodules: recursive`` alone is a
deliberate choice, but combined with a PR trigger it unconditionally
trusts the PR author's ``.gitmodules``. The risk is highest on
``pull_request_target`` (which checks out the base but still trusts
the PR's submodule changes when ``ref:`` is overridden), and still
present on plain ``pull_request`` (which checks out the merge ref).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location, workflow_triggers

RULE = Rule(
    id="GHA-102",
    title="``actions/checkout`` with submodule fetch on a PR trigger",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829",),
    recommendation=(
        "Remove ``submodules: true`` / ``submodules: recursive`` from "
        "checkout steps in PR-triggered workflows. If submodules are "
        "genuinely needed for the PR build, pin submodule URLs to "
        "trusted repositories in a ``.gitmodules`` file that lives on "
        "a protected branch and validate submodule origins before the "
        "build step runs. Alternatively, split the workflow: use a "
        "low-privilege ``pull_request`` job for code review checks "
        "(no submodules) and a ``push``-triggered job for builds "
        "that need submodule content."
    ),
    docs_note=(
        "Fires on workflows triggered by ``pull_request`` or "
        "``pull_request_target`` when any ``actions/checkout`` step "
        "sets ``with.submodules`` to ``true`` or ``recursive``. "
        "The rule does not require a subsequent build step: the "
        "submodule clone itself is the risk surface (lifecycle "
        "scripts, hooks, and build files execute during or "
        "immediately after the clone).\n\n"
        "``submodules: false`` (the default) is safe and does not "
        "fire."
    ),
    known_fp=(
        "Workflows that intentionally clone submodules on PRs for "
        "monorepo builds where all submodule URLs point at repos "
        "within the same organization. Suppress per-step if the "
        "submodule origin is validated before the build.",
    ),
    exploit_example=(
        "# Vulnerable: a PR can modify .gitmodules to point at an\n"
        "# attacker-controlled repo. The recursive checkout clones it\n"
        "# and the subsequent build step executes its code.\n"
        "on: pull_request\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          submodules: recursive\n"
        "      - run: npm ci && npm run build\n"
        "\n"
        "# Safe: no submodule fetch on the PR trigger.\n"
        "on: pull_request\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "      - run: npm ci && npm run build"
    ),
)

_CHECKOUT_SLUGS = (
    "actions/checkout",
)

_PR_TRIGGERS = frozenset(("pull_request", "pull_request_target"))


def _is_pr_triggered(doc: dict[str, Any]) -> bool:
    return bool(_PR_TRIGGERS & set(workflow_triggers(doc)))


def _action_slug(uses: str) -> str:
    return uses.split("@", 1)[0].strip().lower()


def _is_submodule_checkout(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    if not isinstance(uses, str):
        return False
    slug = _action_slug(uses)
    if not any(slug == a for a in _CHECKOUT_SLUGS):
        return False
    with_block = step.get("with")
    if not isinstance(with_block, dict):
        return False
    submodules = with_block.get("submodules")
    if isinstance(submodules, bool):
        return submodules
    if isinstance(submodules, str):
        return submodules.lower() in ("true", "recursive")
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not _is_pr_triggered(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow does not trigger on pull_request or "
                "pull_request_target."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    locations = []

    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            if _is_submodule_checkout(step):
                name = step.get("name") or step.get("id") or f"steps[{idx}]"
                with_block = step.get("with", {})
                mode = with_block.get("submodules", "true")
                offenders.append(
                    f"{job_id}.{name}: submodules={mode}"
                )
                locations.append(step_location(path, step))

    passed = not offenders
    if passed:
        desc = (
            "No ``actions/checkout`` step fetches submodules on a "
            "PR-triggered workflow."
        )
    else:
        desc = (
            f"{len(offenders)} checkout step(s) fetch submodules on a "
            f"PR trigger: {'; '.join(offenders[:3])}"
            f"{'...' if len(offenders) > 3 else ''}. A contributor "
            f"PR can modify ``.gitmodules`` to point at an attacker-"
            f"controlled repository, and the checkout clones it into "
            f"the workspace."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
