"""GHA-032, local script invoked from a ``run:`` block on an untrusted trigger.

Complements GHA-010, which flags ``uses: ./<path>`` (local *action*
references) on the same triggers. GHA-032 catches the equally-bad
``run: ./<path>`` and ``run: bash <path>`` forms, where the privileged
workflow shell-execs a script the PR controls.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers
from ._helpers import UNTRUSTED_TRIGGERS

RULE = Rule(
    id="GHA-032",
    title="run: invokes local script on untrusted-trigger workflow",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Either don't run the script under an untrusted trigger, or "
        "split the workflow: keep the privileged work on the default "
        "branch (``push`` / ``release`` triggers, no PR fork content), "
        "and run untrusted-trigger steps in a separate workflow with "
        "no secrets and a minimal ``GITHUB_TOKEN`` scope. Pinning the "
        "script via ``uses: org/repo@<sha>`` from a separate trusted "
        "repo is the canonical fix."
    ),
    docs_note=(
        "GHA-010 flags ``uses: ./action``, the *action* form of the "
        "same threat. This rule extends to direct shell invocation: "
        "``run: ./scripts/setup.sh`` / ``run: bash scripts/setup.sh`` "
        "/ ``run: python tools/build.py`` resolve against the checked-"
        "out workspace, which on ``pull_request_target`` / "
        "``workflow_run`` is PR-controlled. The attacker ships an "
        "edited script and gets a default-branch-privileged shell."
    ),
    known_fp=(
        "Workflows that explicitly checkout a *trusted* ref "
        "(``ref: ${{ github.event.pull_request.base.sha }}`` or "
        "the default branch) before invoking the local script "
        "land the trusted bytes on disk, so the script body the "
        "PR ships is never executed. The rule has no checkout-"
        "graph analysis, it fires on any ``run: ./script`` under "
        "an untrusted trigger. Suppress per-workflow via "
        "``--ignore-file`` once you've verified the checkout ref "
        "is anchored to a base-branch SHA; the safer pattern is "
        "still to split the workflow so secrets aren't in scope "
        "during the build half.",
    ),
    exploit_example=(
        "# Vulnerable: an untrusted-trigger workflow\n"
        "# (``pull_request_target`` / ``workflow_run``) ``run``s\n"
        "# a local script. The PR head is checked out into the\n"
        "# workspace; the script the workflow invokes was\n"
        "# rewritten by the attacker's PR. The privileged trigger\n"
        "# then executes the PR-controlled script with secrets.\n"
        "name: comment-lint\n"
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened, synchronize]\n"
        "jobs:\n"
        "  lint:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: ./scripts/lint.sh   # attacker rewrote scripts/lint.sh in the PR\n"
        "\n"
        "# Safe: don't run local scripts under untrusted triggers.\n"
        "# Move the privileged work to a separate workflow gated\n"
        "# on ``workflow_dispatch`` (with environment approval) or\n"
        "# scope ``pull_request_target`` to non-script comment\n"
        "# operations only.\n"
        "name: comment-lint\n"
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened, synchronize]\n"
        "jobs:\n"
        "  lint:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/github-script@<sha>\n"
        "        with:\n"
        "          script: |\n"
        "            // Read-only PR metadata; no checkout of PR head.\n"
        "            github.rest.issues.createComment({ ... })"
    ),
)

# Match a ``run:`` body that invokes a local-path script as its
# primary command. Three idioms cover the realistic surface:
#
#   ./scripts/build.sh         # bare relative-path execution
#   bash ./scripts/build.sh    # interpreter + relative path
#   bash scripts/build.sh      # interpreter + bare relative path
#   python tools/build.py      # any-interpreter form
#
# We deliberately do NOT match ``bash -c "<command>"``, that's
# inline shell, no PR-controlled file. The first capture group
# narrows to a leading interpreter token to keep the regex
# anchored on the actual file reference.
_INTERPRETERS = (
    "bash", "sh", "zsh", "ksh", "dash",
    "python", "python3", "ruby", "node", "perl",
)
_INTERP_OR_DIRECT = "|".join(_INTERPRETERS)
_LOCAL_SCRIPT_RE = re.compile(
    rf"^\s*"
    rf"(?:(?:{_INTERP_OR_DIRECT})\s+)?"
    rf"\.{{1,2}}/[\w./\-]+\.(?:sh|bash|py|rb|js|pl)\b"
    rf"|^\s*(?:{_INTERP_OR_DIRECT})\s+[\w./\-]+\.(?:sh|bash|py|rb|js|pl)\b",
    re.MULTILINE,
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    matching = triggers & UNTRUSTED_TRIGGERS
    if not matching:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Workflow has no untrusted trigger.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if _LOCAL_SCRIPT_RE.search(run):
                offenders.append(f"{job_id}[{idx}]")
    passed = not offenders
    desc = (
        f"No ``run:`` block invokes a local script under the "
        f"untrusted trigger(s) {sorted(matching)}."
        if passed else
        f"Workflow with untrusted trigger ({', '.join(sorted(matching))}) "
        f"shell-execs local script(s) at: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The script body is "
        f"resolved against the PR-controlled checkout and runs with "
        f"default-branch privilege."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
