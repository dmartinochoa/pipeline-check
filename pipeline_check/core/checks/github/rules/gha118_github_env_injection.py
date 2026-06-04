"""GHA-118. Untrusted content written to $GITHUB_ENV / $GITHUB_PATH."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps, workflow_triggers

# Triggers where the workspace content / tool input a step reads can be
# attacker-influenced (a checked-out PR file, a downloaded artifact, PR
# metadata). On ``pull_request_target`` / ``workflow_run`` /
# ``issue_comment`` the job also runs with the base repo's secrets and a
# write token, so the later step the injected env escalates is the worst
# case; ``pull_request`` still yields code execution on the runner.
_UNTRUSTED_TRIGGERS = frozenset({
    "pull_request", "pull_request_target", "workflow_run", "issue_comment",
})

# A redirect (``>>`` or ``>``) into GitHub's env-control file. GitHub
# parses this file after the step and sets the named vars / PATH entries
# for every SUBSEQUENT step in the job.
_CONTROL_RE = re.compile(
    r'>>?\s*"?\$\{?(GITHUB_ENV|GITHUB_PATH)\}?"?'
)

# File / command-output readers. Their output is repo / artifact content,
# which an attacker controls on an untrusted trigger, so piping it into
# the control file injects whatever env the file holds.
_FILE_READ_RE = re.compile(
    r'\b(?:cat|tac|head|tail|sed|awk|grep|jq|yq|tee|cut|tr|xargs|envsubst)\b'
)

# Env vars that hijack a later step's process: a preloaded shared object,
# a Node ``--require`` module, a shell startup file, an interpreter path.
# Setting any of these from a dynamic value turns a benign later step into
# arbitrary code execution.
_HIJACK_KEY_RE = re.compile(
    r'\b(LD_PRELOAD|LD_LIBRARY_PATH|NODE_OPTIONS|BASH_ENV|ENV|PYTHONPATH'
    r'|PYTHONSTARTUP|PERL5LIB|PERL5OPT|RUBYOPT|GEM_PATH|GEM_HOME)\s*='
)

RULE = Rule(
    id="GHA-118",
    title="Untrusted content written to $GITHUB_ENV / $GITHUB_PATH",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Never write file content, command output, or any "
        "attacker-influenceable value into ``$GITHUB_ENV`` / "
        "``$GITHUB_PATH`` on an untrusted trigger. GitHub sets those "
        "vars (and prepends those PATH entries) for every later step, so "
        "a single injected line sets ``LD_PRELOAD`` / ``NODE_OPTIONS`` / "
        "``PATH`` and turns a benign later step (which may hold secrets "
        "and a write token) into arbitrary code execution. Write only "
        "fixed, literal ``KEY=value`` pairs; if a value must be dynamic, "
        "validate it against an allowlist first, and never set a "
        "process-hijack key from a computed value. This is the file-"
        "channel successor to the retired ``::set-env::`` command "
        "(GHA-038 covers that legacy stdout channel)."
    ),
    docs_note=(
        "Fires when a workflow reachable from ``pull_request`` / "
        "``pull_request_target`` / ``workflow_run`` / ``issue_comment`` "
        "has a ``run:`` step that redirects into ``$GITHUB_ENV`` / "
        "``$GITHUB_PATH`` AND the written content is either (a) file / "
        "command output (``cat`` / ``sed`` / ``jq`` / a ``$(...)`` "
        "subshell of one, etc.), which is repo / artifact content the "
        "trigger lets an attacker control, or (b) a process-hijack key "
        "(``LD_PRELOAD`` / ``NODE_OPTIONS`` / ``BASH_ENV`` / "
        "``PYTHONPATH`` / ...) set from a dynamic value. A fixed literal "
        "``echo \"KEY=value\" >> $GITHUB_ENV`` passes, as does "
        "``$(git describe)`` into a benign key. Distinct from GHA-038 "
        "(legacy ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` stdout channel), "
        "GHA-019 (a token written OUT of the env file), and GHA-003 / "
        "TAINT (``${{ }}`` expression / ``$GITHUB_OUTPUT`` channels), "
        "none of which watch attacker content written INTO the env-"
        "control file."
    ),
    exploit_example=(
        "# Vulnerable: a pull_request_target job checks out PR head and\n"
        "# pipes a PR-controlled file into the env-control file.\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: cat ./ci.env >> \"$GITHUB_ENV\"\n"
        "      - run: ./build.sh        # runs with secrets in scope\n"
        "# Attack: the PR ships a ci.env line `LD_PRELOAD=./evil.so`;\n"
        "# GitHub sets it for the build step, so evil.so loads into every\n"
        "# process build.sh spawns, with the workflow's secrets and write\n"
        "# token in scope. The PR never touched the workflow file.\n"
        "\n"
        "# Safe: write only fixed literals; compute nothing from the PR\n"
        "# tree into the env-control file.\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@<sha>\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: echo \"BUILD_PROFILE=ci\" >> \"$GITHUB_ENV\""
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    triggers = set(workflow_triggers(doc))
    pr_triggers = sorted(triggers & _UNTRUSTED_TRIGGERS)
    offenders: list[str] = []
    if pr_triggers:
        for job_id, job in iter_jobs(doc):
            for idx, step in enumerate(iter_steps(job)):
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                for line in run.splitlines():
                    m = _CONTROL_RE.search(line)
                    if not m:
                        continue
                    target = m.group(1)
                    lhs = line[:m.start()]
                    reason: str | None = None
                    if _FILE_READ_RE.search(lhs):
                        reason = "file / command-output content"
                    elif target == "GITHUB_ENV":
                        hk = _HIJACK_KEY_RE.search(lhs)
                        if hk and "$" in lhs[hk.end():]:
                            reason = f"process-hijack key {hk.group(1)}"
                    if reason:
                        offenders.append(
                            f"{job_id}.steps[{idx}] -> ${target} ({reason})"
                        )
                        break
    passed = not offenders
    desc = (
        "No untrusted content is written to $GITHUB_ENV / $GITHUB_PATH "
        "on an untrusted trigger."
        if passed else
        f"{len(offenders)} step(s) write attacker-influenceable content "
        f"into the env-control file on a "
        f"`{', '.join(pr_triggers)}` trigger: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. GitHub sets it for every "
        f"later step, so an injected `LD_PRELOAD` / `NODE_OPTIONS` / "
        f"`PATH` escalates a benign later step to code execution."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
