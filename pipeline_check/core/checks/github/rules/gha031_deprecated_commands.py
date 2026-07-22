"""GHA-031, workflow uses retired ``::set-output::`` / ``::save-state::``."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps

RULE = Rule(
    id="GHA-031",
    title="Workflow uses retired set-output / save-state command",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-77",),
    recommendation=(
        "Replace ``echo \"::set-output name=X::$VALUE\"`` with "
        "``echo \"X=$VALUE\" >> \"$GITHUB_OUTPUT\"`` and "
        "``echo \"::save-state name=X::$VALUE\"`` with "
        "``echo \"X=$VALUE\" >> \"$GITHUB_STATE\"``. The old "
        "commands stream through the runner's stdout, which lets any "
        "log line that happens to start with ``::`` inject into the "
        "command channel. The file-redirect forms write to a private "
        "file the runner reads after the step exits, no log-line "
        "interleaving, no injection."
    ),
    docs_note=(
        "GitHub deprecated ``::set-output::`` and ``::save-state::`` "
        "in October 2022 because they read from the runner's stdout "
        "as a control channel. Any tool whose output happens to "
        "contain ``::set-output…`` (a CI job's own diagnostic, a "
        "downloaded log, an upstream test framework) silently sets a "
        "step output. The replacement workflow commands "
        "(``$GITHUB_OUTPUT`` / ``$GITHUB_STATE`` files) close that "
        "injection channel. Workflows still using the retired "
        "commands also depend on a deprecation timer that GitHub has "
        "extended several times. They will eventually break."
    ),
    exploit_example=(
        "# Vulnerable: ``echo \"::set-output name=...\"`` (and\n"
        "# ``::save-state``) are retired GitHub-Actions workflow\n"
        "# commands. GitHub disabled them due to a command-\n"
        "# injection class where an attacker-controlled string\n"
        "# carrying ``%0A::set-output name=secret::pwned`` (or\n"
        "# similar) injects fake workflow commands into the\n"
        "# runner. The retired commands also stopped being\n"
        "# supported, so this step silently no-ops at runtime.\n"
        "jobs:\n"
        "  extract:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo \"::set-output name=tag::$VERSION\"\n"
        "        id: x\n"
        "\n"
        "# Safe: use the file-based replacements (``$GITHUB_OUTPUT``\n"
        "# and ``$GITHUB_STATE``). The new format isn't parsed by\n"
        "# the runner from stdout, so command-injection through a\n"
        "# variable value isn't possible.\n"
        "jobs:\n"
        "  extract:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo \"tag=$VERSION\" >> \"$GITHUB_OUTPUT\"\n"
        "        id: x"
    ),
)

# Match either the bare workflow command or its echoed form. Both
# cause GitHub to ingest the value through the legacy channel.
_DEPRECATED_RE = re.compile(
    r"::(?:set-output|save-state)\s+name=",
    re.IGNORECASE,
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for idx, step in enumerate(iter_steps(job)):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            # Skip ``#`` comment lines so a migration note referencing the
            # retired command (``# migrated from: echo "::set-output..."``)
            # doesn't fire while the live line uses ``$GITHUB_OUTPUT``.
            live = "\n".join(
                ln for ln in run.splitlines()
                if not ln.lstrip().startswith("#")
            )
            if _DEPRECATED_RE.search(live):
                offenders.append(f"{job_id}[{idx}]")
    passed = not offenders
    desc = (
        "No ``run:`` block uses ``::set-output::`` or ``::save-state::``."
        if passed else
        f"{len(offenders)} ``run:`` block(s) use the retired "
        f"``::set-output::`` / ``::save-state::`` command channel: "
        f"{', '.join(offenders)}. Switch to ``$GITHUB_OUTPUT`` / "
        f"``$GITHUB_STATE`` file redirects."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
