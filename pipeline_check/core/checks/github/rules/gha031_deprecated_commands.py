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
            if _DEPRECATED_RE.search(run):
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
