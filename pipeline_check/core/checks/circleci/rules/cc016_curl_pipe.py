"""CC-016 — remote script piped to shell interpreter."""
from __future__ import annotations

from typing import Any

from ..._primitives import remote_script_exec
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity, blob_lower
from ...rule import Rule
from ..base import iter_jobs, iter_run_commands

RULE = Rule(
    id="CC-016",
    title="Remote script piped to shell interpreter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-494",),
    recommendation=(
        "Download the script to a file, verify its checksum, then "
        "execute it. Or vendor the script into the repository."
    ),
    docs_note=(
        "Detects `curl | bash`, `wget | sh`, and similar patterns "
        "that pipe remote content directly into a shell interpreter "
        "inside a CircleCI config. An attacker who controls the remote "
        "endpoint (or poisons DNS / CDN) gains arbitrary code "
        "execution in the CI runner."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # Document-level blob scan — keeps the legacy detection surface
    # so a curl-pipe in a top-level command alias or a parameter
    # default still trips the rule.
    hits = remote_script_exec.scan(blob_lower(doc))

    # Per-job rescan to recover the offending job's line. Each
    # CircleCI job has a ``steps:`` list whose ``run:`` commands
    # are the typical home of curl-pipe idioms.
    locations: list[Location] = []
    for _, job in iter_jobs(doc):
        if any(remote_script_exec.scan(cmd) for cmd in iter_run_commands(job)):
            line = _line_of(job)
            locations.append(Location(
                path=path, start_line=line, end_line=line,
            ))

    passed = not hits
    desc = (
        "No curl-pipe or wget-pipe patterns detected in this config."
        if passed else
        f"Remote script piped to interpreter detected: "
        f"{', '.join(h.snippet for h in hits[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
