"""GHA-017 — docker run with insecure flags (privileged / host mount)."""
from __future__ import annotations

from typing import Any

from ...base import DOCKER_INSECURE_RE, Finding, Location, Severity, blob_lower
from ...rule import Rule
from ..base import iter_jobs, iter_steps, step_location

RULE = Rule(
    id="GHA-017",
    title="Docker run with insecure flags (privileged/host mount)",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-250",),
    recommendation=(
        "Remove --privileged and --cap-add flags. Use minimal volume "
        "mounts. Prefer rootless containers."
    ),
    docs_note=(
        "Flags like `--privileged`, `--cap-add`, `--net=host`, or "
        "host-root volume mounts (`-v /:/`) in a workflow give the "
        "container full access to the runner, enabling container "
        "escape and lateral movement."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # First do the document-level blob scan so a workflow-level
    # ``env:`` value or a ``container.options:`` flag still trips
    # the rule even when no individual step's run: contains the
    # idiom. The blob path is the legacy fallback that has caught
    # findings since v0.1.0.
    blob = blob_lower(doc)
    matches = DOCKER_INSECURE_RE.findall(blob)

    # Then walk every step and re-scan its ``run:`` body for the
    # same pattern. When a step's run text contains the offending
    # flag, the step's source line is the most useful anchor —
    # reporters / SARIF can render path:line and the user lands on
    # the right step. Falls back to a path-only Location when no
    # step matches (the blob hit was in workflow-level env or a
    # container's options block).
    locations: list[Location] = []
    for _, job in iter_jobs(doc):
        for step in iter_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            if DOCKER_INSECURE_RE.search(run.lower()):
                locations.append(step_location(path, step))

    passed = not matches
    desc = (
        "No insecure docker run flags detected in this workflow."
        if passed else
        f"Insecure docker run flags detected: {', '.join(matches[:3])}"
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
