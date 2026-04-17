"""CC-010 — Self-hosted runners should be ephemeral."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="CC-010",
    title="Self-hosted runner without ephemeral marker",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-269",),
    recommendation=(
        "Configure self-hosted runners to tear down between jobs. Use "
        "a `resource_class` value that includes an ephemeral marker, "
        "or use CircleCI's machine executor with runner auto-scaling "
        "so each job gets a fresh environment."
    ),
    docs_note=(
        "Self-hosted runners that persist between jobs leak filesystem "
        "and process state. A PR-triggered job writes to `/tmp`; a "
        "subsequent prod-deploy job on the same runner reads it. The "
        "check looks for `resource_class` values containing "
        "'self-hosted' — if found, it checks for 'ephemeral' in the "
        "value. Also checks for `machine: true` combined with a "
        "self-hosted resource class."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending: list[str] = []
    for job_id, job in iter_jobs(doc):
        resource_class = job.get("resource_class")
        if not isinstance(resource_class, str):
            continue
        rc_lower = resource_class.lower()
        if "self-hosted" not in rc_lower and "self_hosted" not in rc_lower:
            continue
        # Self-hosted runner detected — check for ephemeral marker.
        if "ephemeral" not in rc_lower:
            offending.append(job_id)
    passed = not offending
    desc = (
        "No self-hosted runner job runs without an ephemeral marker."
        if passed else
        f"{len(offending)} self-hosted runner job(s) lack an ephemeral "
        f"marker in `resource_class`: {', '.join(offending)}. Without "
        f"ephemeral runners the worker keeps filesystem and process "
        f"state across jobs, letting a PR-triggered job seed data that "
        f"a later deploy job reads."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
