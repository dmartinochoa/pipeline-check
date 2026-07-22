"""CC-010. Self-hosted runners should be ephemeral."""
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
        "check treats a namespaced `resource_class` (`<namespace>/"
        "<name>`, the shape every self-hosted runner uses) or one "
        "containing 'self-hosted' as a runner, then flags it when the "
        "value carries no 'ephemeral' marker."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending: list[str] = []
    for job_id, job in iter_jobs(doc):
        resource_class = job.get("resource_class")
        if not isinstance(resource_class, str):
            continue
        rc_lower = resource_class.lower()
        # A CircleCI self-hosted runner uses a namespaced resource class
        # (``<namespace>/<name>``, e.g. ``my-org/prod-runner``); managed
        # classes never contain ``/``. The literal ``self-hosted`` token
        # is only a convention, so keying on it alone misses most real
        # runners.
        is_runner = (
            "self-hosted" in rc_lower
            or "self_hosted" in rc_lower
            or "/" in resource_class
        )
        if not is_runner:
            continue
        # Self-hosted runner detected, check for ephemeral marker.
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
