"""BB-016 — self-hosted runners should use ephemeral or Docker-based images."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, blob_lower
from ...rule import Rule

RULE = Rule(
    id="BB-016",
    title="Self-hosted runner without ephemeral marker",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    recommendation=(
        "Use Docker-based self-hosted runners or configure runners to "
        "tear down between jobs. Add 'ephemeral' to `runs-on` labels "
        "or use Bitbucket's runner images that are rebuilt per-job."
    ),
    docs_note=(
        "Self-hosted runners that persist between jobs leak filesystem "
        "and process state. A PR-triggered step writes to a well-known "
        "path; a subsequent deploy step on the same runner reads it. "
        "Detects `runs-on: self.hosted` without an `ephemeral` marker "
        "or Docker image override."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    blob = blob_lower(doc)
    uses_self_hosted = "self.hosted" in blob
    has_ephemeral = "ephemeral" in blob
    passed = not uses_self_hosted or has_ephemeral
    desc = (
        "No non-ephemeral self-hosted runner usage detected."
        if passed
        else "Pipeline uses `self.hosted` runners without an "
        "ephemeral configuration. Runners may persist state between jobs."
    )
    return Finding(
        check_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation,
        passed=passed,
    )
