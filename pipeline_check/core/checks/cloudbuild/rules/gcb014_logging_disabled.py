"""GCB-014 — build logging disabled (``options.logging: NONE``).

Cloud Build exposes four ``options.logging`` modes:

- ``CLOUD_LOGGING_ONLY`` (default) — logs stream to Cloud Logging.
- ``GCS_ONLY`` — logs stream to a GCS bucket the caller owns.
- ``LEGACY`` — both Cloud Logging and GCS.
- ``NONE`` — **no logs are persisted**.

``NONE`` removes the audit trail entirely: a compromised step produces
no record of its commands, no record of its exit code, and no record
of what data it exfiltrated. The operational cost (log storage) is
negligible; the security cost of flying blind on an incident is
enormous.

GCB-specific; there is no cross-provider equivalent because no other
CI platform lets a pipeline author turn off their own logs.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-014",
    title="Build logging disabled (options.logging: NONE)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-10",),
    esf=("ESF-O-AUDIT",),
    cwe=("CWE-778",),
    recommendation=(
        "Remove the ``logging: NONE`` override — or replace it with "
        "``CLOUD_LOGGING_ONLY`` / ``GCS_ONLY`` — so every step's stdout, "
        "stderr, and exit code is persisted. Loss of logs is a "
        "detection-and-response black hole; the storage cost is "
        "measured in cents."
    ),
    docs_note=(
        "``options.logging`` defaults to ``CLOUD_LOGGING_ONLY`` when "
        "omitted, which passes. Only the explicit ``NONE`` value (case- "
        "insensitive) trips this rule. ``GCS_ONLY`` / ``LEGACY`` pass "
        "— they persist logs, just to a different destination."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    options = doc.get("options")
    logging_value: Any = None
    if isinstance(options, dict):
        logging_value = options.get("logging")
    if isinstance(logging_value, str) and logging_value.strip().upper() == "NONE":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "``options.logging: NONE`` disables all build log "
                "persistence. A compromised step produces no audit "
                "trail."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "Build logs are persisted "
            f"(options.logging: {logging_value!r})."
            if logging_value else
            "Build logs are persisted (default CLOUD_LOGGING_ONLY)."
        ),
        recommendation=RULE.recommendation, passed=True,
    )
