"""ENTRA-002. App registration credential valid beyond 180 days."""
from __future__ import annotations

from datetime import UTC, datetime

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ENTRA-002",
    title="App registration credential valid beyond 180 days",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-262",),
    recommendation=(
        "Set credential expiry to 90 days or less and rotate before "
        "expiration. Use certificate credentials or managed identities "
        "instead of client secrets where possible."
    ),
    docs_note=(
        "Long-lived app credentials increase the blast radius of a "
        "leak. Microsoft recommends credential lifetimes of 180 days "
        "or less; CIS Azure Foundations requires expiry review."
    ),
    exploit_example=(
        "A client secret with a 2-year validity window is committed "
        "to a repo. Even after the leak is discovered and the repo "
        "cleaned, the attacker retains access for months before the "
        "credential naturally expires."
    ),
)

_MAX_DAYS = 180


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for app in catalog.applications():
        app_name = app.get("displayName", "<unnamed>")
        app_id = app.get("appId", "<unknown>")
        for cred_list_key in ("passwordCredentials", "keyCredentials"):
            # Graph returns these arrays present-but-null in some exports;
            # ``or []`` guards a null value (the default only covers absent).
            for cred in app.get(cred_list_key) or []:
                if not isinstance(cred, dict):
                    continue
                end_raw = cred.get("endDateTime")
                if not end_raw:
                    continue
                if isinstance(end_raw, str):
                    try:
                        end_dt = datetime.fromisoformat(
                            end_raw.replace("Z", "+00:00"),
                        )
                    except ValueError:
                        continue
                else:
                    end_dt = end_raw
                start_raw = cred.get("startDateTime")
                if isinstance(start_raw, str):
                    try:
                        start_dt = datetime.fromisoformat(
                            start_raw.replace("Z", "+00:00"),
                        )
                    except ValueError:
                        start_dt = datetime.now(tz=UTC)
                elif start_raw:
                    start_dt = start_raw
                else:
                    start_dt = datetime.now(tz=UTC)

                # One side can be tz-aware (a "Z"/offset string or the
                # datetime.now(tz=UTC) fallback) while the other is naive;
                # normalize both to UTC before subtracting.
                if isinstance(end_dt, datetime) and end_dt.tzinfo is None:
                    end_dt = end_dt.replace(tzinfo=UTC)
                if isinstance(start_dt, datetime) and start_dt.tzinfo is None:
                    start_dt = start_dt.replace(tzinfo=UTC)
                lifetime = (end_dt - start_dt).days
                passed = lifetime <= _MAX_DAYS
                cred_type = "secret" if cred_list_key == "passwordCredentials" else "key"
                desc = (
                    f"App '{app_name}' ({app_id}) has a {cred_type} "
                    f"credential valid for {lifetime} days "
                    f"(threshold: {_MAX_DAYS})."
                )
                if passed:
                    desc = (
                        f"App '{app_name}' ({app_id}) has a {cred_type} "
                        f"credential valid for {lifetime} days (within "
                        f"the {_MAX_DAYS}-day threshold)."
                    )
                findings.append(Finding(
                    check_id=RULE.id,
                    title=RULE.title,
                    severity=RULE.severity,
                    resource=f"{app_name} ({app_id})",
                    description=desc,
                    recommendation=RULE.recommendation,
                    passed=passed,
                ))
    return findings
