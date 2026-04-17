"""SIGN-002 — Signing profile is revoked or expired."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SIGN-002",
    title="AWS Signer profile is revoked or inactive",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-347",),
    recommendation=(
        "Rotate the signing profile: create a replacement and update every "
        "code-signing config that references the revoked profile. A "
        "revoked or cancelled profile invalidates every signature it "
        "produced — lambdas relying on it will fail verification."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    try:
        client = catalog.client("signer")
    except Exception:  # noqa: BLE001
        return []
    try:
        resp = client.list_signing_profiles(includeCanceled=True)
    except ClientError:
        return []
    findings: list[Finding] = []
    for profile in resp.get("profiles", []):
        status = (profile.get("status") or "").lower()
        name = profile.get("profileName", "<unnamed>")
        if status in ("active",):
            continue
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name,
            description=f"Signing profile '{name}' status is {status or 'unknown'}.",
            recommendation=RULE.recommendation, passed=False,
        ))
    return findings
