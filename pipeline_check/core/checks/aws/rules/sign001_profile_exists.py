"""SIGN-001 — No AWS Signer signing profile exists when Lambda code-signing is wired."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SIGN-001",
    title="No AWS Signer profile defined for Lambda deploys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-347",),
    recommendation=(
        "Create an AWS Signer profile with platform "
        "``AWSLambda-SHA384-ECDSA`` and reference it from every Lambda "
        "code-signing config used by the pipeline. Without a profile, "
        "LMB-001 remediation isn't possible and release artifacts can't "
        "be signed at build time."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    try:
        client = catalog.client("signer")
    except Exception:  # noqa: BLE001
        return []
    try:
        resp = client.list_signing_profiles()
    except ClientError:
        return []
    profiles = resp.get("profiles", [])
    lambda_profiles = [
        p for p in profiles
        if "Lambda" in (p.get("platformId") or "")
        and (p.get("status") or "").lower() == "active"
    ]
    passed = bool(lambda_profiles)
    desc = (
        f"Found {len(lambda_profiles)} active Lambda signing profile(s): "
        + ", ".join(p.get("profileName", "?") for p in lambda_profiles)
        if passed else
        "No active AWS Signer profile for the Lambda platform is defined."
    )
    return [Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="signer",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )]
