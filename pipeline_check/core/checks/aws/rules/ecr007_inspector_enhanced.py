"""ECR-007 — Inspector v2 enhanced scanning disabled for ECR repositories."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-007",
    title="Inspector v2 enhanced scanning disabled for ECR",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-1104",),
    recommendation=(
        "Enable Amazon Inspector v2 for the ``ECR`` scan type on this "
        "account. Basic ECR scanning on-push only covers OS packages; "
        "Inspector v2 enhanced scanning adds language-ecosystem CVEs and "
        "runs continuously as new vulnerabilities are published."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    try:
        client = catalog.client("inspector2")
    except Exception:  # noqa: BLE001
        return []
    try:
        resp = client.batch_get_account_status(accountIds=[])
    except ClientError:
        # Surface as a single finding — Inspector may be disabled or the
        # caller may lack permission; either way flag it as a gap.
        return [Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="inspector2",
            description=(
                "Inspector v2 BatchGetAccountStatus is unavailable; "
                "enhanced scanning status could not be verified."
            ),
            recommendation=RULE.recommendation, passed=False,
        )]
    accounts = resp.get("accounts", [])
    if not accounts:
        return [Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="inspector2",
            description="Inspector v2 returned no account status — likely disabled.",
            recommendation=RULE.recommendation, passed=False,
        )]
    findings: list[Finding] = []
    for acct in accounts:
        acct_id = acct.get("accountId", "<unknown>")
        state = ((acct.get("resourceState") or {}).get("ecr") or {}).get("status", "")
        passed = state == "ENABLED"
        desc = (
            f"Inspector v2 ECR scanning is {state} for account {acct_id}."
            if state else
            f"Inspector v2 ECR scanning status unknown for account {acct_id}."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=acct_id, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
