"""CCM-003 — CodeCommit trigger targets an SNS/Lambda in a different account."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CCM-003",
    title="CodeCommit trigger targets SNS/Lambda in a different account",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-441",),
    recommendation=(
        "Move trigger targets into the same account as the repository or "
        "explicitly document the cross-account relationship. Cross-account "
        "triggers extend the blast radius of a repository compromise to "
        "whatever the target ARN can do."
    ),
)

_ARN_ACCOUNT_RE = re.compile(r"^arn:aws:[^:]+:[^:]*:(\d{12}):")


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("codecommit")
    try:
        sts = catalog.client("sts").get_caller_identity()
        self_account = sts.get("Account", "")
    except Exception:  # noqa: BLE001
        self_account = ""
    for repo in catalog.codecommit_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        try:
            resp = client.get_repository_triggers(repositoryName=name)
        except ClientError:
            continue
        offenders: list[str] = []
        for trigger in resp.get("triggers", []):
            dest = trigger.get("destinationArn", "")
            m = _ARN_ACCOUNT_RE.match(dest or "")
            if m and self_account and m.group(1) != self_account:
                offenders.append(dest)
        passed = not offenders
        desc = (
            f"Repo '{name}' triggers stay within the account."
            if passed else
            f"Repo '{name}' has trigger(s) targeting other accounts: "
            f"{', '.join(offenders)}."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
