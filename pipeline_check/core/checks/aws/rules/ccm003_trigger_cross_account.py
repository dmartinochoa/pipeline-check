"""CCM-003. CodeCommit trigger targets an SNS/Lambda in a different account."""
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
    docs_note=(
        "A repo trigger pointing at an SNS topic or Lambda in a "
        "different account fires under the receiving account's "
        "permissions on every push. Sometimes this is the intended "
        "shape (a centralized notifications account), but a "
        "cross-account fan-out from a compromised repo can drive "
        "actions in the receiving account that the source-account "
        "owner can't directly observe."
    ),
)

_ARN_ACCOUNT_RE = re.compile(r"^arn:aws[a-z-]*:[^:]+:[^:]*:(\d{12}):")


def _account_from_arn(arn: str) -> str:
    """Extract the 12-digit account ID from any ARN partition, or '' on failure."""
    m = _ARN_ACCOUNT_RE.match(arn or "")
    return m.group(1) if m else ""


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("codecommit")
    sts_failed = False
    try:
        sts = catalog.client("sts").get_caller_identity()
        self_account = sts.get("Account", "")
    except Exception:
        self_account = ""
        sts_failed = True
    for repo in catalog.codecommit_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        # When STS failed we have no reliable source for the owning
        # account: ``list_repositories`` returns only repositoryName /
        # repositoryId (no ARN), so ``repositoryArn`` is virtually always
        # absent and the per-repo triggers fall through to the degraded
        # "cannot verify" branch below. Best-effort only, in case a
        # richer payload ever carries the ARN.
        effective_self = self_account
        if sts_failed and not effective_self:
            effective_self = _account_from_arn(repo.get("repositoryArn", ""))
        try:
            resp = client.get_repository_triggers(repositoryName=name)
        except ClientError:
            continue
        offenders: list[str] = []
        degraded = False
        for trigger in resp.get("triggers", []):
            dest = trigger.get("destinationArn", "")
            m = _ARN_ACCOUNT_RE.match(dest or "")
            if not m:
                continue
            dest_account = m.group(1)
            if not effective_self:
                # Cannot resolve own account; record a degraded result so the
                # trigger is not silently ignored.
                degraded = True
                offenders.append(dest)
            elif dest_account != effective_self:
                offenders.append(dest)
        if degraded:
            desc = (
                f"Repo '{name}' has trigger(s) whose account ownership "
                f"cannot be verified (STS unavailable): {', '.join(offenders)}. "
                "Treat as potentially cross-account."
            )
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=name, description=desc,
                recommendation=RULE.recommendation, passed=False,
            ))
            continue
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
