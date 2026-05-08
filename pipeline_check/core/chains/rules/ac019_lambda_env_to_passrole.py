"""AC-019 — Lambda env-secret meets a CI/CD role with PassRole *.

Two AWS-side findings that look harmless apart and are decisive
together:

- **LMB-003.** A Lambda function carries a credential-shaped
  literal in its env vars. Anyone with
  ``lambda:GetFunctionConfiguration`` (a much wider audience than
  the principal that can invoke the function) reads it; the value
  also lands in CloudFormation drift, change-sets, and CloudTrail
  events. Effectively world-readable to anyone with read access
  to the account.

- **IAM-004.** The CI/CD service role grants ``iam:PassRole`` with
  ``Resource: '*'``. Any principal that holds the role can hand
  any IAM role to any service that calls ``iam:PassRole`` — Lambda
  itself, Glue, EC2, CodeBuild, SageMaker.

Combined: an attacker who lands code in the build pipeline (or
who exfiltrates the Lambda's env-var credential) can invoke
``lambda:CreateFunction`` with ``--role <higher-privileged-role>``
or ``--role <existing-prod-role>``, then run code under that
identity. The first pivot is the credential leak; the second is
the role-hop. Each is bad alone; the combination is the canonical
``CI compromise -> account compromise`` upgrade.

The chain fires when both findings appear in the same scan,
regardless of whether the Lambda function and the CI/CD role
sit in different AWS services — the pivot crosses service lines.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-019",
    title="Lambda env-secret meets a CI/CD role with PassRole *",
    severity=Severity.CRITICAL,
    summary=(
        "A Lambda function holds a credential-shaped literal in "
        "its env vars (LMB-003) AND a CI/CD service role in the "
        "same account grants ``iam:PassRole`` with ``Resource: '*'`` "
        "(IAM-004). The first leak gives any read-account principal "
        "the credential; the second turns that credential into a "
        "role-hop primitive against any IAM role in the account."
    ),
    mitre_attack=(
        "T1552.001",  # Unsecured Credentials: Credentials In Files
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase="credential-access -> privilege-escalation -> lateral-movement",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-and-Access-Management",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
        "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption",
    ),
    recommendation=(
        "Close either leg. On the Lambda side: move every env-var "
        "credential into Secrets Manager or SSM SecureString and "
        "fetch it at function init; the env vars then carry only "
        "the secret's ARN, not the value. On the IAM side: scope "
        "``iam:PassRole`` with ``Resource: <specific-role-ARNs>`` "
        "and add an ``iam:PassedToService`` condition. The "
        "credential leak is its own compliance failure; the "
        "PassRole wildcard is its own; the chain stops being a "
        "chain when either is fixed."
    ),
    providers=("aws",),
    triggering_check_ids=("LMB-003", "IAM-004"),
)


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "LMB-003"):
        return []
    if not has_failing(findings, "IAM-004"):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"LMB-003", "IAM-004"}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this AWS account scan:\n"
        "  1. At least one Lambda function carries a credential-"
        "shaped literal in its env vars (LMB-003). Lambda env "
        "vars are visible to anyone with "
        "``lambda:GetFunctionConfiguration`` — a strictly wider "
        "audience than the principal that can invoke the "
        "function. The value also persists in CloudFormation "
        "drift, change-sets, and CloudTrail events.\n"
        "  2. A CI/CD service role grants ``iam:PassRole`` with "
        "``Resource: '*'`` (IAM-004). Any holder of the role can "
        "hand any IAM role in the account to any service that "
        "calls ``iam:PassRole`` — including Lambda itself.\n"
        "  3. An attacker who reads the Lambda env (a "
        "compromised CI runner, a misattached IAM policy, an "
        "engineer with broad read access) gets the credential. "
        "If that credential is the CI/CD principal — or if "
        "they can reach the principal via separate means — the "
        "PassRole wildcard lets them launch a Lambda / EC2 / "
        "CodeBuild instance under any role in the account, "
        "running code under whatever identity they choose. "
        "Either fix breaks the chain."
    )
    return [Chain(
        chain_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        confidence=min_confidence(triggers),
        summary=RULE.summary,
        narrative=narrative,
        mitre_attack=list(RULE.mitre_attack),
        kill_chain_phase=RULE.kill_chain_phase,
        triggering_check_ids=["LMB-003", "IAM-004"],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
