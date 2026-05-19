"""AC-019. Lambda env-secret meets a CI/CD role with PassRole *.

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
  any IAM role to any service that calls ``iam:PassRole``. Lambda
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
sit in different AWS services, the pivot crosses service lines.

ResourceAnchor phase 1: AC-019 prefers a confirmed pairing when
the LMB-003 Lambda's *execution role* IS the wildcard-PassRole
role IAM-004 flagged. That's a strictly tighter claim than the
generic "credential leak + PassRole wildcard somewhere in the
account" co-occurrence: when the same role both governs a
secret-leaking Lambda's execution context AND carries
``iam:PassRole *``, anyone who exfils the env var inherits the
role-hop primitive in one step. LMB-003 emits two anchors per
finding (``lambda_fn`` for the function ARN + ``iam_role`` for
the execution-role ARN) and IAM-004 emits ``iam_role`` for its
own role's ARN; ``group_by_anchor`` on ``iam_role`` matches the
two when present. Falls back to scan-level co-occurrence (the
original signal) when the execution role and the PassRole-*
role differ — that's the looser "two account-wide problems"
shape that's still worth surfacing.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_anchor, has_failing, min_confidence

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


def _base_narrative() -> str:
    return (
        "  1. At least one Lambda function carries a credential-"
        "shaped literal in its env vars (LMB-003). Lambda env "
        "vars are visible to anyone with "
        "``lambda:GetFunctionConfiguration``, a strictly wider "
        "audience than the principal that can invoke the "
        "function. The value also persists in CloudFormation "
        "drift, change-sets, and CloudTrail events.\n"
        "  2. A CI/CD service role grants ``iam:PassRole`` with "
        "``Resource: '*'`` (IAM-004). Any holder of the role can "
        "hand any IAM role in the account to any service that "
        "calls ``iam:PassRole``, including Lambda itself.\n"
    )


def match(findings: list[Finding]) -> list[Chain]:
    # ResourceAnchor phase 1: same-role tightening. When the LMB-003
    # Lambda's execution role IS the IAM-004 wildcard-PassRole role,
    # emit a per-role chain whose narrative cites the role-equality
    # as the tightening fact. The chain still ships with
    # ``confirmed_reachable=False`` and weakest-leg confidence —
    # LMB-003 only proves a credential-shaped literal is in the env
    # vars, not that the leaked value is an AWS credential for THIS
    # role, so promoting to HIGH would overclaim exploitability.
    # The per-role narrative still distinguishes this signal from a
    # disjoint scan-level co-occurrence; consumers wanting the
    # tighter claim can read ``reachability_note`` for the role
    # match and pair it with a separate secret-classification step.
    by_role = group_by_anchor(findings, ["LMB-003", "IAM-004"], "iam_role")
    out: list[Chain] = []
    matched_findings: set[int] = set()
    for role_arn, ck_map in by_role.items():
        lmb003 = ck_map["LMB-003"]
        iam004 = ck_map["IAM-004"]
        triggers = [lmb003, iam004]
        matched_findings.add(id(lmb003))
        matched_findings.add(id(iam004))
        narrative = (
            f"For role `{role_arn}`:\n"
            + _base_narrative()
            + f"  3. Same-role tightening: the secret-leaking Lambda "
            f"(`{lmb003.resource}`) RUNS AS `{role_arn}`, and "
            f"`{role_arn}` is also the role IAM-004 flagged for "
            f"``iam:PassRole *``. IF the leaked env var contains "
            f"credentials for this role, the exfil-to-PassRole path "
            f"is single-step and single-execution-context. The leak "
            f"could also be a JWT / SMTP password / Stripe key / "
            f"other non-AWS credential, so this stays a co-"
            f"occurrence signal until a separate secret-"
            f"classification step ties the env-var content to AWS "
            f"credentials for this principal."
        )
        out.append(Chain(
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
            resources=[role_arn],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=False,
            reachability_note=(
                f"LMB-003 Lambda's execution role matches IAM-004 "
                f"role `{role_arn}` (role-equality only; env-var "
                f"content not verified as AWS credentials)"
            ),
        ))

    # Co-occurrence fallback: both legs fire but the Lambda's
    # execution role and the PassRole-* role are different roles. The
    # original AC-019 narrative (account-wide leak + account-wide
    # PassRole wildcard, exploitable via a separate principal-reach
    # step) still applies and is still worth surfacing.
    if has_failing(findings, "LMB-003") and has_failing(findings, "IAM-004"):
        unmatched = [
            f for f in findings
            if (not f.passed)
            and f.check_id in {"LMB-003", "IAM-004"}
            and id(f) not in matched_findings
        ]
        unmatched_legs = {f.check_id for f in unmatched}
        if "LMB-003" in unmatched_legs and "IAM-004" in unmatched_legs:
            triggers = unmatched
            resources = sorted({f.resource for f in triggers})
            narrative = (
                "In this AWS account scan:\n"
                + _base_narrative()
                + "  3. Reachability unconfirmed: no secret-leaking "
                "Lambda runs AS the wildcard-PassRole role. An "
                "attacker who reads the Lambda env still gets a "
                "credential; if it maps to a principal that can "
                "reach the PassRole-* role via separate means, the "
                "role-hop primitive applies. Treat as a co-occurrence "
                "signal — each leg is independently exploitable, just "
                "without the single-execution-context shortcut."
            )
            out.append(Chain(
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
                confirmed_reachable=False,
                reachability_note="",
            ))
    return out
