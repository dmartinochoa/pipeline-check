"""AC-007 — IAM Privilege Escalation via CodeBuild.

A CodeBuild project that runs in privileged mode AND has an attached
service role with `iam:PassRole` + wildcard actions lets a malicious
buildspec assume any role in the account.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-007",
    title="IAM Privilege Escalation via CodeBuild",
    severity=Severity.CRITICAL,
    summary=(
        "A CodeBuild project runs in privileged mode AND its service "
        "role grants wildcard IAM actions or unconstrained PassRole. "
        "Anyone who can land a buildspec change (or a poisoned "
        "dependency the build pulls) can assume a higher-privileged "
        "role and pivot across the account."
    ),
    mitre_attack=(
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1548.005",  # Abuse Elevation Control: Temporary Elevated Cloud Access
        "T1098.001",  # Account Manipulation: Additional Cloud Credentials
    ),
    kill_chain_phase="execution -> privilege-escalation -> lateral-movement",
    references=(
        "https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/",
        "https://docs.aws.amazon.com/codebuild/latest/userguide/security-iam.html",
    ),
    recommendation=(
        "Strip wildcard actions and unconstrained PassRole from the "
        "CodeBuild service role; pin PassRole to specific role ARNs "
        "with a build-tag condition. Disable privileged mode unless "
        "the build genuinely requires Docker-in-Docker."
    ),
    providers=("aws", "terraform", "cloudformation"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # AWS findings on different resources (a CodeBuild project ARN vs
    # an IAM role ARN) — match by presence, not by shared resource.
    if not has_failing(findings, "CB-002"):
        return []
    if not (has_failing(findings, "IAM-002") or has_failing(findings, "IAM-004")):
        return []
    triggers = [
        f for f in findings
        if (not f.passed) and f.check_id in {"CB-002", "IAM-002", "IAM-004"}
    ]
    cb_resources = sorted({f.resource for f in triggers if f.check_id == "CB-002"})
    iam_resources = sorted({
        f.resource for f in triggers if f.check_id in {"IAM-002", "IAM-004"}
    })
    iam_check_ids = sorted({
        f.check_id for f in triggers if f.check_id.startswith("IAM-")
    })
    narrative = (
        "In this AWS account:\n"
        f"  1. CodeBuild project(s) {', '.join(cb_resources)} run in "
        "privileged mode (CB-002) — buildspec processes can call the "
        "Docker daemon, mount the host fs, and intercept other jobs.\n"
        f"  2. An IAM role in scope ({', '.join(iam_resources)}) "
        f"grants {', '.join(iam_check_ids)} (wildcard action and/or "
        "unconstrained PassRole).\n"
        "  3. A malicious buildspec (planted via a PR or via a "
        "compromised dependency) calls `aws sts assume-role` against "
        "any target role and pivots — privileged mode means the "
        "isolation guarantees normally provided by the build sandbox "
        "are absent."
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
        triggering_check_ids=["CB-002"] + iam_check_ids,
        triggering_findings=triggers,
        resources=cb_resources + iam_resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
