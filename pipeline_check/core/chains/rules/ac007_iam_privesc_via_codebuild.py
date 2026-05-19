"""AC-007. IAM Privilege Escalation via CodeBuild.

A CodeBuild project that runs in privileged mode AND has an attached
service role with `iam:PassRole` + wildcard actions lets a malicious
buildspec assume any role in the account.

ResourceAnchor phase 1: prefers a confirmed pairing when the
CodeBuild project's ``serviceRole`` ARN IS the role that IAM-002
flagged for wildcard authority or IAM-004 flagged for unconstrained
``iam:PassRole``. That's a strictly tighter claim than the prior
"some privileged project + some bad role in the account"
co-occurrence: when the same role both governs the privileged
build's execution context AND grants the privesc primitive,
anyone who lands a buildspec change inherits the privilege escalation
in one step. CB-002 emits ``iam_role(serviceRole)``; IAM-002 and
IAM-004 emit ``iam_role(Arn)``; ``group_by_anchor`` on ``iam_role``
matches them. Falls back to scan-level co-occurrence when the
project's service role differs from the bad role (the cross-principal
attack still applies but requires a separate pivot step).
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_anchor, has_failing, min_confidence

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
    triggering_check_ids=("CB-002", "IAM-002", "IAM-004"),
)


def _base_narrative(cb_resources: list[str], iam_check_ids: list[str]) -> str:
    return (
        f"  1. CodeBuild project(s) {', '.join(cb_resources)} run in "
        "privileged mode (CB-002), buildspec processes can call the "
        "Docker daemon, mount the host fs, and intercept other jobs.\n"
        f"  2. The IAM-side leg fires {', '.join(iam_check_ids)} "
        "(wildcard action and/or unconstrained PassRole).\n"
    )


def _emit_confirmed(
    role_arn: str,
    cb002_findings: list[Finding],
    iam_legs: list[Finding],
) -> Chain:
    triggers = [*cb002_findings, *iam_legs]
    iam_check_ids = sorted({f.check_id for f in iam_legs})
    cb_resources = sorted({f.resource for f in cb002_findings})
    narrative = (
        f"For role `{role_arn}`:\n"
        + _base_narrative(cb_resources, iam_check_ids)
        + f"  3. Reachability confirmed: privileged CodeBuild "
        f"project(s) {', '.join(cb_resources)} run AS `{role_arn}`, "
        f"the same role flagged by {', '.join(iam_check_ids)}. A "
        f"malicious buildspec (planted via PR, poisoned dep, or a "
        f"compromised upstream action) calls ``aws sts get-caller-"
        f"identity`` and the wildcard / PassRole primitive applies "
        f"immediately, no cross-principal pivot needed."
    )
    return Chain(
        chain_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        confidence=Confidence.HIGH,
        summary=RULE.summary,
        narrative=narrative,
        mitre_attack=list(RULE.mitre_attack),
        kill_chain_phase=RULE.kill_chain_phase,
        triggering_check_ids=["CB-002", *iam_check_ids],
        triggering_findings=triggers,
        resources=[role_arn],
        references=list(RULE.references),
        recommendation=RULE.recommendation,
        confirmed_reachable=True,
        reachability_note=(
            f"CB-002 project(s) serviceRole matches IAM-side role "
            f"`{role_arn}`"
        ),
    )


def _findings_anchored_to(
    findings: list[Finding], check_id: str, role_arn: str,
) -> list[Finding]:
    """Return every failing *check_id* finding whose anchor set names
    *role_arn* under the ``iam_role`` kind.

    Plain ``group_by_anchor`` keeps one finding per (identity,
    check_id); this helper preserves the full per-anchor list so a
    role shared across multiple CodeBuild projects (or flagged twice
    by IAM-002 on different statements) carries every finding into
    the chain's triggering list and blast-radius prose.
    """
    out: list[Finding] = []
    for f in findings:
        if f.passed or f.check_id != check_id:
            continue
        for anchor in f.resource_anchors:
            if anchor.kind == "iam_role" and anchor.identity == role_arn:
                out.append(f)
                break
    return out


def match(findings: list[Finding]) -> list[Chain]:
    # ResourceAnchor phase 1: confirmed pairing per iam_role identity
    # shared between CB-002 (project's service role) and either of
    # the IAM-side legs (IAM-002 wildcard or IAM-004 PassRole *).
    # ``group_by_anchor`` is the right primitive to find which roles
    # are confirmed; we then re-walk findings to recover every
    # finding anchored to that role so a role shared across multiple
    # CodeBuild projects (or flagged twice by IAM-002) keeps every
    # finding in the chain's triggering list.
    by_role_002 = group_by_anchor(findings, ["CB-002", "IAM-002"], "iam_role")
    by_role_004 = group_by_anchor(findings, ["CB-002", "IAM-004"], "iam_role")
    confirmed_roles: set[str] = (
        set(by_role_002.keys()) | set(by_role_004.keys())
    )
    out: list[Chain] = []
    matched_findings: set[int] = set()
    for role_arn in confirmed_roles:
        cb002 = _findings_anchored_to(findings, "CB-002", role_arn)
        iam002 = _findings_anchored_to(findings, "IAM-002", role_arn)
        iam004 = _findings_anchored_to(findings, "IAM-004", role_arn)
        iam_legs = [*iam002, *iam004]
        for f in (*cb002, *iam_legs):
            matched_findings.add(id(f))
        out.append(_emit_confirmed(role_arn, cb002, iam_legs))

    # Co-occurrence fallback: CB-002 fires somewhere and at least one
    # IAM-side leg fires somewhere, but no shared service-role ARN
    # matched. The original narrative (account-wide CodeBuild risk +
    # account-wide IAM risk, exploitable via cross-principal pivot)
    # still applies.
    if not has_failing(findings, "CB-002"):
        return out
    if not (has_failing(findings, "IAM-002") or has_failing(findings, "IAM-004")):
        return out
    unmatched = [
        f for f in findings
        if (not f.passed)
        and f.check_id in {"CB-002", "IAM-002", "IAM-004"}
        and id(f) not in matched_findings
    ]
    unmatched_legs = {f.check_id for f in unmatched}
    has_cb = "CB-002" in unmatched_legs
    has_iam = bool(unmatched_legs & {"IAM-002", "IAM-004"})
    if has_cb and has_iam:
        triggers = unmatched
        cb_resources = sorted({
            f.resource for f in triggers if f.check_id == "CB-002"
        })
        iam_resources = sorted({
            f.resource for f in triggers
            if f.check_id in {"IAM-002", "IAM-004"}
        })
        iam_check_ids = sorted({
            f.check_id for f in triggers if f.check_id.startswith("IAM-")
        })
        narrative = (
            "In this AWS account:\n"
            + _base_narrative(cb_resources, iam_check_ids)
            + f"  3. Reachability unconfirmed: no privileged CodeBuild "
            f"project runs as one of the IAM-side roles "
            f"({', '.join(iam_resources)}). A malicious buildspec can "
            f"still pivot to the bad role via ``sts assume-role`` if "
            f"the project's principal can reach it, but the "
            f"single-execution-context escalation isn't visible from "
            f"the scan."
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
            triggering_check_ids=["CB-002"] + iam_check_ids,
            triggering_findings=triggers,
            resources=cb_resources + iam_resources,
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=False,
            reachability_note="",
        ))
    return out
