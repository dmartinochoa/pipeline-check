"""AC-033. Environment-secret laundering to unprotected job.

Two legs:

  * ``TAINT-009`` — a secret read inside an ``environment:``-bound
    job flows via ``needs.<job>.outputs.*`` to a consumer job
    without ``environment:``. The consumer operates with the secret
    but without the environment's protection gates (required
    reviewers, wait timer, deployment-branch constraints).
  * ``GHA-098`` — the same workflow deploys without a security-scan
    gate, or ``GHA-014`` (deploy environment posture).

Independently: TAINT-009 is an authorization bypass; GHA-098 is a
deployment gate gap. Together: the environment-protected secret
reaches an unprotected job that performs a deploy, meaning the
attacker bypasses both the review gate (via output laundering) and
the scan gate (via the missing security check) in one flow.

Reachability model: per-workflow co-occurrence. Both legs fire on the
same workflow file. The TAINT-009 finding already confirms the
cross-job dataflow exists.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-033",
    title="Environment-secret laundering to unprotected deploy job",
    severity=Severity.CRITICAL,
    summary=(
        "A protected environment secret flows through "
        "``jobs.<id>.outputs:`` to a consumer job without "
        "``environment:`` binding (TAINT-009) AND the workflow "
        "deploys without a security-scan gate (GHA-098). The "
        "environment's review gates are bypassed: the secret reaches "
        "an unprotected job that performs a production deploy."
    ),
    mitre_attack=(
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1548",      # Abuse Elevation Control Mechanism
    ),
    kill_chain_phase=(
        "privilege-escalation (environment gate bypass) -> "
        "lateral-movement (secret in unprotected job) -> "
        "impact (ungated deploy)"
    ),
    references=(
        "https://docs.github.com/en/actions/deployment/"
        "targeting-different-environments/managing-environments-for-deployment",
    ),
    recommendation=(
        "Break either leg:\n"
        "  1. Add an ``environment:`` binding to the consuming job "
        "(TAINT-009): every job that touches the secret must go "
        "through the same protection gate.\n"
        "  2. Add a security-scan gate before the deploy step "
        "(GHA-098): a scan dependency ensures the deploy job "
        "doesn't run without validation.\n"
        "Best: restructure the workflow so the secret never "
        "leaves the environment-bound job's boundary. Perform the "
        "deploy operation in the same protected job."
    ),
    providers=("github",),
    triggering_check_ids=("TAINT-009", "GHA-098"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["TAINT-009", "GHA-098"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        taint = ck_map["TAINT-009"]
        deploy = ck_map["GHA-098"]
        triggers = [taint, deploy]
        narrative = (
            f"On workflow `{resource}`:\n"
            f"  1. A protected environment secret flows through job "
            f"outputs to a consumer job without ``environment:`` "
            f"binding (TAINT-009). The environment's required "
            f"reviewers, wait timer, and branch constraints do not "
            f"apply to the consuming job.\n"
            f"  2. The workflow deploys without a security-scan gate "
            f"(GHA-098). No intermediate check prevents the "
            f"unprotected job from reaching production.\n"
            f"  3. Composite: the secret mint job passes review, but "
            f"the deploy job that uses the secret doesn't. An "
            f"attacker who can trigger the workflow gets the secret "
            f"in a job that runs without any of the environment's "
            f"protection rules."
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
            triggering_check_ids=["TAINT-009", "GHA-098"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
