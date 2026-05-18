"""AC-001. Fork-PR Credential Theft (GitHub Actions).

A `pull_request_target` workflow that checks out PR-head code while
holding long-lived AWS credentials lets a fork PR run attacker code
with those credentials in scope. This is the PyTorch supply-chain
compromise pattern.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-001",
    title="Fork-PR Credential Theft (pull_request_target)",
    severity=Severity.CRITICAL,
    summary=(
        "A pull_request_target workflow checks out PR-head code while "
        "exposing long-lived AWS credentials. A fork-PR opener can run "
        "arbitrary code in the privileged context and exfiltrate the "
        "credentials before the PR is even reviewed."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1552.001",  # Unsecured Credentials: in Files
    ),
    kill_chain_phase="initial-access -> credential-access -> exfiltration",
    references=(
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        "https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability",
    ),
    recommendation=(
        "Break the chain by either (a) switching to `pull_request` "
        "(no write-scope token), or (b) replacing static AWS keys "
        "with OIDC `role-to-assume` scoped to the workflow."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-002", "GHA-005"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Both legs must fire on the SAME workflow file, a different-workflow
    # combo isn't the same threat (the credentials would be elsewhere).
    # Reachability: a shared job between GHA-002 (PR-head checkout) and
    # GHA-005 (long-lived AWS keys reachable from that job) confirms
    # the PyTorch-style fork-PR credential-theft primitive in its
    # most-direct form.
    grouped = group_by_resource(findings, ["GHA-002", "GHA-005"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha002 = ck_map["GHA-002"]
        gha005 = ck_map["GHA-005"]
        triggers = [gha002, gha005]

        prhead_jobs = set(gha002.job_anchors)
        cred_jobs = set(gha005.job_anchors)
        shared = sorted(prhead_jobs & cred_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"PR-head checkout and long-lived AWS keys share job "
                f"{shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the same job(s) "
                f"({shared_repr}) both run PR-head code AND can "
                f"read ``$AWS_ACCESS_KEY_ID`` / "
                f"``$AWS_SECRET_ACCESS_KEY`` from the environment."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the PR-head "
                "checkout and the long-lived AWS credential land "
                "in different jobs of the same workflow file. "
                "Treat as a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. Workflow uses `pull_request_target` and explicitly "
            "checks out the PR-head ref (GHA-002).\n"
            "  2. Same workflow holds long-lived AWS credentials in "
            "`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (GHA-005).\n"
            "  3. An attacker opens a fork PR with a malicious build "
            "step. The workflow runs with a write-scope GITHUB_TOKEN "
            "and the AWS keys in env, executes the attacker's code, "
            "and the keys leave the runner before any reviewer sees "
            "the PR.\n"
            f"{reach_narrative}"
        )

        if confirmed:
            chain_confidence = Confidence.HIGH
        else:
            chain_confidence = min_confidence(triggers)

        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=chain_confidence,
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["GHA-002", "GHA-005"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
