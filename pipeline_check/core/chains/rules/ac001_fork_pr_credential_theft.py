"""AC-001 — Fork-PR Credential Theft (GitHub Actions).

A `pull_request_target` workflow that checks out PR-head code while
holding long-lived AWS credentials lets a fork PR run attacker code
with those credentials in scope. This is the PyTorch supply-chain
compromise pattern.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
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
)


def match(findings: list[Finding]) -> list[Chain]:
    # Both legs must fire on the SAME workflow file — a different-workflow
    # combo isn't the same threat (the credentials would be elsewhere).
    grouped = group_by_resource(findings, ["GHA-002", "GHA-005"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-002"], ck_map["GHA-005"]]
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
            "the PR."
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
            triggering_check_ids=["GHA-002", "GHA-005"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
