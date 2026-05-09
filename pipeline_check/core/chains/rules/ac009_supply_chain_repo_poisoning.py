"""AC-009. Supply Chain Repo Poisoning.

A workflow combines three legs that, together, give a fork-PR
attacker durable code execution against the repo's stored secrets:
unpinned third-party actions (mutable supply chain), a script-
injection sink (code execution from untrusted PR context), and
literal secrets in the file (the prize, already in plaintext).

Each leg is a HIGH-or-CRITICAL finding on its own. The chain
captures that the *combination* is materially worse: even if the
attacker can't immediately exfiltrate the secrets via the script-
injection sink, the unpinned action gives them a second route on
the next release of the upstream action.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-009",
    title="Supply Chain Repo Poisoning",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow uses unpinned third-party actions (GHA-001), "
        "interpolates untrusted PR context into a shell ``run:`` block "
        "(GHA-002), and carries literal secrets in the YAML (GHA-008). "
        "Any one of those is exploitable; the combination gives a "
        "fork-PR attacker two independent code-execution paths to the "
        "same plaintext credentials."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase="initial-access -> credential-access",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
        "https://securitylab.github.com/research/github-actions-untrusted-input/",
    ),
    recommendation=(
        "Pin every third-party action to a commit SHA (not a tag). "
        "Move secrets out of the YAML and into the GitHub Secrets "
        "store, referenced via ``${{ secrets.NAME }}``. Replace "
        "direct interpolation of PR-controlled context (`event.*`, "
        "`pull_request.*`) into shell with environment-variable "
        "indirection."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-001", "GHA-002", "GHA-008"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-001", "GHA-002", "GHA-008"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-001"], ck_map["GHA-002"], ck_map["GHA-008"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. Third-party action is referenced by tag rather than "
            "commit SHA (GHA-001). The maintainer (or anyone who "
            "compromises their account) can re-tag a malicious "
            "version and have it executed in this repo on the next "
            "run.\n"
            "  2. The same workflow interpolates PR-controlled context "
            "into a `run:` block (GHA-002). Anyone opening a PR can "
            "execute arbitrary shell with the workflow's privileges.\n"
            "  3. The workflow file also carries literal credential-"
            "shaped values in plaintext (GHA-008). Either of the "
            "above two execution vectors can read them; the fork "
            "itself can read them too if the repo accepts external "
            "PRs."
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
            triggering_check_ids=["GHA-001", "GHA-002", "GHA-008"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
