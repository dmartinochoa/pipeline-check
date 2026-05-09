"""AC-018. Unpinned action lands on a deploy job with no approval gate.

The deploy-stage attack pattern that several real GHA-supply-chain
incidents have exploited: a workflow uses a third-party action
pinned by tag (or branch) rather than commit SHA, AND its deploy
job has no GitHub Environment binding (which is what gates the
job behind required-reviewer approval). When the upstream action
maintainer's account is compromised, or the maintainer pushes a
malicious release under the same tag, the next workflow run
executes attacker-controlled code, and the deploy job ships it
without a human in the loop.

Each leg is a finding on its own: ``GHA-001`` flags the unpinned
action (HIGH) and ``GHA-014`` flags the missing environment binding
(MEDIUM). The chain captures that the *combination* on the same
workflow file is materially worse: pinning would defeat the
supply-chain leg, environment binding would defeat the deploy leg,
and either fix breaks the chain on its own.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-018",
    title="Unpinned action lands on deploy job with no environment gate",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow uses a third-party action pinned by tag rather "
        "than commit SHA (GHA-001) AND its deploy job has no "
        "``environment:`` binding (GHA-014). A compromise of the "
        "upstream action maintainer's account, or a malicious "
        "release re-tagged under the existing version, runs in "
        "the deploy job's context without a required-reviewer "
        "gate, shipping attacker-controlled code to production "
        "on the next workflow trigger."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
        "T1556",      # Modify Authentication Process
    ),
    kill_chain_phase="initial-access -> execution -> impact",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
        "https://docs.github.com/en/actions/deployment/targeting-different-environments/managing-environments-for-deployment",
        "https://www.stepsecurity.io/blog/popular-github-action-tj-actions-changed-files-is-compromised",
    ),
    recommendation=(
        "Pin every third-party action to a 40-char commit SHA "
        "(``actions/checkout@<sha> # v4.1.0``) and put deploy "
        "jobs behind a GitHub Environment that requires reviewer "
        "approval and restricts deployment branches. Either fix "
        "alone breaks the chain, the SHA pin removes the supply-"
        "chain leg, the environment gate removes the unattended-"
        "deploy leg. Best is both, plus a deployment-branch "
        "restriction so only ``main`` / ``release/*`` can reach "
        "the gated environment."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-001", "GHA-014"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-001", "GHA-014"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-001"], ck_map["GHA-014"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. A third-party action is pinned by tag or branch "
            "rather than a commit SHA (GHA-001). The maintainer "
            "(or anyone who compromises their account) can re-tag "
            "a malicious version under the existing reference, "
            "and the next workflow run executes the attacker's "
            "code with the workflow's privileges.\n"
            "  2. The same workflow's deploy job has no "
            "``environment:`` binding (GHA-014). GitHub's "
            "environment-protection rules, required reviewers, "
            "deployment-branch restrictions, only enforce against "
            "jobs that declare an environment, so this job's "
            "deployment runs unattended on every successful build.\n"
            "  3. The combination ships attacker-controlled code "
            "from a compromised upstream action straight to "
            "production. SHA-pinning alone defeats leg 1; "
            "environment-gating alone defeats leg 2; either "
            "fix breaks the chain."
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
            triggering_check_ids=["GHA-001", "GHA-014"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
