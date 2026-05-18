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

from ...checks.base import Confidence, Finding, Severity
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
    # Reachability mirrors the AC-002 pilot: intersect the supply-
    # chain leg's ``job_anchors`` (GHA-001, the jobs whose steps use
    # an unpinned ``uses:``) with the deploy-side ``job_anchors``
    # (GHA-014, the jobs that deploy without an environment gate).
    # A non-empty intersection means the same job both pulls
    # attacker-controllable upstream code AND ships unattended — a
    # confirmed end-to-end path. The chain still fires on disjoint
    # anchors so the legacy file-co-occurrence signal isn't
    # regressed, but the report flags it as unconfirmed.
    grouped = group_by_resource(findings, ["GHA-001", "GHA-014"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha001 = ck_map["GHA-001"]
        gha014 = ck_map["GHA-014"]
        triggers = [gha001, gha014]

        unpinned_jobs = set(gha001.job_anchors)
        deploy_jobs = set(gha014.job_anchors)
        shared = sorted(deploy_jobs & unpinned_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"unpinned action and ungated deploy share job "
                f"{shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the unpinned "
                f"action and the ungated deploy fire in the same "
                f"job(s) ({shared_repr}). A compromised upstream "
                f"release runs in the deploy job itself, with its "
                f"environment secrets and credentials in scope."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the unpinned "
                "action and the ungated deploy fire on the same "
                "workflow file but in different jobs. The attack "
                "is still possible when the unpinned action "
                "produces artifacts the deploy job consumes; "
                "treat as a co-occurrence signal rather than a "
                "proven path."
            )

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
            "fix breaks the chain.\n"
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
            triggering_check_ids=["GHA-001", "GHA-014"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
