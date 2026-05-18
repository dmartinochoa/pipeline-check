"""AC-006. Cache Poisoning via Untrusted Trigger.

A workflow that caches build state with a key that an attacker can
influence (e.g. PR-controlled paths) AND accepts a fork-PR trigger
lets that attacker plant a poisoned cache entry the next privileged
build will consume.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-006",
    title="Cache Poisoning via Untrusted Trigger",
    severity=Severity.HIGH,
    summary=(
        "A workflow accepts an untrusted trigger (fork PR, "
        "issue_comment) AND uses an attacker-influenceable cache key. "
        "The attacker plants a poisoned cache entry that the next "
        "privileged build (push to main, scheduled deploy) restores "
        "and trusts."
    ),
    mitre_attack=(
        "T1554",      # Compromise Host Software Binary
        "T1195.002",  # Supply Chain Compromise: Software Supply Chain
    ),
    kill_chain_phase="initial-access -> persistence -> impact",
    references=(
        "https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/",
        "https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#restrictions-for-accessing-a-cache",
    ),
    recommendation=(
        "Lock cache keys to verifiable inputs (lockfile hashes, not "
        "PR-controlled paths). Restrict caches to push events only "
        "and scope by ref. Either fix breaks the chain."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-002", "GHA-011"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability: a shared job between GHA-002 (the job that runs
    # PR-head code under pull_request_target) and GHA-011 (the job
    # whose cache step has a tainted key) confirms the direct
    # poisoning primitive — the malicious PR-head Makefile / build
    # script writes whatever it wants into the cache the same job
    # is populating, and the next privileged restore consumes it.
    # Disjoint jobs still co-occur on a poisonable workflow file
    # but require an extra step (the PR-head code influencing
    # another job's cache content); we keep that as the unconfirmed
    # signal rather than dropping the chain.
    grouped = group_by_resource(findings, ["GHA-002", "GHA-011"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha002 = ck_map["GHA-002"]
        gha011 = ck_map["GHA-011"]
        triggers = [gha002, gha011]

        prhead_jobs = set(gha002.job_anchors)
        cache_jobs = set(gha011.job_anchors)
        shared = sorted(prhead_jobs & cache_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"PR-head checkout and poisonable cache share job "
                f"{shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the same job(s) "
                f"({shared_repr}) both run PR-head code AND "
                f"populate the cache under the attacker-influenced "
                f"key. The malicious build script writes directly "
                f"into the cache entry that a later privileged run "
                f"will restore."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the PR-head "
                "checkout and the poisonable cache key fire on the "
                "same workflow file but in different jobs. The "
                "attack still works when the PR-head code "
                "influences the artifact the caching job ships; "
                "treat as a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. Workflow accepts `pull_request_target` and checks "
            "out PR-head code (GHA-002), fork PRs run in a context "
            "that can write to the repo's cache namespace.\n"
            "  2. The cache key is influenceable by attacker-controlled "
            "input (GHA-011), e.g. it hashes a path under the PR "
            "tree rather than a stable lockfile.\n"
            "  3. Attacker opens fork PR that populates the cache "
            "with a poisoned `node_modules` (or similar). The next "
            "main-branch build restores that cache and ships the "
            "attacker's payload.\n"
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
            triggering_check_ids=["GHA-002", "GHA-011"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
