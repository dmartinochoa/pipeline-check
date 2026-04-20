"""AC-006 — Cache Poisoning via Untrusted Trigger.

A workflow that caches build state with a key that an attacker can
influence (e.g. PR-controlled paths) AND accepts a fork-PR trigger
lets that attacker plant a poisoned cache entry the next privileged
build will consume.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
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
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-002", "GHA-011"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-002"], ck_map["GHA-011"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. Workflow accepts `pull_request_target` and checks "
            "out PR-head code (GHA-002) — fork PRs run in a context "
            "that can write to the repo's cache namespace.\n"
            "  2. The cache key is influenceable by attacker-controlled "
            "input (GHA-011) — e.g. it hashes a path under the PR "
            "tree rather than a stable lockfile.\n"
            "  3. Attacker opens fork PR that populates the cache "
            "with a poisoned `node_modules` (or similar). The next "
            "main-branch build restores that cache and ships the "
            "attacker's payload."
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
            triggering_check_ids=["GHA-002", "GHA-011"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
