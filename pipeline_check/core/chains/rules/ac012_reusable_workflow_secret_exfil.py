"""AC-012. Reusable Workflow Secret Exfiltration (GitHub Actions).

A reusable workflow whose ``uses:`` ref is mutable (tag / branch
rather than a 40-char SHA) AND that's called with ``secrets:
inherit`` is a one-step credential exfiltration channel. The owner
of the upstream repo can repoint the tag to a malicious commit, and
the next caller-side run hands every caller secret to that commit
under cover of GitHub's normal reusable-workflow plumbing.

Distinct from:

  * AC-001, fork-PR credential theft via ``pull_request_target``.
  * AC-009, repo-poisoning combo with multiple GHA-* findings on
    the same workflow.

The chain fires when both GHA-025 (reusable workflow not pinned to
SHA) and GHA-034 (``secrets: inherit``) fire on the *same* workflow
file. A different-workflow combo is not the same threat, the
secret surface is decided per call site, not at the catalog level.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-012",
    title="Reusable Workflow Secret Exfiltration",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow calls a reusable workflow whose ``uses:`` ref is "
        "mutable (tag / branch) AND passes ``secrets: inherit``. The "
        "owner of the upstream repo can repoint the tag to malicious "
        "code; the next caller-side run hands every caller secret to "
        "that code under cover of normal reusable-workflow plumbing."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1552.001",  # Unsecured Credentials: in Files
        "T1078",      # Valid Accounts
    ),
    kill_chain_phase="initial-access -> credential-access -> exfiltration",
    references=(
        "https://docs.github.com/en/actions/sharing-automations/reusing-workflows#using-inputs-and-secrets-in-a-reusable-workflow",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3-Dependency-Chain-Abuse",
    ),
    recommendation=(
        "Break either leg of the chain. (a) Replace the mutable ref "
        "(``@v2`` / ``@main``) with a 40-char commit SHA so an "
        "upstream tag move can't repoint to attacker code. (b) Replace "
        "``secrets: inherit`` with an explicit allowlist (``secrets: "
        "{ NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }``) so a compromised "
        "callee can't reach unrelated credentials. Doing (a) closes "
        "the supply-chain leg; (b) limits blast radius even if (a) "
        "is somehow bypassed."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-025", "GHA-034"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability: a shared job between GHA-025 (the unpinned
    # reusable-workflow ``uses:`` call site) and GHA-034 (the
    # ``secrets: inherit`` call site) confirms the tag-move-to-
    # credential-exfil happens in one execution context. Two
    # reusable-workflow calls on the same file but in different jobs
    # are independently risky but don't compose into the single-step
    # exfil unless the same call site exposes both legs.
    grouped = group_by_resource(findings, ["GHA-025", "GHA-034"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha025 = ck_map["GHA-025"]
        gha034 = ck_map["GHA-034"]
        triggers = [gha025, gha034]

        unpinned_jobs = set(gha025.job_anchors)
        inherit_jobs = set(gha034.job_anchors)
        shared = sorted(unpinned_jobs & inherit_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"Unpinned reusable-workflow call and ``secrets: inherit`` "
                f"share job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the same job(s) "
                f"({shared_repr}) both call the reusable workflow "
                f"via a mutable ref AND pass ``secrets: inherit``. "
                f"A tag move on the callee repo exfiltrates the "
                f"entire caller secret surface in one run, no "
                f"second call site required."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the unpinned "
                "reusable-workflow ref and the ``secrets: inherit`` "
                "fire on the same workflow file but in different "
                "jobs. Each leg is independently risky; treat as "
                "a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. A reusable-workflow ``uses:`` ref is pinned to a "
            "tag or branch rather than a commit SHA (GHA-025). The "
            "callee repo's owner can repoint that ref to any commit "
            "they choose, including one that exfiltrates whatever "
            "secrets it receives.\n"
            "  2. The same call site passes ``secrets: inherit`` "
            "(GHA-034). Every caller-defined secret reachable to the "
            "calling workflow becomes available to the callee with "
            "no allowlist.\n"
            "  3. A tag-move attack on the callee repo therefore "
            "exfiltrates the entire caller secret surface in a "
            "single run, before any review of the called code.\n"
            f"{reach_narrative}"
        )

        chain_confidence = Confidence.HIGH if confirmed else min_confidence(triggers)

        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=chain_confidence,
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["GHA-025", "GHA-034"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
