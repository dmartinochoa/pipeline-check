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

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-009",
    title="Supply Chain Repo Poisoning",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow uses unpinned third-party actions (GHA-001), "
        "checks out PR head on a ``pull_request_target`` trigger "
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
    # Reachability: a single job that BOTH pulls an unpinned action
    # AND runs the script-injection sink AND has the credential
    # literal in scope is the tight one-execution-context route to
    # the plaintext secret. Three-way job_anchors intersection
    # captures that. GHA-008 fans its anchor out to every job when
    # the credential lives at workflow ``env:`` level (inherited)
    # so a top-level secret intersects with any GHA-001 / GHA-002
    # job. Disjoint anchors still co-occur on the workflow file but
    # don't compose into the single-job exploit primitive — for
    # instance an unpinned action in a docs-build job + an
    # injection sink in a release job + a top-level-scoped literal
    # is still bad, but the unpinned-action leg's exploit path is
    # via the next upstream release rather than the immediate PR.
    grouped = group_by_resource(findings, ["GHA-001", "GHA-002", "GHA-008"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha001 = ck_map["GHA-001"]
        gha002 = ck_map["GHA-002"]
        gha008 = ck_map["GHA-008"]
        triggers = [gha001, gha002, gha008]

        action_jobs = set(gha001.job_anchors)
        inj_jobs = set(gha002.job_anchors)
        secret_jobs = set(gha008.job_anchors)
        shared = sorted(action_jobs & inj_jobs & secret_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"Unpinned action, injection sink, and literal "
                f"credential share job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the same job(s) "
                f"({shared_repr}) pull the unpinned action AND "
                f"interpolate PR-controlled context AND have the "
                f"literal credential in scope. A fork PR exfiltrates "
                f"the plaintext secret through the injection sink "
                f"in one execution context, with the unpinned-action "
                f"leg as a second route on the next upstream release."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the three legs fire "
                "on the same workflow file but do not all share a "
                "single job. Each leg is independently exploitable "
                "(and the credential literal must be rotated "
                "regardless); treat as a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. Third-party action is referenced by tag rather than "
            "commit SHA (GHA-001). The maintainer (or anyone who "
            "compromises their account) can re-tag a malicious "
            "version and have it executed in this repo on the next "
            "run.\n"
            "  2. The workflow checks out PR head on a "
            "`pull_request_target` trigger (GHA-002). The checked-out "
            "code runs with the target branch's privileges.\n"
            "  3. The workflow file also carries literal credential-"
            "shaped values in plaintext (GHA-008). Either of the "
            "above two execution vectors can read them; the fork "
            "itself can read them too if the repo accepts external "
            "PRs.\n"
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
            triggering_check_ids=["GHA-001", "GHA-002", "GHA-008"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
