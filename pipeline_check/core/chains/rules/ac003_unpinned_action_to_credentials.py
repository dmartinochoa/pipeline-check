"""AC-003. Unpinned Action to Credential Exfiltration.

A workflow that uses third-party actions pinned only by tag (mutable)
and exposes long-lived AWS credentials gives the action's author
(or anyone who can re-tag) the ability to swap in malicious code and
exfiltrate the credentials.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-003",
    title="Unpinned Action to Credential Exfiltration",
    severity=Severity.HIGH,
    summary=(
        "A workflow consumes third-party actions by mutable tag "
        "(`@v1`, `@main`) AND holds long-lived cloud credentials. "
        "An action maintainer (or an attacker who compromises the "
        "action repo) can swap in malicious code on the next run and "
        "exfiltrate the credentials."
    ),
    mitre_attack=(
        "T1195.001",  # Supply Chain Compromise: Software Dependencies
        "T1552.001",  # Unsecured Credentials: in Files
    ),
    kill_chain_phase="supply-chain -> credential-access -> exfiltration",
    references=(
        "https://blog.gitguardian.com/github-actions-security-cheat-sheet/",
        "https://github.com/tj-actions/changed-files",  # tj-actions/changed-files compromise
    ),
    recommendation=(
        "Pin every third-party action to a 40-char SHA. Combined with "
        "OIDC short-lived credentials this chain becomes infeasible: "
        "a compromised action no longer has a valid long-lived secret "
        "to steal."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-001", "GHA-005"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability follows the AC-002 model: intersect the supply-
    # chain leg's ``job_anchors`` (GHA-001, the jobs whose steps
    # ``uses:`` an unpinned third-party action) with the credential
    # leg's ``job_anchors`` (GHA-005, the jobs that can read long-
    # lived AWS keys — job/step-level env, or workflow-level env
    # inherited into every job). A shared job means the now-malicious
    # action and the credential it can read coexist in one runner
    # process; that's the credential-exfiltration path. The chain
    # still fires when the intersection is empty so the legacy file-
    # co-occurrence signal isn't regressed, but the report flags it
    # as unconfirmed.
    grouped = group_by_resource(findings, ["GHA-001", "GHA-005"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha001 = ck_map["GHA-001"]
        gha005 = ck_map["GHA-005"]
        triggers = [gha001, gha005]

        unpinned_jobs = set(gha001.job_anchors)
        cred_jobs = set(gha005.job_anchors)
        shared = sorted(cred_jobs & unpinned_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"unpinned action and long-lived AWS keys share job "
                f"{shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the unpinned action "
                f"and the long-lived AWS credential are reachable "
                f"from the same job(s) ({shared_repr}). The "
                f"compromised upstream code runs in the same runner "
                f"process that holds ``$AWS_ACCESS_KEY_ID`` / "
                f"``$AWS_SECRET_ACCESS_KEY`` in its environment."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the unpinned action "
                "and the long-lived AWS credential land in different "
                "jobs of the same workflow file, with no env-"
                "inheritance link between them. Treat as a co-"
                "occurrence signal rather than a proven path."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. One or more third-party actions are referenced by "
            "mutable tag (GHA-001), the maintainer can rewrite the "
            "tag pointer at any time.\n"
            "  2. Same workflow holds long-lived AWS credentials in "
            "env (GHA-005).\n"
            "  3. The next time the workflow runs, the now-malicious "
            "action reads `$AWS_ACCESS_KEY_ID` / `$AWS_SECRET_ACCESS_KEY` "
            "from the environment and POSTs them to an attacker host. "
            "The credentials remain valid until manually revoked.\n"
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
            triggering_check_ids=["GHA-001", "GHA-005"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
