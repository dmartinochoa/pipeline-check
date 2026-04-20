"""AC-003 — Unpinned Action to Credential Exfiltration.

A workflow that uses third-party actions pinned only by tag (mutable)
and exposes long-lived AWS credentials gives the action's author
(or anyone who can re-tag) the ability to swap in malicious code and
exfiltrate the credentials.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
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
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-001", "GHA-005"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-001"], ck_map["GHA-005"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. One or more third-party actions are referenced by "
            "mutable tag (GHA-001) — the maintainer can rewrite the "
            "tag pointer at any time.\n"
            "  2. Same workflow holds long-lived AWS credentials in "
            "env (GHA-005).\n"
            "  3. The next time the workflow runs, the now-malicious "
            "action reads `$AWS_ACCESS_KEY_ID` / `$AWS_SECRET_ACCESS_KEY` "
            "from the environment and POSTs them to an attacker host. "
            "The credentials remain valid until manually revoked."
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
            triggering_check_ids=["GHA-001", "GHA-005"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
