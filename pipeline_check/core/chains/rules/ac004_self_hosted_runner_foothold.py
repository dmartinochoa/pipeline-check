"""AC-004 — Self-Hosted Runner Persistent Foothold.

A non-ephemeral self-hosted runner that processes fork PRs (or any
untrusted trigger) becomes a persistent foothold: malicious code can
plant a daemon that waits for the next privileged job.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-004",
    title="Self-Hosted Runner Persistent Foothold",
    severity=Severity.CRITICAL,
    summary=(
        "A self-hosted runner is configured non-ephemerally AND the "
        "same workflow accepts a fork-trigger that can run untrusted "
        "code. The runner OS persists between jobs, so malicious code "
        "from a fork PR can plant a long-lived backdoor that "
        "intercepts the next privileged build."
    ),
    mitre_attack=(
        "T1543",      # Create or Modify System Process
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1554",      # Compromise Host Software Binary
    ),
    kill_chain_phase="initial-access -> persistence -> privilege-escalation",
    references=(
        "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
        "https://www.praetorian.com/blog/self-hosted-github-runners-are-backdoors/",
    ),
    recommendation=(
        "Use ephemeral runners (one job, then destroy the host). If "
        "ephemeral isn't possible, restrict the workflow trigger to "
        "first-party events only — `pull_request` from forks must "
        "land on GitHub-hosted runners exclusively."
    ),
    providers=("github",),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-002", "GHA-012"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-002"], ck_map["GHA-012"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. Workflow accepts `pull_request_target` and checks "
            "out PR-head code (GHA-002) — fork PRs reach the runner.\n"
            "  2. The runner is self-hosted without ephemeral lifecycle "
            "(GHA-012) — the host survives between jobs.\n"
            "  3. Attacker opens fork PR with code that writes a cron "
            "or systemd unit. The next job on that runner — a privileged "
            "deploy from a maintainer's branch — runs in an environment "
            "the attacker still owns."
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
            triggering_check_ids=["GHA-002", "GHA-012"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
