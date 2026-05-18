"""AC-004. Self-Hosted Runner Persistent Foothold.

A non-ephemeral self-hosted runner that processes fork PRs (or any
untrusted trigger) becomes a persistent foothold: malicious code can
plant a daemon that waits for the next privileged job.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
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
        "first-party events only, `pull_request` from forks must "
        "land on GitHub-hosted runners exclusively."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-002", "GHA-012"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability: a shared job between GHA-002 (PR-head checkout)
    # and GHA-012 (self-hosted, non-ephemeral runner) confirms the
    # foothold primitive — the malicious PR-head code runs on the
    # same runner instance that will later host a privileged job.
    # Disjoint jobs are still suspicious because the runner pool may
    # be shared across jobs, but no direct same-runner claim holds.
    grouped = group_by_resource(findings, ["GHA-002", "GHA-012"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha002 = ck_map["GHA-002"]
        gha012 = ck_map["GHA-012"]
        triggers = [gha002, gha012]

        prhead_jobs = set(gha002.job_anchors)
        runner_jobs = set(gha012.job_anchors)
        shared = sorted(prhead_jobs & runner_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"PR-head checkout and non-ephemeral runner share job "
                f"{shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the same job(s) "
                f"({shared_repr}) both check out PR-head code AND "
                f"run on a self-hosted, non-ephemeral runner. The "
                f"attacker's payload runs on a runner instance "
                f"that survives the job."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: PR-head checkout "
                "and non-ephemeral runner fire in different jobs. "
                "The foothold attack still works when jobs share a "
                "runner pool; treat as a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. Workflow accepts `pull_request_target` and checks "
            "out PR-head code (GHA-002), fork PRs reach the runner.\n"
            "  2. The runner is self-hosted without ephemeral lifecycle "
            "(GHA-012), the host survives between jobs.\n"
            "  3. Attacker opens fork PR with code that writes a cron "
            "or systemd unit. The next job on that runner, a privileged "
            "deploy from a maintainer's branch, runs in an environment "
            "the attacker still owns.\n"
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
            triggering_check_ids=["GHA-002", "GHA-012"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
