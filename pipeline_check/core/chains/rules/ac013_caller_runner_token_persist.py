"""AC-013. Caller-Controlled Runner with Token Persistence (GitHub Actions).

A workflow whose ``runs-on:`` is computed from an attacker-
controllable expression (GHA-036) AND that writes
``GITHUB_TOKEN`` to persistent storage (GHA-019) is a one-step
credential delivery to an attacker-chosen runner. The caller (or
PR sender, depending on trigger) picks the runner; the workflow
then writes its short-lived token to disk on that runner; the
attacker who controls the picked runner reads the token and
pivots into the repo with the workflow's permissions.

Distinct from:

  * AC-010, non-ephemeral self-hosted + curl-pipe / token-
    persistence. AC-010 attacks any caller of the workflow once
    persistence lands; AC-013 lets the *attacker* pick the runner
    directly without the persistence-on-shared-host step.
  * AC-001, fork-PR credential theft via ``pull_request_target``
    is a different initial-access shape; this chain doesn't
    require a fork PR, just any caller of the parameterized
    workflow.

The chain fires when both GHA-036 and GHA-019 fire on the *same*
workflow file. A different-workflow combo is not the same threat.
The runner-targeting decision and the token-persistence step have
to be in the same execution.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-013",
    title="Caller-Controlled Runner with Token Persistence",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow's ``runs-on:`` is computed from an attacker-"
        "controllable expression (GHA-036) AND a step in the same "
        "workflow writes ``GITHUB_TOKEN`` to persistent storage "
        "(GHA-019). The caller (or PR sender) picks which runner "
        "the workflow lands on; the workflow then drops its short-"
        "lived token onto that runner's filesystem; whoever owns "
        "the picked runner harvests the token and acts as the "
        "workflow inside the repo."
    ),
    mitre_attack=(
        "T1078",      # Valid Accounts
        "T1552.001",  # Unsecured Credentials: in Files
        "T1133",      # External Remote Services
    ),
    kill_chain_phase="initial-access -> credential-access -> exfiltration",
    references=(
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-7-Insecure-System-Configuration",
    ),
    recommendation=(
        "Break either leg of the chain. (a) Hard-code ``runs-on:`` "
        "or validate the input against an allowlist of known-good "
        "labels before the job runs, so the caller can't pick an "
        "attacker-controlled runner. (b) Stop writing "
        "``GITHUB_TOKEN`` to disk, use it inline via "
        "``${{ secrets.GITHUB_TOKEN }}`` in the step that needs it. "
        "Doing (a) closes the targeting leg; (b) limits blast "
        "radius even if (a) is somehow bypassed because the token "
        "no longer outlives the step that consumes it."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-036", "GHA-019"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Same-workflow pairing matters: GHA-036 in workflow A and
    # GHA-019 in workflow B are independent risks, not a chain.
    # Reachability: a shared job between GHA-036 (the caller picks
    # this job's runner) and GHA-019 (this job writes the token to
    # disk) confirms the single-job persistence delivery path.
    grouped = group_by_resource(findings, ["GHA-036", "GHA-019"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha036 = ck_map["GHA-036"]
        gha019 = ck_map["GHA-019"]
        triggers = [gha036, gha019]

        target_jobs = set(gha036.job_anchors)
        persist_jobs = set(gha019.job_anchors)
        shared = sorted(target_jobs & persist_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"caller-targeted runner and token persistence share "
                f"job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Co-located (unverified): the same job(s) "
                f"({shared_repr}) both let the caller pick the "
                f"runner AND write the token to disk on whatever "
                f"runner was picked."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: caller-targeted "
                "``runs-on:`` and token persistence land in "
                "different jobs. Treat as a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. A job's ``runs-on:`` is computed from an attacker-"
            "controllable expression (GHA-036), ``${{ inputs.* }}``, "
            "``${{ github.event.* }}``, ``${{ github.head_ref }}``, "
            "or another caller-supplied field. Whoever queues the "
            "workflow picks which runner it lands on, including "
            "any self-hosted label the org owns.\n"
            "  2. The same workflow writes ``GITHUB_TOKEN`` (or "
            "another secret) to persistent storage on the runner "
            "(GHA-019), typically ``> $GITHUB_ENV``, a redirected "
            "tee, or an output-file append. The token lives past "
            "the step boundary on that runner's filesystem.\n"
            "  3. An attacker who controls the picked runner reads "
            "the persisted token from disk and acts as the workflow "
            "for the rest of the token's lifetime, committing to "
            "branches, opening PRs, accessing protected secrets, "
            "all under the workflow's GITHUB_TOKEN scope.\n"
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
            triggering_check_ids=["GHA-036", "GHA-019"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
