"""AC-038. Untrusted branch reaches OIDC trusted publish.

The reachable form of the npm "trusted publishing, untrusted branch"
attack (Red Hat npm compromise, BoostSecurity 2026). Intersects two
single-rule findings on the same job:

  * **GHA-114** — a package-publish workflow is reachable from an
    unrestricted ``push`` trigger (a wildcard ``branches:`` pattern or
    no branch filter), so anyone who can create a branch can run the
    publish path.
  * **GHA-113** — the publish job mints an OIDC token (``id-token:
    write``) with no protected ``environment:`` gate, so nothing pins
    which ref may mint the token.

When the *same job* satisfies both, the result is a publish token
mintable from any branch with no human or branch gate: a counterfeit
``ci.yml`` on a throwaway ``oidc-*`` branch mints the OIDC token, npm /
PyPI trusted publishing accepts it (it validates only org + repo +
workflow filename), and a malicious version ships as the trusted
maintainer with valid provenance recording the throwaway ref.

This is the OIDC trusted-publishing lane. AC-029 covers the
long-lived-token publish lane (a static ``NPM_TOKEN`` exposed to an
untrusted trigger) and explicitly cannot reach the tokenless trusted-
publishing path, where there is no secret to leak, only a ref gate
that was never set.

Reachability model: ``GHA-113`` and ``GHA-114`` both anchor the
publish job(s) via ``Finding.job_anchors``. The chain confirms an
executable path when those anchor sets intersect (one job is both the
ungated OIDC publisher and reachable from the unrestricted trigger);
co-occurrence on different jobs of the same workflow stays an
unconfirmed signal.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-038",
    title="Untrusted branch reaches OIDC trusted publish",
    severity=Severity.CRITICAL,
    summary=(
        "A package-publish job mints an OIDC token with no environment "
        "gate (GHA-113) AND the workflow is reachable from an "
        "unrestricted push trigger (GHA-114). The publish token mints "
        "from any branch with no human or branch gate, so a counterfeit "
        "workflow on a throwaway branch publishes a malicious version as "
        "the trusted maintainer (the Red Hat npm 'untrusted branch' "
        "compromise)."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1199",      # Trusted Relationship
        "T1606",      # Forge Web Credentials
    ),
    kill_chain_phase=(
        "initial-access (push a counterfeit publish workflow to a "
        "throwaway branch) -> credential-access (mint an OIDC token the "
        "registry accepts because it validates only org + repo + "
        "workflow filename) -> impact (publish a malicious package "
        "version as the trusted maintainer, no human or branch gate)"
    ),
    references=(
        "https://labs.boostsecurity.io/articles/"
        "trusted-publishing-untrusted-branch-red-hat-npm/",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-02-Inadequate-Identity-And-Access-Management",
    ),
    recommendation=(
        "Break either leg:\n"
        "  1. Gate the trigger (GHA-114): publish only from a tag "
        "(``on: push: tags:``), a ``release: published`` event, or "
        "``workflow_dispatch``, not a branch push to any ref.\n"
        "  2. Gate the token (GHA-113): bind the publish job to a "
        "protected ``environment:`` whose deployment-branch rule pins "
        "the release ref, so the OIDC token mints only from that ref.\n"
        "Best: do both, and keep ``id-token: write`` scoped to the "
        "publish job. Either gate alone stops a throwaway branch from "
        "minting a publish token."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-113", "GHA-114"),
)


def match(findings: list[Finding]) -> list[Chain]:
    out: list[Chain] = []
    grouped = group_by_resource(findings, ["GHA-113", "GHA-114"])
    for resource, ck_map in grouped.items():
        gha113 = ck_map["GHA-113"]
        gha114 = ck_map["GHA-114"]
        triggers: list[Finding] = [gha113, gha114]

        ungated_oidc_jobs = set(gha113.job_anchors)
        unrestricted_jobs = set(gha114.job_anchors)
        shared = sorted(ungated_oidc_jobs & unrestricted_jobs)
        confirmed = bool(shared)

        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"ungated OIDC publish and unrestricted trigger share "
                f"job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Co-located (unverified): job {shared_repr} both "
                f"mints the OIDC token with no environment gate AND is "
                f"reachable from the unrestricted trigger. One job is "
                f"the whole attack: a publish token mintable from any "
                f"branch with no gate."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the ungated OIDC publish "
                "and the unrestricted-trigger publish fire on the same "
                "workflow but on different jobs. Treat as a co-occurrence "
                "signal rather than a proven single-job path."
            )

        narrative = (
            f"On workflow `{resource}`:\n"
            f"  1. A package-publish job mints an OIDC token "
            f"(`id-token: write`) with no protected `environment:` "
            f"gate (GHA-113), so nothing pins which ref may mint it.\n"
            f"  2. The workflow is reachable from an unrestricted `push` "
            f"trigger (GHA-114): a wildcard branch pattern or no branch "
            f"filter, so any branch runs the publish path.\n"
            f"  3. Composite: a counterfeit copy of this workflow on a "
            f"throwaway branch mints the OIDC token, the registry "
            f"accepts it (it checks only org + repo + workflow "
            f"filename), and a malicious version publishes as the "
            f"trusted maintainer.\n"
            f"{reach_narrative}"
        )

        # Confirmed single-job reachability is the whole attack, promote
        # to HIGH even though each leg is MEDIUM confidence; the cross-
        # finding intersection is the evidence. Unconfirmed co-occurrence
        # stays at the weakest leg so it doesn't outrank a single finding.
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
            triggering_check_ids=["GHA-113", "GHA-114"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
