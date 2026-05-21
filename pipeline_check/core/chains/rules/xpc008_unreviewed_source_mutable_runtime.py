"""XPC-008. Unreviewed source ships a mutable runtime image
(unprotected default branch + Dockerfile FROM not digest-pinned).

Cross-provider chain composing an SCM-side governance failure with
a Dockerfile-side runtime-immutability failure. Fires when a single
multi-provider scan run carries failures in both:

  * ``SCM-001`` — the repo's default branch has no protection rule;
    OR ``SCM-007`` — protection rule exists but allows force-pushes;
    AND
  * ``DF-001`` — the Dockerfile's ``FROM`` line references a
    floating tag (``FROM python:3.12``) rather than a digest
    (``FROM python:3.12@sha256:<hex>``).

Independently each leg names a real risk. Together they collapse
the attacker primitive: an insider with write access can land a
tampered Dockerfile change in a single self-merge with no review
gate, AND the runtime image the build produces inherits whatever
bytes the upstream registry currently serves under the named tag.
The next image build runs with the upstream's *current* base
image, which neither the team's reviewers nor the team's lockfile
have any visibility into.

This chain currently activates when scanning ``--pipelines
dockerfile,scm`` together; single-provider runs of either alone
won't have both legs in the chain engine's input.

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The SCM finding lives on the
repo's branch-protection state, the DF finding lives on a
Dockerfile path, the two halves don't share a CI job. Per-scan
co-occurrence is the reachability claim, an insider can land
tampered ``FROM`` changes through the unguarded review surface
AND the upstream registry's bytes drift freely under the floating
tag the Dockerfile names.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-008",
    title="Unreviewed source ships a mutable runtime image",
    severity=Severity.HIGH,
    summary=(
        "The repo's default branch is unprotected (or allows "
        "force-pushes) AND the Dockerfile pulls its base image "
        "by floating tag rather than digest. An insider can land "
        "a tampered ``FROM`` reference change in a single "
        "self-merge, AND every subsequent build inherits whatever "
        "bytes the upstream registry currently serves under the "
        "named tag. Neither the team's review process nor any "
        "lockfile has visibility into the runtime image's actual "
        "content."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1525",      # Implant Internal Image
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase=(
        "supply-chain (insider source change -> mutable upstream "
        "ingestion at build-time)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-1",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3",
    ),
    recommendation=(
        "Two fixes; either alone narrows the chain, both close it:\n"
        "  1. Add a branch protection rule on the default branch "
        "with required pull-request reviews and force-push denial "
        "(SCM-001 / SCM-007). This forces any change to the "
        "Dockerfile (and every other source file) to go through "
        "review before it can affect the build.\n"
        "  2. Pin the Dockerfile's ``FROM`` to a digest "
        "(``FROM python:3.12@sha256:<hex>``) (DF-001). The build "
        "then uses the exact bytes the digest names; an upstream "
        "tag rewrite has no effect until a maintainer deliberately "
        "updates the digest in the Dockerfile.\n"
        "Best to fix both: branch protection is the durable control "
        "preventing the insider-introduction half, and digest "
        "pinning is the durable control preventing the upstream-"
        "ingestion half. Either alone leaves the other open."
    ),
    providers=("dockerfile", "scm"),
    triggering_check_ids=("SCM-001", "SCM-007", "DF-001"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one SCM governance leg AND one DF-001
    finding fail in the same run.

    The SCM leg is satisfied by either SCM-001 (no protection rule)
    or SCM-007 (rule exists but force-pushes allowed) — both signal
    "anyone with write access can land arbitrary changes on the
    default branch." Same logic as XPC-004's SCM-leg matching.

    One composite per ``(scm_finding, df_finding)`` cross-product
    cell so a scan covering multiple SCM repos or multiple
    offending Dockerfiles produces one entry per pair the operator
    can audit.
    """
    scm_legs = failing(findings, "SCM-001") + failing(findings, "SCM-007")
    df_legs = failing(findings, "DF-001")
    if not scm_legs or not df_legs:
        return []

    out: list[Chain] = []
    for scm_finding in scm_legs:
        for df_finding in df_legs:
            triggers = [scm_finding, df_finding]
            scm_phrase = (
                "has no branch protection rule"
                if scm_finding.check_id == "SCM-001"
                else "allows force-pushes on the protected branch"
            )
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. SCM repo `{scm_finding.resource}` "
                f"{scm_phrase} ({scm_finding.check_id}). Anyone "
                f"with write access can land changes to the "
                f"Dockerfile (or any other source file) without "
                f"review (or rewrite history after the fact to "
                f"hide the change).\n"
                f"  2. Dockerfile `{df_finding.resource}` "
                f"references its base image by floating tag rather "
                f"than digest (DF-001). Every build pulls whatever "
                f"bytes the upstream registry currently serves "
                f"under that tag; neither the Dockerfile nor any "
                f"lockfile bounds what gets executed at build-time.\n"
                f"  3. Composite: an insider with write access can "
                f"flip the ``FROM`` line to a tampered base image "
                f"(or to a known-malicious upstream tag), self-"
                f"merge with no review gate, and every subsequent "
                f"build runs with the new bytes. Even without an "
                f"insider change, an upstream-account compromise "
                f"on the base image's repository propagates to the "
                f"team's next build automatically. The team has "
                f"two unrelated trust boundaries open at once and "
                f"no compensating control to break the chain at."
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
                triggering_check_ids=[
                    scm_finding.check_id, df_finding.check_id,
                ],
                triggering_findings=triggers,
                resources=[scm_finding.resource, df_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
