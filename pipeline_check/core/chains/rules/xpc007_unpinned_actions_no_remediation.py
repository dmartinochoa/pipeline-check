"""XPC-007. Upstream-compromise primitive without automated remediation
(unpinned actions + Dependabot security updates disabled).

Cross-provider chain composing a workflow-side supply-chain-ingestion
primitive with an SCM-side remediation gap. Fires when a single
multi-provider scan run carries failures in both:

  * ``GHA-001`` — workflow ``uses:`` references aren't pinned to
    40-char commit SHAs (``actions/checkout@v4``,
    ``tj-actions/changed-files@v45``); AND
  * ``SCM-005`` — Dependabot security updates are disabled on the
    repo, so new CVEs against in-use dependencies don't generate
    auto-PRs.

Independently:
  * GHA-001 is the upstream-compromise primitive. The
    tj-actions/changed-files compromise (CVE-2025-30066, March 2025)
    shipped CI-secret exfiltration to ~23,000 repos that pinned the
    action to ``@v45`` instead of a SHA — the upstream maintainer
    force-moved the tag to a malicious commit and every consumer
    auto-pulled it on the next workflow run.
  * SCM-005 is the absent-remediation primitive. Even after a CVE
    lands publicly, the team has to discover it and triage it
    manually; no Dependabot auto-PR opens with the minimum-
    required pin update.

The composite says: the repo has maximum exposure window from
upstream compromise to remediation. The action gets pulled
mutably (immediate exposure on the first malicious push), AND
when the public CVE lands, no automated workflow opens a PR to
move the team to a known-safe SHA. The team learns about the
compromise from a security advisory, an incident response
report, or — at worst — from their own logs after the
exfiltration completed.

This chain currently activates when scanning ``--pipelines
github,scm`` together; single-provider runs of either alone
won't have both legs in the chain engine's input.

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The GHA finding lives on a
workflow file path, the SCM finding lives on the repo's Dependabot
configuration state (queried via REST API), the two halves don't
share a CI job. Per-scan co-occurrence is the reachability claim,
ingestion is unpinned AND no automated remediation chases new
CVEs through PRs the team can review.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-007",
    title="Unpinned actions with no automated remediation",
    severity=Severity.HIGH,
    summary=(
        "Workflow ``uses:`` references aren't SHA-pinned (so an "
        "upstream maintainer compromise propagates to the next "
        "workflow run automatically) AND the repo has Dependabot "
        "security updates disabled (so the team has no automated "
        "alert + PR when the public CVE lands). The exposure window "
        "between upstream compromise and remediation is maximized."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1195.001",  # Compromise Software Dependencies and Development Tools
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase=(
        "supply-chain (mutable ingestion -> no automated detection / "
        "patch path; manual triage measured in days)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-3",
        "https://www.cve.org/CVERecord?id=CVE-2025-30066",
        "https://www.cve.org/CVERecord?id=CVE-2025-30154",
    ),
    recommendation=(
        "Two fixes; either alone narrows the chain, both close it:\n"
        "  1. Pin every ``uses:`` reference to a 40-char commit SHA "
        "(GHA-001). The Renovate / Dependabot ``version-update`` "
        "config keeps the pins fresh while preserving review of "
        "every move. Tag pins (``@v4``, ``@main``) accept silent "
        "upstream rewrites; SHA pins do not.\n"
        "  2. Enable Dependabot security updates on the repo "
        "(SCM-005). The bot opens a PR with the minimum-required "
        "upgrade against every open advisory on an in-use "
        "dependency, so a maintainer is paged within hours of the "
        "CVE landing instead of days when someone notices.\n"
        "Best to fix both: SHA pins remove the *immediate* "
        "exposure to upstream tag rewrites; Dependabot remediation "
        "closes the *post-disclosure* window during which a CVE "
        "is published but no fix is in flight. The tj-actions "
        "March 2025 compromise demonstrated both halves of the "
        "failure mode in the same incident."
    ),
    providers=("github", "scm"),
    triggering_check_ids=("SCM-005", "GHA-001"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one SCM-005 AND one GHA-001 fail in the same run.

    One composite per ``(scm_finding, gha_finding)`` pair so a scan
    covering multiple repos or multiple offending workflows
    produces one entry per cross-product cell.
    """
    scm_legs = failing(findings, "SCM-005")
    gha_legs = failing(findings, "GHA-001")
    if not scm_legs or not gha_legs:
        return []

    out: list[Chain] = []
    for scm_finding in scm_legs:
        for gha_finding in gha_legs:
            triggers = [scm_finding, gha_finding]
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. Workflow `{gha_finding.resource}` references "
                f"third-party actions by tag or branch rather than "
                f"by 40-char commit SHA (GHA-001). The bytes the "
                f"workflow runs are whatever the upstream maintainer "
                f"currently serves under that tag; a tag rewrite "
                f"propagates to the next workflow run with no "
                f"diff visible to this repo.\n"
                f"  2. SCM repo `{scm_finding.resource}` has "
                f"Dependabot security updates disabled (SCM-005). "
                f"When a CVE lands publicly against an in-use "
                f"dependency, no automated PR opens with the "
                f"minimum-required pin upgrade; the team has to "
                f"discover the advisory and triage it manually.\n"
                f"  3. Composite: the repo has the maximum "
                f"exposure window between upstream compromise and "
                f"remediation. The tj-actions/changed-files "
                f"compromise (CVE-2025-30066, March 2025) is the "
                f"canonical example: maintainer-account compromise "
                f"force-moved ``@v45`` to a malicious commit, "
                f"~23,000 tag-pinned repos auto-pulled the new "
                f"bytes, and Dependabot-disabled repos had no "
                f"in-flight PR to move them to a known-safe SHA "
                f"once the advisory dropped. Pinning closes the "
                f"first leg; Dependabot updates close the second."
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
                triggering_check_ids=["SCM-005", "GHA-001"],
                triggering_findings=triggers,
                resources=[scm_finding.resource, gha_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
