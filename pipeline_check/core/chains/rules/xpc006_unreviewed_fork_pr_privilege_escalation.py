"""XPC-006. Unreviewed fork-PR privilege escalation
(no-required-reviews + pull_request_target checks out PR head).

Cross-provider chain composing an SCM-side review-gate failure with
a workflow-side privileged-fork-PR primitive. Fires when a single
multi-provider scan run carries failures in both:

  * ``SCM-002`` — the default branch protection rule does not
    require approving pull-request reviews; AND
  * ``GHA-002`` — a workflow uses ``pull_request_target`` and
    explicitly checks out the PR head (the canonical "pwn request"
    pattern that runs untrusted fork-PR code with the caller
    repo's secrets and a write-scope ``GITHUB_TOKEN``).

Independently:
  * GHA-002 is already CRITICAL on its own — every fork PR can
    trigger privileged execution of attacker-controlled code in
    the base repo's context.
  * SCM-002 means a single insider (collaborator, member, admin
    with a compromised account) can land a change with no
    second-pair-of-eyes review.

The composite says: there is no human-review gate to either
*introduce* GHA-002 (a maintainer with one compromised account can
add the ``pull_request_target`` workflow change and merge it
solo) or *fix* GHA-002 (the same gate-skip lets the malicious
workflow stay even after detection). The vulnerability becomes a
single-identity decision rather than a cross-team consensus, and
the fork-PR exploitation primitive stays open for every external
contributor for as long as the workflow lives.

This chain currently activates when scanning ``--pipelines
github,scm`` together; single-provider runs of either alone won't
have both legs in the chain engine's input.

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The SCM finding lives on the
repo's branch-protection review-requirement state, the GHA finding
lives on a workflow file path, the two halves don't share a CI
job. Per-scan co-occurrence is the reachability claim, the
combination means a fork PR can land code execution on a workflow
that holds the caller-repo's secrets without a human review gate.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-006",
    title="Unreviewed fork-PR privilege escalation",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow uses ``pull_request_target`` and checks out the "
        "PR head (CRITICAL fork-PR privilege escalation primitive) "
        "AND the default branch's protection rule does not require "
        "approving reviews. A single insider can introduce or keep "
        "the vulnerability alive solo — there is no review gate "
        "between a compromised maintainer account and a "
        "fork-PR-exploitable workflow on the default branch."
    ),
    mitre_attack=(
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1199",      # Trusted Relationship
        "T1195.002",  # Compromise Software Supply Chain
        "T1078.003",  # Valid Accounts: Local Accounts
    ),
    kill_chain_phase=(
        "initial-access -> execution (single-identity introduction "
        "of the pwn-request primitive; ongoing fork-PR exploitation)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-1",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-4",
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
    ),
    recommendation=(
        "Two fixes; either alone narrows the chain, both close it:\n"
        "  1. Replace ``pull_request_target`` with ``pull_request`` "
        "for any workflow that runs fork-PR code, OR split the "
        "workflow so the privileged half (write-scope token, "
        "secrets) does NOT check out the PR head and the build "
        "half runs in the unprivileged ``pull_request`` context "
        "(GHA-002).\n"
        "  2. Set ``required_approving_review_count >= 1`` in the "
        "default branch protection rule so a second identity must "
        "acknowledge any change to the workflow file before it "
        "merges (SCM-002). Pair with ``require_last_push_approval`` "
        "(SCM-014) so a force-push after approval doesn't smuggle "
        "the malicious diff back in.\n"
        "Best to fix both: GHA-002 is the active exploit primitive "
        "(every fork PR is a trigger), SCM-002 is the durable "
        "control that prevents reintroduction. Without the second, "
        "a future commit can reopen the door silently."
    ),
    providers=("github", "scm"),
    triggering_check_ids=("SCM-002", "GHA-002"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one SCM-002 AND one GHA-002 fail in the same run.

    One composite per ``(scm_finding, gha_finding)`` pair so a scan
    covering multiple repos or multiple offending workflows
    produces one entry per cross-product cell.
    """
    scm_legs = failing(findings, "SCM-002")
    gha_legs = failing(findings, "GHA-002")
    if not scm_legs or not gha_legs:
        return []

    out: list[Chain] = []
    for scm_finding in scm_legs:
        for gha_finding in gha_legs:
            triggers = [scm_finding, gha_finding]
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. Workflow `{gha_finding.resource}` uses "
                f"``pull_request_target`` and explicitly checks out "
                f"the PR head (GHA-002). Every fork PR triggers a "
                f"privileged run with the base repo's secrets and a "
                f"write-scope ``GITHUB_TOKEN`` in scope, executing "
                f"attacker-controlled code from the PR.\n"
                f"  2. SCM repo `{scm_finding.resource}` does not "
                f"require approving pull-request reviews on the "
                f"default branch (SCM-002). A single insider — a "
                f"collaborator with a compromised PAT, a member of a "
                f"team with write access, an admin — can land "
                f"changes to that workflow file with no second "
                f"identity's approval.\n"
                f"  3. Composite: there is no human-review gate "
                f"either to *introduce* the pwn-request primitive "
                f"(one compromised maintainer adds the "
                f"``pull_request_target`` trigger and the PR-head "
                f"checkout in a single PR they self-merge) or to "
                f"*remove* it after detection (the same gate-skip "
                f"lets the malicious workflow stay). The fork-PR "
                f"exploitation surface stays open for every external "
                f"contributor for as long as the workflow lives, "
                f"and the team has no procedural backstop to catch "
                f"the change."
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
                triggering_check_ids=["SCM-002", "GHA-002"],
                triggering_findings=triggers,
                resources=[scm_finding.resource, gha_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
