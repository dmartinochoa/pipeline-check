"""XPC-004. Token persistence on an unprotected default branch.

Cross-provider chain composing an SCM-side governance failure with
a workflow-side credential-handling failure. Fires when a single
multi-provider scan run carries failures in both:

  * ``SCM-001`` — the repo's default branch has no protection rule
    (anyone with write access can push directly), or
    ``SCM-007`` — protection rule allows force-pushes; and
  * ``GHA-019`` — a workflow writes ``GITHUB_TOKEN`` (or another
    secret) into persistent storage at runtime — log file, artifact,
    cache, ``$GITHUB_OUTPUT``, env-export survival.

Independently each rule is bad. Together they say: a credential
that surfaces in build artifacts (or logs, or cache) lives on a
branch that anyone with write access can land code into without
review. The attacker primitive collapses from "compromise the
build box" to "open a PR, get the build artifact via the public
artifact-download endpoint." The composite severity is therefore
higher than either singleton's.

This chain currently activates when scanning ``--pipelines
github,scm`` together; single-provider runs of either alone won't
have both legs in the chain engine's input.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-004",
    title="Token persistence on an unprotected default branch",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow persists a CI token or secret into build "
        "artifacts (or logs, cache, ``$GITHUB_OUTPUT``) on a repo "
        "whose default branch is either unprotected (no protection "
        "rule) or allows force-pushes. The combination collapses the "
        "attack primitive from 'compromise the build runtime' to "
        "'open a PR that lands a malicious change on main, then "
        "fetch the next build's artifacts.' Either leg alone is "
        "fixable in isolation; together, the secret is reachable to "
        "anyone with write access to the repo."
    ),
    mitre_attack=(
        "T1552.001",  # Unsecured Credentials: Credentials In Files
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1195.002",  # Compromise Software Supply Chain
    ),
    kill_chain_phase=(
        "credential-access -> persistence (write to default branch -> "
        "harvest from artifact)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-1",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-6",
    ),
    recommendation=(
        "Two fixes, either alone breaks the chain:\n"
        "  1. Add a branch protection rule on the default branch "
        "with required pull-request reviews and force-push denial "
        "(SCM-001 + SCM-007). This forces any change to go through "
        "review before it can run with full CI permissions.\n"
        "  2. Stop persisting tokens to build artifacts (GHA-019). "
        "Use OIDC federation with short-lived credentials, mask "
        "secret values in logs, and audit any ``::set-output::`` / "
        "``$GITHUB_OUTPUT`` write that includes ``${{ secrets.* }}`` "
        "or ``${{ github.token }}``.\n"
        "Best to fix both — branch protection is the durable "
        "control even when a future workflow change reintroduces "
        "credential persistence."
    ),
    providers=("github", "scm"),
    triggering_check_ids=("SCM-001", "SCM-007", "GHA-019"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one SCM governance leg AND one workflow
    token-persistence finding fail in the same run.

    The SCM leg is satisfied by either SCM-001 (no protection rule)
    or SCM-007 (rule exists but force-pushes allowed). Either is a
    "anyone with write access can land arbitrary code on the default
    branch" signal; the chain doesn't care which one fires.

    One composite per ``(scm_finding, gha_finding)`` cross-product so
    a scan covering multiple SCM repos or multiple offending
    workflows produces one entry per pair the operator can audit.
    """
    scm_legs = failing(findings, "SCM-001") + failing(findings, "SCM-007")
    gha_legs = failing(findings, "GHA-019")
    if not scm_legs or not gha_legs:
        return []

    out: list[Chain] = []
    for scm_finding in scm_legs:
        for gha_finding in gha_legs:
            triggers = [scm_finding, gha_finding]
            scm_phrase = (
                "has no branch protection rule"
                if scm_finding.check_id == "SCM-001"
                else "allows force-pushes on the protected branch"
            )
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. SCM repo `{scm_finding.resource}` "
                f"{scm_phrase} ({scm_finding.check_id}). Anyone with "
                f"write access can land code on the default branch "
                f"without review (or rewrite history after the fact "
                f"to hide the change).\n"
                f"  2. Workflow `{gha_finding.resource}` persists a "
                f"CI token or secret into build output (GHA-019) — "
                f"a log file, an artifact, ``$GITHUB_OUTPUT``, an "
                f"env export that survives the step. The persisted "
                f"value is reachable to anyone who can run a build "
                f"on the same workflow.\n"
                f"  3. Composite: an attacker with PR-author or "
                f"contributor access doesn't need to compromise the "
                f"build runtime to harvest the credential. They open "
                f"a PR that lands a tweak on the default branch, "
                f"wait for the next CI run, then download the build "
                f"artifact (a public endpoint on public repos; a "
                f"low-privilege endpoint on private repos). The "
                f"persisted token comes back in the artifact bytes "
                f"and the attacker has the same scope the workflow "
                f"had."
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
                    scm_finding.check_id, gha_finding.check_id,
                ],
                triggering_findings=triggers,
                resources=[scm_finding.resource, gha_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
