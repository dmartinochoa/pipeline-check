"""AC-028. npm worm propagation primitive co-located (Shai-Hulud class).

A repo simultaneously ships an npm package whose ``package.json``
declares install-time lifecycle scripts (NPM-004) AND a GitHub
Actions workflow that either authors a sibling workflow file
(GHA-048) or pushes commits to a parameterized external repo
(GHA-049). Either half alone is a smell; together they're the
exact topology the Shai-Hulud npm worm needed to propagate:

  * Consumers ``npm install`` the package; the postinstall runs with
    each consumer's credentials.
  * The workflow leg in the same repo is the worm's reference
    implementation of how to propagate further once the postinstall
    has stolen a token.

Detection of the combination is materially stronger than either
finding alone: an isolated postinstall is hygiene debt; an isolated
self-mutating workflow is hygiene debt; the *combination* is the
fingerprint of code designed to spread.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, has_failing, min_confidence

RULE = ChainRule(
    id="AC-028",
    title="npm worm propagation primitive co-located",
    severity=Severity.CRITICAL,
    summary=(
        "A repo carries both halves of the Shai-Hulud-class npm worm "
        "propagation primitive: a package.json with install-time "
        "lifecycle scripts (NPM-004) sits alongside a GitHub Actions "
        "workflow that authors sibling workflow files (GHA-048) or "
        "pushes to parameterized external repos (GHA-049). The "
        "combination is the topology the Shai-Hulud npm worm used to "
        "spread, postinstall harvests credentials from every "
        "consumer; the workflow leg writes the next stage of the worm "
        "into every repo the stolen token can reach."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1546",      # Event-Triggered Execution
    ),
    kill_chain_phase="initial-access -> execution -> lateral-movement",
    references=(
        "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack",
        "https://www.microsoft.com/en-us/security/blog/2025/12/09/"
        "shai-hulud-2-0-guidance-for-detecting-investigating-and-"
        "defending-against-the-supply-chain-attack/",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-03-Dependency-Chain-Abuse",
    ),
    recommendation=(
        "Break either leg: (a) move install-time logic out of "
        "``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` "
        "into a documented CLI subcommand consumers invoke "
        "deliberately, OR (b) remove the workflow's ability to author "
        "workflow YAML on the runner and to push to non-allow-listed "
        "external repos. With either leg severed the worm has no "
        "propagation primitive in this repo. Long-term: rotate every "
        "credential the repo's CI can reach if the GHA-048 / GHA-049 "
        "finding suggests the workflow has already executed once."
    ),
    providers=("github", "npm"),
    triggering_check_ids=("NPM-004", "GHA-048", "GHA-049"),
)


def match(findings: list[Finding]) -> list[Chain]:
    if not has_failing(findings, "NPM-004"):
        return []
    has_self_mut = has_failing(findings, "GHA-048")
    has_cross_push = has_failing(findings, "GHA-049")
    if not (has_self_mut or has_cross_push):
        return []
    workflow_ids = []
    if has_self_mut:
        workflow_ids.append("GHA-048")
    if has_cross_push:
        workflow_ids.append("GHA-049")
    triggers = [
        f for f in findings
        if (not f.passed)
        and f.check_id in {"NPM-004", *workflow_ids}
    ]
    resources = sorted({f.resource for f in triggers})
    narrative = (
        "In this repo:\n"
        "  1. A ``package.json`` declares one or more install-time "
        "lifecycle scripts (NPM-004). Every consumer that runs ``npm "
        "install`` executes this code with their own credentials in "
        "scope, the inbound primitive a worm needs to steal tokens "
        "from victims.\n"
        "  2. A workflow in the same repo "
        + (
            "writes a file under ``.github/workflows/`` (GHA-048). A "
            "workflow that authors a sibling workflow is the worm's "
            "next-stage drop primitive.\n"
            if has_self_mut else ""
        )
        + (
            "pushes commits or creates repos against a parameterized "
            "external target (GHA-049). Cross-repo writes are the "
            "lateral-movement primitive that lets a worm leave the "
            "first infected runner.\n"
            if has_cross_push else ""
        )
        + "  3. The two halves co-located in one repo is the "
        "Shai-Hulud topology: postinstall steals the consumer's "
        "GITHUB_TOKEN / NPM_TOKEN, the workflow leg seeds the worm "
        "into every repo the stolen token can reach."
    )
    return [Chain(
        chain_id=RULE.id,
        title=RULE.title,
        severity=RULE.severity,
        confidence=min_confidence(triggers),
        summary=RULE.summary,
        narrative=narrative,
        mitre_attack=list(RULE.mitre_attack),
        kill_chain_phase=RULE.kill_chain_phase,
        triggering_check_ids=["NPM-004", *workflow_ids],
        triggering_findings=triggers,
        resources=resources,
        references=list(RULE.references),
        recommendation=RULE.recommendation,
    )]
