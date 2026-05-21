"""XPC-010. npm cooldown miss meets Dockerfile lifecycle execution.

Cross-provider chain composing the package-manifest (npm) and
container-build (dockerfile) sides of a Shai-Hulud-class consumer
compromise. Fires when a single multi-provider scan run carries
failures in both:

  * ``NPM-008`` — a ``package.json`` pinned an exact dependency
    version that was published within the cooldown window
    (``--resolve-remote`` populates the publish-time metadata); AND
  * ``DF-024`` — the Dockerfile's ``npm`` / ``yarn`` / ``pnpm``
    install line runs lifecycle scripts (no ``--ignore-scripts``,
    no image-wide ``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` /
    ``YARN_ENABLE_SCRIPTS=false`` kill-switch).

Independently each leg is bounded. NPM-008 alone is a "you bumped
faster than the registry's takedown window" signal; the freshly
published version may still be benign. DF-024 alone is a "lifecycle
scripts are an execution primitive" signal; without a compromised
dep landing in the install set, the primitive does nothing.

Together the two halves are the consumer-side Shai-Hulud topology:
the next image build runs ``npm ci`` against a freshly published
version inside the takedown window, and that version's
``postinstall`` executes with the builder's ``NPM_TOKEN`` /
``GH_TOKEN`` / ``AWS_*`` in scope. Lockfile pinning does not break
the chain, the pinned version *is* the freshly published one; the
two breaks are ``--ignore-scripts`` (removes the execution
primitive) or holding back the bump (closes the time window).

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The two halves live in
different documents (``package.json`` + ``Dockerfile``), and the
threat is the per-scan co-occurrence — at build time, the
Dockerfile's ``COPY package.json ./`` then ``RUN npm ci`` line wires
the manifest's pinned spec to the image-wide install. Repo-level
co-occurrence is the reachability claim.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-010",
    title="npm cooldown miss meets Dockerfile lifecycle execution",
    severity=Severity.HIGH,
    summary=(
        "A ``package.json`` pinned a freshly published exact "
        "dependency version (NPM-008) AND the Dockerfile's install "
        "step runs lifecycle scripts (DF-024). The next image build "
        "executes the new release's ``postinstall`` with the "
        "builder's NPM_TOKEN / GH_TOKEN / AWS_* in scope, the "
        "consumer-side Shai-Hulud / TanStack blast radius. Either "
        "leg alone is hygiene debt; together they are the "
        "execution primitive lined up with a time window the "
        "registry has not yet had a chance to close."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1546",      # Event-Triggered Execution
    ),
    kill_chain_phase=(
        "supply-chain (fresh upstream release) -> execution "
        "(lifecycle script in build container)"
    ),
    references=(
        "https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-03-Dependency-Chain-Abuse",
    ),
    recommendation=(
        "Two fixes; either alone narrows the chain, both close it:\n"
        "  1. Hold back the bump, pin the dependency to the most "
        "recent release older than the cooldown window (NPM-008). "
        "``pipeline_check --pipeline npm --resolve-remote`` will "
        "surface the publish dates so the team can choose a safe "
        "anchor.\n"
        "  2. Disable lifecycle scripts in the Dockerfile install "
        "(DF-024). Pass ``--ignore-scripts`` on every ``npm`` / "
        "``yarn`` / ``pnpm install`` line, or set "
        "``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` / "
        "``ENV YARN_ENABLE_SCRIPTS=false`` before the install. "
        "Re-enable per package via a scoped ``RUN npm rebuild "
        "<pkg>`` line only when a native-module build genuinely "
        "needs it.\n"
        "Best to fix both, the cooldown gate is a default-safe "
        "policy applied at bump time, and ``--ignore-scripts`` is "
        "the durable execution-primitive control that protects "
        "every other dep too."
    ),
    providers=("npm", "dockerfile"),
    triggering_check_ids=("NPM-008", "DF-024"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one NPM-008 AND one DF-024 fail in the same run.

    One composite per ``(npm_finding, df_finding)`` cross-product
    cell so a scan covering multiple manifests or multiple
    Dockerfiles produces one entry per pair the operator can audit.
    The chain doesn't require the manifest and Dockerfile to live
    in the same directory, build pipelines that ``COPY ../pkg/
    package.json`` from a sibling workspace are common, and the
    runtime cost of a stray pair is one extra triage line rather
    than a false positive on a real exploit primitive.
    """
    npm_legs = failing(findings, "NPM-008")
    df_legs = failing(findings, "DF-024")
    if not npm_legs or not df_legs:
        return []

    out: list[Chain] = []
    for npm_finding in npm_legs:
        for df_finding in df_legs:
            triggers = [npm_finding, df_finding]
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. ``package.json`` `{npm_finding.resource}` "
                f"pinned a direct dependency to an exact version "
                f"published inside the cooldown window (NPM-008). "
                f"The registry has not yet had time to detect and "
                f"yank a publisher-account compromise on the new "
                f"release; consumers who bump now run with whatever "
                f"the registry currently serves.\n"
                f"  2. Dockerfile `{df_finding.resource}` runs an "
                f"``npm`` / ``yarn`` / ``pnpm`` install with "
                f"lifecycle scripts enabled (DF-024), no "
                f"``--ignore-scripts`` and no image-wide "
                f"``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` kill-"
                f"switch. Every ``postinstall`` in the dependency "
                f"tree executes with the build container's "
                f"environment in scope.\n"
                f"  3. Composite: at the next image build, "
                f"``npm ci`` (or equivalent) resolves the freshly "
                f"published version AND executes its lifecycle "
                f"scripts inside the builder. If the new release "
                f"is the consumer side of a Shai-Hulud / TanStack-"
                f"class compromise, NPM_TOKEN / GH_TOKEN / "
                f"AWS_* / GCP credentials in the builder are "
                f"harvestable, and a second-stage loader can be "
                f"baked into ``node_modules`` for every container "
                f"start. Lockfile pinning is no defense, the "
                f"pinned version *is* the poisoned one. Break "
                f"either leg to close the chain."
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
                    npm_finding.check_id, df_finding.check_id,
                ],
                triggering_findings=triggers,
                resources=[npm_finding.resource, df_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
