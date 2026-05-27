"""AC-032. Cosign-verified-but-not-bound artifact reaches production deploy.

Two legs:

  * ``GHA-100`` — ``cosign verify`` without ``--certificate-identity``
    and ``--certificate-oidc-issuer``. The verification step accepts
    any valid Sigstore signature, not just the expected build pipeline's.
  * ``GHA-014`` or ``GHA-098`` — the workflow deploys to a named
    environment without a security-scan gate (GHA-098) or without an
    environment binding at all (GHA-014 carries environment posture).

Independently: GHA-100 is a verification gap; GHA-098 is a deployment
gate gap. Together: an attacker who replaces the artifact on the CDN
or registry can mint their own valid Sigstore signature, the
verification passes, and the unguarded deploy pushes attacker code to
production.

Reachability model: per-workflow co-occurrence. Both legs fire on the
same workflow file, so ``group_by_resource`` is the right grouping.
The verify step typically precedes the deploy step in the same job or
a ``needs:`` chain. Shared-job intersection is a future refinement.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-032",
    title="Cosign-verified-but-not-bound artifact to production deploy",
    severity=Severity.CRITICAL,
    summary=(
        "A ``cosign verify`` invocation lacks certificate identity "
        "binding (GHA-100) AND the same workflow deploys without a "
        "security-scan gate (GHA-098) or environment protection "
        "(GHA-014). An attacker who replaces the artifact can mint "
        "their own valid Sigstore signature, pass the unbound "
        "verification, and reach production through the unguarded "
        "deploy step."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1036.005",  # Match Legitimate Name or Location
    ),
    kill_chain_phase=(
        "initial-access (artifact replacement) -> defense-evasion "
        "(unbound cosign verify passes) -> impact (production deploy)"
    ),
    references=(
        "https://docs.sigstore.dev/cosign/verifying/verify/",
        "https://blog.sigstore.dev/cosign-2-0-released/",
    ),
    recommendation=(
        "Break either leg:\n"
        "  1. Bind the ``cosign verify`` identity (GHA-100): add "
        "``--certificate-identity(-regexp)`` AND "
        "``--certificate-oidc-issuer(-regexp)`` pinned to the expected "
        "build workflow.\n"
        "  2. Gate the deploy step (GHA-098): require a security scan "
        "or manual approval environment before the deploy job runs.\n"
        "Both fixes together give defense-in-depth: even if a future "
        "signing key compromise occurs, the deploy gate catches "
        "unsigned or unexpected artifacts."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-100", "GHA-098"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-100", "GHA-098"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        verify = ck_map["GHA-100"]
        deploy = ck_map["GHA-098"]
        triggers = [verify, deploy]
        narrative = (
            f"On workflow `{resource}`:\n"
            f"  1. A ``cosign verify`` invocation lacks certificate "
            f"identity binding (GHA-100). Any valid Sigstore "
            f"signature satisfies the check, not just the expected "
            f"build pipeline's.\n"
            f"  2. The workflow deploys without a security-scan gate "
            f"(GHA-098). No intermediate check prevents a tampered "
            f"artifact from reaching production.\n"
            f"  3. Composite: an attacker replaces the artifact on "
            f"the CDN or registry, mints their own valid Sigstore "
            f"signature from their own workflow, the unbound "
            f"verification passes, and the deploy step pushes "
            f"attacker code to production."
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
            triggering_check_ids=["GHA-100", "GHA-098"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
