"""XPC-005. End-to-end provenance gap (unsigned source -> unsigned artifact).

Cross-provider chain composing an SCM-side commit-signature gap with
a workflow-side artifact-signature gap. Fires when a single
multi-provider scan run carries failures in both:

  * ``SCM-006`` — the repo's default branch protection does not
    require signed commits; AND
  * ``GHA-006`` — the workflow doesn't sign release artifacts
    (cosign / sigstore / SLSA generator).

Independently each rule is a moderate signal. Together they say:
the entire delivery pipeline lacks a cryptographic chain of
custody. A consumer of the resulting artifact has no way to
verify *what* shipped (artifact unsigned) was built from *what*
(source unsigned). Tampering at either boundary — a maintainer-
account compromise that pushes unsigned commits, or a build-
runtime compromise that swaps the artifact bytes — propagates
through to consumers indistinguishable from a legitimate release.

This chain currently activates when scanning ``--pipelines
github,scm`` together; single-provider runs of either alone
won't have both legs in the chain engine's input.

Reachability-model carve-out: this chain does not migrate to the
``job_anchors`` intersection model. The SCM finding lives on the
repo's branch-protection signed-commits state, the GHA finding
lives on a workflow file path, the two halves don't share a CI
job. Per-scan co-occurrence is the reachability claim, the
delivery pipeline lacks a cryptographic chain of custody from
source to artifact when the same scan saw both gaps.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="XPC-005",
    title="End-to-end provenance gap: source unsigned, artifact unsigned",
    severity=Severity.HIGH,
    summary=(
        "The repo doesn't require signed commits AND the workflow "
        "doesn't sign release artifacts. There is no cryptographic "
        "chain of custody at either boundary: a tampered commit can "
        "land under any contributor's name, and a tampered artifact "
        "can ship from any compromised build runtime. Consumers "
        "downstream cannot verify what built from what — every "
        "release is trust-on-first-use."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1554",      # Compromise Client Software Binary
    ),
    kill_chain_phase=(
        "supply-chain (source tampering -> build tampering, no "
        "compensating control at either boundary)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-9",
        "https://slsa.dev/spec/v1.0/levels",
        "https://slsa.dev/spec/v1.0/requirements",
    ),
    recommendation=(
        "Two fixes; either alone narrows the chain, both close it:\n"
        "  1. Enable ``Require signed commits`` on the default "
        "branch protection rule (SCM-006). Configure GPG / SSH / "
        "S/MIME signing for every contributor so commits land with "
        "a verifiable identity.\n"
        "  2. Add a signing step to the release workflow (GHA-006). "
        "``slsa-framework/slsa-github-generator`` produces a "
        "verifiable SLSA L3 provenance attestation; "
        "``sigstore/cosign`` signs the artifact with a keyless "
        "Fulcio identity. Publish the signature alongside the "
        "artifact and document the verification command in the "
        "release notes.\n"
        "Best to fix both: a signed commit landing in an unsigned "
        "release still leaves the build-runtime tampering vector "
        "open, and a signed artifact built from unsigned commits "
        "still has provenance ambiguity at the source boundary."
    ),
    providers=("github", "scm"),
    triggering_check_ids=("SCM-006", "GHA-006"),
)


def match(findings: list[Finding]) -> list[Chain]:
    """Match when at least one SCM-006 AND one GHA-006 fail in the same run.

    Cross-provider chains can't use ``group_by_resource`` — the SCM
    finding lives on a ``github:owner/repo`` resource handle, the
    GHA finding lives on a workflow file path. We emit one
    composite per ``(scm_finding, gha_finding)`` pair so a scan
    covering multiple SCM repos or multiple offending workflows
    produces one composite per cross-product cell.
    """
    scm_legs = failing(findings, "SCM-006")
    gha_legs = failing(findings, "GHA-006")
    if not scm_legs or not gha_legs:
        return []

    out: list[Chain] = []
    for scm_finding in scm_legs:
        for gha_finding in gha_legs:
            triggers = [scm_finding, gha_finding]
            narrative = (
                f"Cross-provider chain:\n"
                f"  1. SCM repo `{scm_finding.resource}` does not "
                f"require signed commits on the default branch "
                f"(SCM-006). Anyone with write access can land "
                f"commits indistinguishable from a real maintainer's "
                f"work; a stolen access token leaves no signature "
                f"trail.\n"
                f"  2. Workflow `{gha_finding.resource}` does not "
                f"sign release artifacts (GHA-006). The bytes the "
                f"build runtime emits are accepted by consumers on "
                f"trust; a build-runtime compromise (or a tampered "
                f"input that the build silently consumed) can swap "
                f"the artifact bytes with no detectable difference.\n"
                f"  3. Composite: there is no cryptographic "
                f"chain of custody anywhere from commit to release. "
                f"Consumers can't verify what built from what; "
                f"incident response after a confirmed compromise "
                f"can't bound the blast radius because every prior "
                f"release is trust-on-first-use. SLSA Build L3 "
                f"specifically requires both signed commits and "
                f"signed provenance to close this gap."
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
                triggering_check_ids=["SCM-006", "GHA-006"],
                triggering_findings=triggers,
                resources=[scm_finding.resource, gha_finding.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    return out
