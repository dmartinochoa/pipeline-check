"""ATTEST-001. SLSA provenance attests an untrusted builder identity."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="ATTEST-001",
    title="SLSA provenance attests an untrusted builder identity",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2", "CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-PROVENANCE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-345", "CWE-1357"),
    recommendation=(
        "Re-run the build on a recognized hosted CI builder (GitHub-"
        "hosted runners, slsa-github-generator, Cloud Build, GitLab "
        "SaaS, Buildkite, or BuildKit attesting via Docker Hub) so "
        "the SLSA ``builder.id`` claim resolves to an isolated, "
        "publicly-auditable build environment. Self-hosted runners "
        "and unknown builder identities defeat the SLSA L2+ "
        "isolation guarantee, the supply-chain trust chain only "
        "extends as far as the *builder* the attestation names."
    ),
    docs_note=(
        "Reads the SLSA provenance from each in-toto Statement "
        "carried in the image's attestation manifests, then checks "
        "``predicate.builder.id`` (SLSA v0.2) / "
        "``predicate.runDetails.builder.id`` (SLSA v1) against an "
        "allowlist of URI prefixes for hosted CI builders. Fires "
        "when the attested builder is unknown or matches a "
        "self-hosted-runner shape.\n\n"
        "Triggering this rule means the bytes of the runtime image "
        "were produced by a builder identity the SLSA contract "
        "cannot vouch for. A compromised self-hosted runner can "
        "produce a perfectly-formed, signature-valid attestation "
        "for a tampered image, so a passing OCI-002 (attestation "
        "present) is not the same thing as a trustworthy "
        "attestation, this rule is the difference."
    ),
    known_fp=(
        "Some teams run their own SLSA-conformant builders for "
        "policy reasons (air-gapped builds, regulated workloads, "
        "FedRAMP environments). Add the builder's URI prefix to a "
        "future allowlist override (deferred to v2) or suppress "
        "via ignore-file when the team has a documented review of "
        "the builder's isolation posture.",
        "Older BuildKit versions emitted a generic placeholder "
        "(``https://github.com/docker/buildx@v0.X``) without "
        "tying the identity to the runner. Modern Buildx writes a "
        "concrete builder URI; if the scan flags a placeholder, "
        "upgrade Buildx and rebuild before treating it as a real "
        "incident.",
    ),
    incident_refs=(
        "[SLSA threat-model v1.0](https://slsa.dev/spec/v1.0/threats): "
        "untrusted builder is the canonical Build-track Threat #2 "
        "('Build the package from a modified source'). A tampered "
        "self-hosted runner can emit a syntactically-valid "
        "attestation for the wrong source.",
        "[GitHub docs on self-hosted runner security]"
        "(https://docs.github.com/en/actions/hosting-your-own-runners/"
        "managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security): "
        "non-ephemeral self-hosted runners default to persisted "
        "state between jobs; one compromised job gives the "
        "attacker arbitrary code execution that produces signed "
        "artifacts on every subsequent legitimate build on that "
        "runner. SLSA's isolation requirement (L2+) explicitly "
        "excludes this shape, which is why the rule treats "
        "``self-hosted`` URIs as untrusted regardless of the "
        "rest of the chain.",
    ),
    exploit_example=(
        "# Vulnerable: the SLSA provenance attestation names a\n"
        "# self-hosted builder whose isolation cannot be audited\n"
        "# publicly. The signed attestation only attests that *this*\n"
        "# builder produced the artifact; it doesn't guarantee the\n"
        "# build environment was hermetic. A compromised self-hosted\n"
        "# runner produces signed provenance for malicious bytes.\n"
        "{\n"
        "  \"_type\": \"https://in-toto.io/Statement/v0.1\",\n"
        "  \"predicateType\": \"https://slsa.dev/provenance/v0.2\",\n"
        "  \"predicate\": {\n"
        "    \"builder\": {\n"
        "      \"id\": \"https://internal-jenkins.example.com/jobs/build\"\n"
        "    },\n"
        "    \"buildType\": \"https://example.com/build-script@v1\"\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: rebuild via a recognized hosted CI builder that\n"
        "# enforces hermetic isolation (slsa-github-generator on a\n"
        "# GitHub-hosted runner, the canonical SLSA L3 producer).\n"
        "# Downstream verifiers can validate the builder URI against\n"
        "# a public allowlist and trust the isolation guarantee.\n"
        "{\n"
        "  \"_type\": \"https://in-toto.io/Statement/v0.1\",\n"
        "  \"predicateType\": \"https://slsa.dev/provenance/v0.2\",\n"
        "  \"predicate\": {\n"
        "    \"builder\": {\n"
        "      \"id\": \"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0\"\n"
        "    },\n"
        "    \"buildType\": \"https://github.com/slsa-framework/slsa-github-generator/container@v1\"\n"
        "  }\n"
        "}"
    ),
)


# URI prefixes for builders we recognize as SLSA-isolated. The match
# is a string-prefix check on ``builder.id``, so a builder whose URI
# starts with any of these strings passes. The list is intentionally
# narrow: a permissive allowlist would defeat the purpose.
#
# slsa-github-generator runs in a reusable workflow on hosted runners
# and is the SLSA L3 reference path. GitHub-hosted runners
# themselves emit the ``actions/runner`` family. Buildx attests as
# ``docker/buildx``; Cloud Build, GitLab SaaS, Buildkite, and CircleCI
# round out the public CI services that produce verifiable provenance.
_TRUSTED_BUILDER_PREFIXES: tuple[str, ...] = (
    "https://github.com/slsa-framework/slsa-github-generator/",
    "https://github.com/actions/runner/Linux",
    "https://github.com/actions/runner/macOS",
    "https://github.com/actions/runner/Windows",
    "https://github.com/actions/runner/github-hosted",
    "https://actions.github.com/",
    "https://github.com/Attestations/GitHubHostedActions",
    "https://github.com/docker/buildx@",
    "https://docs.docker.com/build/buildkit/",
    "https://cloudbuild.googleapis.com/",
    "https://gitlab.com/",
    "https://buildkite.com/",
    "https://circleci.com/",
)

# URI substrings that explicitly mark a self-hosted / less-trusted
# builder. Even a builder URI under a recognized domain falls back
# to UNTRUSTED when one of these tokens is present, so a
# ``github.com/actions/runner/self-hosted`` ref doesn't pass via the
# generic ``actions/runner/`` prefix.
_SELF_HOSTED_TOKENS: tuple[str, ...] = (
    "/self-hosted",
    "/self_hosted",
    "self-hosted-runner",
    "localhost",
    "127.0.0.1",
)


def _builder_id(predicate: dict[str, Any]) -> str | None:
    """Return the SLSA provenance ``builder.id`` URI, or ``None``.

    Handles both spec versions:
    - v0.2: ``predicate.builder.id``
    - v1.0: ``predicate.runDetails.builder.id`` (preferred) with
      a fallback to ``predicate.builder.id`` for transitional
      attestations that carry both shapes.
    """
    run_details = predicate.get("runDetails")
    if isinstance(run_details, dict):
        rd_builder = run_details.get("builder")
        if isinstance(rd_builder, dict):
            bid = rd_builder.get("id")
            if isinstance(bid, str) and bid:
                return bid
    builder = predicate.get("builder")
    if isinstance(builder, dict):
        bid = builder.get("id")
        if isinstance(bid, str) and bid:
            return bid
    return None


def _classify(builder_id: str) -> str:
    """Return ``'trusted'`` / ``'self-hosted'`` / ``'unknown'`` for *builder_id*."""
    for token in _SELF_HOSTED_TOKENS:
        if token in builder_id:
            return "self-hosted"
    for prefix in _TRUSTED_BUILDER_PREFIXES:
        if builder_id.startswith(prefix):
            return "trusted"
    return "unknown"


def check(manifest: OCIManifest) -> Finding:
    # Single-image manifests can't carry attestations at all; defer
    # to OCI-002 for that finding shape.
    if not manifest.is_index:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Single-image manifest carries no attestations; "
                "builder-identity verification not applicable."
            ),
            recommendation="No action required.", passed=True,
        )

    slsa_attestations = [
        a for a in manifest.attestations if a.is_slsa_provenance
    ]
    if not slsa_attestations:
        # Either no attestations were parsed (single ``index.json``
        # input without a sibling ``blobs/`` tree, or no attestation
        # entries in the index), or the attestations present aren't
        # SLSA provenance. Either way, this rule has nothing to
        # check; OCI-002 covers the missing-attestation case.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No SLSA provenance attestation content available "
                "to verify builder identity. This rule requires an "
                "OCI image-layout directory with a ``blobs/`` tree "
                "alongside ``index.json``; a bare ``index.json`` "
                "shows the attestation entries but not their "
                "content."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    untrusted: list[str] = []
    self_hosted: list[str] = []
    for att in slsa_attestations:
        bid = _builder_id(att.predicate)
        if bid is None:
            untrusted.append(
                f"<missing builder.id in {att.predicate_type}>"
            )
            continue
        verdict = _classify(bid)
        if verdict == "trusted":
            continue
        if verdict == "self-hosted":
            self_hosted.append(bid)
        else:
            untrusted.append(bid)

    if not untrusted and not self_hosted:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"All {len(slsa_attestations)} SLSA provenance "
                f"attestation(s) name a recognized hosted CI "
                f"builder."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    parts: list[str] = []
    if self_hosted:
        parts.append(
            f"{len(self_hosted)} self-hosted-runner builder(s): "
            f"{', '.join(sorted(set(self_hosted))[:3])}"
        )
    if untrusted:
        parts.append(
            f"{len(untrusted)} unknown builder(s): "
            f"{', '.join(sorted(set(untrusted))[:3])}"
        )
    desc = (
        "SLSA provenance attests builder identities outside the "
        "trusted-builder allowlist: " + "; ".join(parts) + ". "
        "A self-hosted or unknown builder defeats the SLSA L2+ "
        "isolation guarantee."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
