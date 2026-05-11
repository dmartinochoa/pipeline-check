"""ATTEST-004. SLSA provenance ships without a resolved-dependencies set.

ATTEST-001 verifies *who* built the image. ATTEST-002 verifies *from
what source*. ATTEST-004 verifies *what inputs the build consumed*.

The SLSA provenance carries two adjacent claims that operationally
function as one chain-of-custody record:

- v0.2 ``predicate.materials``  -- a list of ``{uri, digest}`` entries
  for every input the build read.
- v1   ``predicate.buildDefinition.resolvedDependencies``  -- the
  rename, same idea: every input pinned by digest.

A passing OCI-002 + ATTEST-001 + ATTEST-002 with an *empty* materials
list says: a trusted builder produced this image from a known source
repo, and the build claims it consumed *nothing*. That's defensible
only for the most trivial (`FROM scratch` + literal byte copies)
builds. For every realistic image it's a hole in the supply-chain
graph: a downstream consumer can't tell which base image, which
package manager state, or which transitive ref actually contributed
to the bytes.

The rule reads the canonical lists, accepts both spec versions, and
fires when the list is missing or empty. Per-material digest
validation (each entry has a ``digest`` map with at least one
algorithm) lands separately when the rule pack grows.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="ATTEST-004",
    title="SLSA provenance ships without a resolved-dependencies set",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-PROVENANCE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-1357", "CWE-1104"),
    recommendation=(
        "Configure the builder to emit a non-empty ``materials`` "
        "(SLSA v0.2) or ``resolvedDependencies`` (SLSA v1) list "
        "with one entry per ingredient the build consumed. For "
        "BuildKit, set ``--attest=type=provenance,mode=max`` so "
        "the resolved-base-image + checked-out source land in "
        "the attestation. For slsa-github-generator the L3 "
        "presets populate this automatically; teams running a "
        "custom generator must add the inputs explicitly. An "
        "empty list is structurally indistinguishable from 'the "
        "build had no inputs' and breaks downstream "
        "vulnerability correlation."
    ),
    docs_note=(
        "Walks every SLSA provenance attestation on the image "
        "index and reads the materials list at the spec-version-"
        "appropriate path. Both v0.2 and v1 are accepted. A "
        "missing key, a non-list value, and an empty list all "
        "fail (each shape means the consumer gets no input "
        "chain-of-custody). Per-material content validation "
        "(digest map populated, URI well-formed) is deferred "
        "to a future rule, this one establishes that the list "
        "exists.\n\n"
        "Pairs with ATTEST-003: ATTEST-003 verifies the SBOM "
        "covers package-level inputs, ATTEST-004 verifies the "
        "build-level inputs. Both are needed for the SLSA "
        "Build-track L3 'isolated, reproducible' claim; SBOM-"
        "only coverage misses the resolved base image and the "
        "build-tool chain."
    ),
    known_fp=(
        "Trivial ``FROM scratch`` images with no build-time "
        "dependencies legitimately have an empty materials "
        "list. The rule has no way to distinguish 'trivial "
        "build' from 'instrumentation gap', the SLSA spec "
        "treats both as the same fail-closed signal. Suppress "
        "per-image via ``--ignore-file`` once you've verified "
        "the build genuinely has nothing to attest.",
        "Some builders (older BuildKit, hand-rolled generators) "
        "populate ``materials`` but omit the ``digest`` map, "
        "which the SLSA spec marks recommended-not-required. "
        "This rule accepts that shape today (list non-empty = "
        "pass); a future ATTEST-NNN will tighten to require "
        "digest coverage.",
    ),
    incident_refs=(
        "[SLSA v1 spec, Build track L3 requirements]"
        "(https://slsa.dev/spec/v1.0/levels#build-l3): resolved "
        "dependencies are a Build-track requirement, not an "
        "optional courtesy. The provenance was supposed to "
        "answer 'what went into this artifact'; an empty "
        "resolvedDependencies list answers 'we declined to "
        "say', which is materially worse than 'we didn't "
        "produce an attestation' because consumers see a "
        "signed-and-stamped document and trust it.",
        "tj-actions/changed-files compromise (CVE-2025-30066, "
        "March 2025): forensic teams reconstructing the blast "
        "radius needed to know which downstream images consumed "
        "the compromised action's outputs. Builds whose "
        "provenance carried materials lists pinpointed the "
        "exposure in minutes; builds without paid for the gap "
        "in days of manual review.",
    ),
    exploit_example=(
        "# Vulnerable: BuildKit provenance attestation generated\n"
        "# with the default --attest=type=provenance (mode=min),\n"
        "# which records the builder identity but omits the\n"
        "# resolved base image and source materials.\n"
        "$ docker buildx build \\\n"
        "    --attest=type=provenance \\\n"
        "    --tag registry.example/app:v1.4.2 \\\n"
        "    --push .\n"
        "\n"
        "# Resulting provenance (SLSA v0.2 predicate):\n"
        "#   {\n"
        "#     \"builder\": {\"id\": \"https://github.com/docker/buildx@v0.13\"},\n"
        "#     \"buildType\": \"https://example.com/buildtype/v1\",\n"
        "#     \"invocation\": { ... configSource present ... },\n"
        "#     \"materials\": []          <-- empty\n"
        "#   }\n"
        "\n"
        "# Attack surface: a downstream CVE advisory for the\n"
        "# resolved base image (say, ubuntu:22.04 -> a specific\n"
        "# digest known to ship the vulnerable libcurl) can't be\n"
        "# correlated to this image because the provenance never\n"
        "# recorded which base image was resolved at build time.\n"
        "# Forensic response shifts from \"grep provenance for\n"
        "# affected digest\" to \"rebuild every image and inspect\n"
        "# layer contents.\"\n"
        "\n"
        "# Safe: use --attest=type=provenance,mode=max so the\n"
        "# builder records the resolved base image and every\n"
        "# source ref the build pulled.\n"
        "$ docker buildx build \\\n"
        "    --attest=type=provenance,mode=max \\\n"
        "    --tag registry.example/app:v1.4.2 \\\n"
        "    --push .\n"
        "\n"
        "# Resulting provenance:\n"
        "#   \"materials\": [\n"
        "#     {\"uri\": \"pkg:docker/ubuntu@22.04\",\n"
        "#      \"digest\": {\"sha256\": \"<resolved digest>\"}},\n"
        "#     {\"uri\": \"git+https://github.com/foo/bar@v1.4.2\",\n"
        "#      \"digest\": {\"sha1\": \"<commit sha>\"}}\n"
        "#   ]"
    ),
)


def _materials(predicate: dict[str, Any]) -> tuple[str, Any]:
    """Return the spec-version label + raw materials value for *predicate*.

    SLSA v1 prefers ``buildDefinition.resolvedDependencies``;
    v0.2 uses ``materials``. Some transitional attestations carry
    both, prefer the v1 key when present so the rule consistently
    reads the canonical source for the predicate version.

    Returns ``(label, value)``; ``value`` is whatever the
    predicate stored (often a list, possibly missing, possibly
    something malformed). Caller validates shape.
    """
    build_def = predicate.get("buildDefinition")
    if isinstance(build_def, dict) and "resolvedDependencies" in build_def:
        return "resolvedDependencies", build_def.get("resolvedDependencies")
    return "materials", predicate.get("materials")


def _is_populated(value: Any) -> bool:
    """True iff *value* is a non-empty list (canonical SLSA shape).

    A missing key returns ``None`` from ``predicate.get``; a
    malformed scalar (string, int) is not a list. Both treated as
    empty so the rule fails closed.
    """
    return isinstance(value, list) and len(value) > 0


def check(manifest: OCIManifest) -> Finding:
    # Single-image manifests can't carry attestations; defer to
    # OCI-002 for "no provenance at all" findings.
    if not manifest.is_index:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Single-image manifest carries no attestations; "
                "materials verification not applicable."
            ),
            recommendation="No action required.", passed=True,
        )

    slsa_attestations = [
        a for a in manifest.attestations if a.is_slsa_provenance
    ]
    if not slsa_attestations:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No SLSA provenance attestation content available "
                "to verify materials / resolvedDependencies. Pass "
                "an OCI image-layout directory with a sibling "
                "``blobs/`` tree to enable content checks; OCI-002 "
                "covers the missing-attestation case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    offenders: list[str] = []
    for att in slsa_attestations:
        label, value = _materials(att.predicate)
        if _is_populated(value):
            continue
        # Reported per attestation so the operator sees how many
        # platform variants are affected (a multi-arch image has
        # one provenance per platform).
        offenders.append(f"{att.predicate_type}: {label} empty/missing")

    if not offenders:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"All {len(slsa_attestations)} SLSA provenance "
                f"attestation(s) declare a non-empty materials / "
                f"resolvedDependencies list."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    desc = (
        f"{len(offenders)} of {len(slsa_attestations)} SLSA "
        f"provenance attestation(s) ship without a resolved-"
        f"dependencies / materials list: "
        f"{'; '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. Downstream "
        f"consumers can't correlate base-image or source-input "
        f"advisories against this image."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
