"""ATTEST-006. SLSA provenance lacks a meaningful ``buildType`` claim.

The ``buildType`` claim names the schema of the build process the
provenance describes. SLSA v0.2 puts it at ``predicate.buildType``;
v1 moved it to ``predicate.buildDefinition.buildType``. Either way,
the value is a URI that uniquely identifies *what kind of build*
produced the artifact (``https://slsa.dev/buildtypes/github-actions-
workflow/v1``, ``https://github.com/Attestations/GitHubHostedActions
@v1``, vendor-specific URIs for self-hosted generators, etc.).

Without a populated, non-placeholder ``buildType``, consumers
verifying the provenance can't validate the predicate's parameter
schema. The other fields (materials, configSource, builder) are all
declared *relative to* a particular build-type contract, so an
attestation that doesn't name its contract is structurally
under-specified: the verifier has to guess which fields are
authoritative and which are decorative.

Pairs with ATTEST-001 (who built it), ATTEST-002 (from what source),
ATTEST-004 (with which inputs), ATTEST-005 (bound to which bytes).
ATTEST-006 fills the "under what schema" slot in the same chain.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="ATTEST-006",
    title="SLSA provenance lacks a meaningful buildType",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-1357",),
    recommendation=(
        "Configure the builder to emit a concrete ``buildType`` URI "
        "naming the schema the provenance follows. For "
        "slsa-github-generator that's automatic (``https://github.com/"
        "slsa-framework/slsa-github-generator/<workflow>@<ref>``). "
        "For BuildKit the canonical URI is ``https://github.com/"
        "Attestations/GitHubHostedActions@v1`` or one of the "
        "SLSA-listed build types at "
        "https://slsa.dev/buildtypes/. Custom in-house generators "
        "should publish their own buildType URI that points at a "
        "stable schema doc; the URI doesn't need to be globally "
        "registered, but it does need to be resolvable so consumers "
        "can review the schema."
    ),
    docs_note=(
        "Reads the ``buildType`` claim at the spec-appropriate "
        "path: v0.2 at ``predicate.buildType``, v1 at "
        "``predicate.buildDefinition.buildType``. Fires when the "
        "claim is missing, an empty string, or a known placeholder "
        "(``example.com``, ``unknown``, ``n/a``, ``tbd``). A "
        "well-shaped buildType is a URI with a scheme and a path "
        "component; the rule does a conservative URI-shape check "
        "to catch typos like a bare repository name or an "
        "unfilled template token.\n\n"
        "Doesn't validate that the URI is reachable or that the "
        "schema it names is one a verifier knows about; that's "
        "policy-layer work (an allowlist of trusted buildType URIs "
        "is a separate consumer-side concern)."
    ),
    known_fp=(
        "Some experimental generators emit a buildType under a "
        "placeholder URI during development (``https://example.com/"
        "buildtype/v1``). The rule fires on those by design; "
        "the canonical fix is to publish a real schema URI before "
        "any image ships to a registry that downstream consumers "
        "trust. Suppress per-manifest via ``--ignore-file`` only "
        "when the team has a documented review of the "
        "placeholder's intended scope.",
        "BuildKit < v0.10 emitted Statements without a buildType "
        "field at all. Modern Buildx always populates it; if the "
        "rule fires on a current build, the provenance "
        "configuration is likely incomplete rather than the "
        "Buildx version being too old.",
    ),
    incident_refs=(
        "[SLSA v1.0 provenance spec](https://slsa.dev/spec/v1.0/provenance): "
        "buildType is REQUIRED on every Statement. The spec calls "
        "out that consumers MUST refuse provenance whose buildType "
        "they don't recognize, which means an under-specified "
        "buildType reduces the attestation to advisory text the "
        "verifier can't act on.",
        "[SLSA build types catalog](https://slsa.dev/buildtypes/): "
        "the publicly registered buildType URIs SLSA-aware tooling "
        "knows how to verify. Provenance that names an "
        "unregistered URI is acceptable when paired with a "
        "documented schema, but provenance with no URI at all is "
        "structurally unverifiable."
    ),
    exploit_example=(
        "# Vulnerable: a self-rolled SLSA generator that omits the\n"
        "# buildType field. The predicate carries every other\n"
        "# claim (builder, materials, configSource) but consumers\n"
        "# can't tell which schema those claims follow.\n"
        "{\n"
        "  \"_type\": \"https://in-toto.io/Statement/v1\",\n"
        "  \"predicateType\": \"https://slsa.dev/provenance/v1\",\n"
        "  \"predicate\": {\n"
        "    \"buildDefinition\": {\n"
        "      \"externalParameters\": {...},\n"
        "      \"resolvedDependencies\": [...]\n"
        "      // no buildType key\n"
        "    },\n"
        "    \"runDetails\": {\"builder\": {\"id\": \"...\"}}\n"
        "  }\n"
        "}\n"
        "\n"
        "# Attack surface: a consumer verifying this Statement with\n"
        "# a policy of 'only accept buildType = <list>' has no field\n"
        "# to match against. Two common downstream outcomes:\n"
        "#   1. The verifier rejects every Statement (over-strict);\n"
        "#   2. The verifier accepts every Statement (over-loose),\n"
        "#      which means an attacker forging materials in a\n"
        "#      different schema slips by because the verifier\n"
        "#      can't tell the schemas apart.\n"
        "\n"
        "# Safe: emit a concrete buildType URI. For slsa-github-\n"
        "# generator the framework fills this in automatically:\n"
        "{\n"
        "  \"predicate\": {\n"
        "    \"buildDefinition\": {\n"
        "      \"buildType\": \"https://github.com/slsa-framework/\"\n"
        "                    \"slsa-github-generator/generic@v2\",\n"
        "      ...\n"
        "    }\n"
        "  }\n"
        "}"
    ),
)


# Placeholder values the rule explicitly rejects. Lowercased + stripped
# before comparison. The list is intentionally short, the rule's main
# job is to catch *missing* fields; placeholder text is a secondary
# pattern that a few experimental generators are known to emit.
_PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    "", "?", "n/a", "na", "unknown", "none", "tbd", "todo",
    "https://example.com/buildtype/v1",
    "https://example.com",
    "example.com",
})


def _extract_build_type(predicate_type: str, predicate: dict[str, Any]) -> str | None:
    """Return the ``buildType`` value at the spec-version-appropriate
    path, or ``None`` when neither location is populated.

    v1 takes precedence when ``buildDefinition`` is present (some
    transitional attestations carry both shapes; the canonical place
    is the v1 path once buildDefinition exists).
    """
    bd = predicate.get("buildDefinition")
    if isinstance(bd, dict):
        bt = bd.get("buildType")
        if isinstance(bt, str):
            return bt
    bt = predicate.get("buildType")
    if isinstance(bt, str):
        return bt
    return None


def _is_uri_shaped(value: str) -> bool:
    """Conservative URI shape check.

    Must contain ``://`` and at least one non-empty path component
    after the authority. Doesn't validate scheme, host syntax, or
    reachability — those are out of scope for a structural-
    completeness rule.
    """
    if "://" not in value:
        return False
    after_scheme = value.split("://", 1)[1]
    if "/" not in after_scheme:
        return False
    authority, _, path = after_scheme.partition("/")
    if not authority or not path:
        return False
    return True


def check(manifest: OCIManifest) -> Finding:
    if not manifest.is_index:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Single-image manifest carries no attestations; "
                "buildType verification not applicable."
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
                "to verify buildType. Pass an OCI image-layout "
                "directory with a sibling ``blobs/`` tree to enable "
                "content checks; OCI-002 covers the missing-"
                "attestation case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    problems: list[str] = []
    for att in slsa_attestations:
        bt = _extract_build_type(att.predicate_type, att.predicate)
        if bt is None:
            problems.append(
                f"{att.predicate_type}: buildType missing"
            )
            continue
        stripped = bt.strip().lower()
        if stripped in _PLACEHOLDER_VALUES:
            problems.append(
                f"{att.predicate_type}: placeholder buildType {bt!r}"
            )
            continue
        if not _is_uri_shaped(bt):
            problems.append(
                f"{att.predicate_type}: buildType {bt!r} is not a "
                f"URI"
            )

    if not problems:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"All {len(slsa_attestations)} SLSA provenance "
                f"attestation(s) name a non-placeholder buildType "
                f"URI."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    desc = (
        f"{len(problems)} of {len(slsa_attestations)} SLSA "
        f"provenance attestation(s) carry an unverifiable buildType "
        f"claim: {'; '.join(problems[:3])}"
        f"{'…' if len(problems) > 3 else ''}. Consumers can't "
        f"validate the predicate schema without a concrete "
        f"buildType URI."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
