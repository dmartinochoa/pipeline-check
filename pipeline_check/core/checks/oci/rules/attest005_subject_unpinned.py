"""ATTEST-005. In-toto Statement subject is missing or unpinned.

An in-toto Statement attests a claim about a *subject*, the artifact
the predicate describes. The subject carries one or more entries each
shaped:

    {"name": "<arbitrary label>", "digest": {"<algo>": "<hex-value>"}}

The digest value is what cryptographically binds the attestation to a
specific byte sequence. A signed attestation whose subject digest is
empty, all-zero, or malformed is structurally unbound: an attacker who
controls the signing key (or who can re-attach a signed envelope) can
move it onto any image at all because the verifier has nothing to
compare against.

ATTEST-001 verifies *who* built the image. ATTEST-002 verifies *from
what source*. ATTEST-004 verifies *what build inputs were consumed*.
ATTEST-005 verifies *that the attestation is actually bound to the
image bytes it claims to describe*.

Pairs with the upstream in-toto threat model: a statement with a
placeholder subject is the canonical attestation-substitution surface,
documented as Statement-Track Threat #2 in the SLSA spec.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="ATTEST-005",
    title="In-toto Statement subject is missing or unpinned",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345", "CWE-1357"),
    recommendation=(
        "Configure the builder to emit Statements with a non-empty "
        "``subject`` array whose entries each carry a populated "
        "``digest`` map. The digest value must be a real hex "
        "encoding of the artifact's bytes, an empty string or "
        "all-zeros placeholder defeats verification. For BuildKit "
        "this is automatic when ``--attest=type=provenance`` is set "
        "alongside ``--push``; older Buildx versions sometimes "
        "emitted Statements with empty subjects, upgrade if you "
        "see this fire on a recent build. For slsa-github-generator "
        "and cosign-attested workflows the subject is populated by "
        "the framework, an empty subject usually means a custom "
        "attestor was wired up incorrectly."
    ),
    docs_note=(
        "Walks every parsed in-toto Statement (SLSA provenance + "
        "SBOM both) and validates the subject array. Three failure "
        "shapes:\n"
        "  - ``subject`` is missing or an empty list, the "
        "Statement attests nothing.\n"
        "  - A subject entry has no ``digest`` map, the entry "
        "names an artifact but doesn't bind to its bytes.\n"
        "  - A digest value is empty, all-zeros, or not valid "
        "hex, the bind exists structurally but the value is a "
        "placeholder.\n\n"
        "Hex validation is conservative: the value must consist "
        "entirely of ``0-9`` and ``a-f`` (case-insensitive) and "
        "the length must be a multiple of two (a valid byte "
        "encoding). Algorithm-specific length checks (``sha256`` "
        "= 64 chars, ``sha1`` = 40) are not enforced here, some "
        "registries truncate to a 16-char prefix and the rule "
        "accepts those as long as the bytes are well-formed."
    ),
    known_fp=(
        "Some experimental attestor implementations emit "
        "Statements with placeholder subjects for in-flight "
        "verification (the bytes are still being uploaded when "
        "the attestation is signed). Suppress per-manifest via "
        "``--ignore-file`` if the team has a documented review "
        "of the deferred-binding pattern; the default expectation "
        "for any image promoted to a production registry is a "
        "subject digest that matches the actual image bytes.",
        "Multi-subject Statements (one attestation covering "
        "multiple sibling artifacts) are accepted, as long as "
        "*every* entry has a populated digest. A partially-filled "
        "subject array fires because the unbound entries are the "
        "substitution surface, the rest don't compensate.",
    ),
    incident_refs=(
        "[in-toto Statement spec](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md): "
        "the subject digest is the cryptographic bind between a "
        "signed envelope and the artifact bytes. A placeholder "
        "value reduces the attestation to a free-floating "
        "signature attackers can re-attach.",
        "[SLSA threat-model v1.0, Statement-Track Threats](https://slsa.dev/spec/v1.0/threats): "
        "attestation substitution is called out as the primary "
        "Statement-track threat. The mitigation listed is exactly "
        "this rule: 'consumers MUST verify the subject digest "
        "matches the artifact they are about to use'.",
    ),
    exploit_example=(
        "# Vulnerable: a Statement signed by a trusted builder but\n"
        "# carrying an empty subject digest. The signature is valid;\n"
        "# the bind to the image bytes is not.\n"
        "{\n"
        "  \"_type\": \"https://in-toto.io/Statement/v1\",\n"
        "  \"subject\": [\n"
        "    {\"name\": \"image\", \"digest\": {\"sha256\": \"\"}}\n"
        "  ],\n"
        "  \"predicateType\": \"https://slsa.dev/provenance/v1\",\n"
        "  \"predicate\": { ... }\n"
        "}\n"
        "\n"
        "# Attack: an attacker who can re-publish the signed DSSE\n"
        "# envelope (the envelope is public on the OCI registry the\n"
        "# image is pushed to) attaches it to a tampered image. The\n"
        "# consumer's verifier checks the signature (valid, the\n"
        "# builder did sign this Statement), checks the source repo\n"
        "# (valid, ATTEST-002 passes), checks the builder identity\n"
        "# (valid, ATTEST-001 passes), and never gets to compare\n"
        "# the subject digest because the digest is empty. Result:\n"
        "# the tampered image looks fully attested.\n"
        "\n"
        "# Safe: subject digest populated with the actual image\n"
        "# config digest BuildKit / slsa-github-generator emit by\n"
        "# default when wired up correctly.\n"
        "{\n"
        "  \"_type\": \"https://in-toto.io/Statement/v1\",\n"
        "  \"subject\": [\n"
        "    {\"name\": \"image\",\n"
        "     \"digest\": {\n"
        "       \"sha256\": \"4d5a6e7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70819\"\n"
        "                    \"a2b3c4d5e6f70819a2b3c4d5e6f70819\"\n"
        "     }}\n"
        "  ],\n"
        "  \"predicateType\": \"https://slsa.dev/provenance/v1\",\n"
        "  \"predicate\": { ... }\n"
        "}"
    ),
)


# Characters allowed in a hex digest value. Lowercased before comparison.
_HEX_CHARS: frozenset[str] = frozenset("0123456789abcdef")


def _is_well_formed_digest(value: Any) -> bool:
    """True when *value* is a non-empty, all-zero-free hex string.

    Length must be even (a byte encoding). Algorithm-specific length
    checks (``sha256`` = 64, ``sha1`` = 40) are intentionally not
    enforced, some registries truncate to a shorter prefix and the
    rule treats those as bound-enough.
    """
    if not isinstance(value, str):
        return False
    stripped = value.strip().lower()
    if not stripped:
        return False
    if len(stripped) % 2 != 0:
        return False
    if set(stripped) <= {"0"}:
        return False
    return set(stripped) <= _HEX_CHARS


def _evaluate_subject(subject: Any) -> str | None:
    """Validate a Statement's subject array. Returns a problem string
    on failure, ``None`` on pass.

    Three failure modes:
    - The subject array is missing or empty.
    - Any entry lacks a populated ``digest`` map.
    - Any digest value is empty, all-zeros, or not valid hex.

    Reports the first failure encountered so the caller surfaces a
    single concise reason per attestation; subsequent failures are
    typically the same shape and don't add diagnostic value.
    """
    if not isinstance(subject, (list, tuple)) or not subject:
        return "subject array is empty or missing"
    for idx, entry in enumerate(subject):
        if not isinstance(entry, dict):
            return f"subject[{idx}] is not a mapping"
        digest_block = entry.get("digest")
        if not isinstance(digest_block, dict) or not digest_block:
            name = entry.get("name") or f"<entry {idx}>"
            return f"subject[{idx}] ({name!r}) has no digest"
        for algo, value in digest_block.items():
            if not _is_well_formed_digest(value):
                name = entry.get("name") or f"<entry {idx}>"
                rendered = repr(value)[:40] if value else "<empty>"
                return (
                    f"subject[{idx}] ({name!r}) "
                    f"{algo} digest is unpinned: {rendered}"
                )
    return None


def check(manifest: OCIManifest) -> Finding:
    if not manifest.is_index:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Single-image manifest carries no attestations; "
                "subject-digest verification not applicable."
            ),
            recommendation="No action required.", passed=True,
        )

    if not manifest.attestations:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "No attestation content available to verify subject "
                "binding. Pass an OCI image-layout directory with a "
                "sibling ``blobs/`` tree to enable content checks; "
                "OCI-002 covers the missing-attestation case."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    problems: list[str] = []
    for att in manifest.attestations:
        msg = _evaluate_subject(att.subject)
        if msg is not None:
            # Tag the failure with the predicate type so an operator
            # scanning the description can tell whether it's a
            # provenance or SBOM Statement that's unbound.
            problems.append(f"{att.predicate_type}: {msg}")

    if not problems:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                f"All {len(manifest.attestations)} attestation(s) "
                f"carry a populated subject digest."
            ),
            recommendation=RULE.recommendation, passed=True,
        )

    desc = (
        f"{len(problems)} of {len(manifest.attestations)} "
        f"attestation(s) carry an unpinned subject: "
        f"{'; '.join(problems[:3])}"
        f"{'…' if len(problems) > 3 else ''}. Attestations whose "
        f"subject digest isn't bound to actual image bytes can be "
        f"re-attached to tampered artifacts without breaking the "
        f"signature."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
