"""OCI-008. Manifest references a digest with a weak / legacy hash."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="OCI-008",
    title="Manifest references digest using non-sha256 hash",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-IMMUTABLE", "ESF-S-PROVENANCE"),
    cwe=("CWE-327", "CWE-328"),
    recommendation=(
        "Rebuild and re-push the image so every descriptor "
        "(config, layers, sub-manifest entries) carries a "
        "``sha256:`` digest. ``sha512:`` is also acceptable per "
        "the OCI spec, but anything weaker (md5, sha1) breaks "
        "the integrity guarantee the registry pull is supposed "
        "to provide. sha1 has had practical collisions since "
        "SHAttered (2017); md5 has had them since the early "
        "2000s. A manifest that pins a layer by sha1 lets an "
        "attacker who can produce a colliding blob substitute a "
        "different tarball without changing the manifest, the "
        "registry's content-addressing then ratifies the "
        "substitution."
    ),
    docs_note=(
        "The OCI image-spec mandates ``sha256:`` or ``sha512:`` "
        "for content descriptors. ``sha1:`` and ``md5:`` were "
        "never permitted by the spec but show up occasionally "
        "in mirror exports and forensic JSON; this rule catches "
        "them.\n\n"
        "Detection scope: the config descriptor digest, every "
        "layer descriptor digest (single-image manifests), and "
        "every sub-manifest entry digest in an image index. The "
        "matcher accepts ``sha256:`` and ``sha512:`` as the "
        "only valid prefixes; anything else fires."
    ),
    known_fp=(
        "Test fixtures and intentionally-corrupt CTF images "
        "sometimes use degraded hashes for pedagogical reasons. "
        "Suppress on the specific path with an ignore-file when "
        "this is the deliberate shape.",
    ),
)


_ACCEPTED_PREFIXES: tuple[str, ...] = ("sha256:", "sha512:")


def _is_weak(digest: str) -> bool:
    if not digest:
        return False
    return not digest.startswith(_ACCEPTED_PREFIXES)


def _digest_algo(digest: str) -> str:
    return digest.split(":", 1)[0] if ":" in digest else "(missing)"


def check(manifest: OCIManifest) -> Finding:
    offenders: list[str] = []
    if manifest.is_index:
        for idx, entry in enumerate(manifest.entries):
            if _is_weak(entry.digest):
                offenders.append(
                    f"manifests[{idx}]: {_digest_algo(entry.digest)}"
                )
    else:
        if _is_weak(manifest.config_digest):
            offenders.append(
                f"config: {_digest_algo(manifest.config_digest)}"
            )
        for idx, layer in enumerate(manifest.layers):
            digest = layer.get("digest") if isinstance(layer, dict) else None
            if isinstance(digest, str) and _is_weak(digest):
                offenders.append(
                    f"layers[{idx}]: {_digest_algo(digest)}"
                )
    passed = not offenders
    desc = (
        "Every descriptor digest uses sha256 or sha512."
        if passed else
        f"{len(offenders)} descriptor(s) use a non-sha256 "
        f"digest: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
