"""OCI image manifest context and base check.

Loads JSON files from disk and classifies each as either a
single-platform image manifest or a multi-platform image index.
Documents that don't carry a recognized OCI / Docker-distribution-v2
``mediaType`` are skipped, so a directory holding mixed JSON content
(``package.json``, build metadata, lock files) is safe to point at.

The parser is deliberately small. It does NOT fetch the config or
layer blobs that the manifest references, it does NOT validate
digests against the registry, and it does NOT execute any
``oci-tool`` / ``oras`` / ``crane`` binary. Its job is to surface
the manifest *shape* so per-rule logic (provenance annotations,
attestation-manifest entries, image-creation timestamp) doesn't
reimplement JSON loading, encoding, or media-type classification.

Attestation content (SLSA provenance, SBOMs) is parsed when the
input is an OCI image-layout directory (``blobs/<algo>/<digest>``
filesystem layout per the OCI image-layout spec). The
attestation-manifest sub-entries' layer blobs are read, parsed as
in-toto Statements, and surfaced on
:attr:`OCIManifest.attestations`. Single ``index.json`` inputs
without sibling blobs see attestation-manifest *entries* but no
parsed *content*; the ``ATTEST-NNN`` rules degrade gracefully.
"""
from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..base import BaseCheck

# Media types we recognize as "image manifest" shapes. Includes both
# the OCI 1.0 / 1.1 spec types and the Docker-distribution-v2 types
# BuildKit still emits by default. Keeping both keeps the rule set
# applicable to images that haven't migrated off the docker types
# yet, which in practice is most of the public registry.
_INDEX_MEDIA_TYPES: frozenset[str] = frozenset({
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
})
_MANIFEST_MEDIA_TYPES: frozenset[str] = frozenset({
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
})

# BuildKit attestation manifests are sibling entries inside an image
# index, distinguished by a synthetic platform (``unknown/unknown``)
# and the ``vnd.docker.reference.type: attestation-manifest``
# annotation. The same attestation-manifest convention is what
# ``docker buildx --attest=type=provenance`` and ``--attest=type=sbom``
# produce; rules look for any sub-manifest carrying this annotation.
_ATTESTATION_REF_TYPE_KEY = "vnd.docker.reference.type"
_ATTESTATION_REF_TYPE_VALUE = "attestation-manifest"

# Layer mediaType BuildKit emits for in-toto Statement payloads. The
# blob content is the bare Statement JSON, not a DSSE envelope.
_INTOTO_LAYER_MEDIA_TYPE = "application/vnd.in-toto+json"

# Minimal predicate-type prefixes the parser recognizes. The rule
# layer interprets the full predicate type; the parser just keeps
# whatever string the Statement carries. Listed here for reference:
#
#   https://slsa.dev/provenance/v0.2          (SLSA Build L2)
#   https://slsa.dev/provenance/v1            (SLSA L3+)
#   https://spdx.dev/Document                 (SPDX SBOM)
#   https://cyclonedx.org/bom                 (CycloneDX SBOM)
#
# Layer ``annotations.in-toto.io/predicate-type`` is the BuildKit-side
# hint; the Statement's ``predicateType`` field is the canonical
# source. The two should agree; rules read the Statement field.


@dataclass(frozen=True, slots=True)
class IndexEntry:
    """One entry inside an image-index ``manifests`` array.

    ``platform`` is preserved as-is because rules differentiate
    runtime manifests (e.g. ``linux/amd64``) from the synthetic
    ``unknown/unknown`` BuildKit assigns to attestation manifests.
    """

    media_type: str
    digest: str
    size: int
    platform: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    @property
    def is_attestation_manifest(self) -> bool:
        """True when this entry is a BuildKit-style attestation manifest."""
        return (
            self.annotations.get(_ATTESTATION_REF_TYPE_KEY)
            == _ATTESTATION_REF_TYPE_VALUE
        )


@dataclass(frozen=True, slots=True)
class Attestation:
    """A parsed in-toto Statement extracted from an attestation
    manifest's layer blob.

    BuildKit / SLSA-github-generator emit the Statement as a bare
    JSON document under media type ``application/vnd.in-toto+json``;
    the parser also accepts DSSE-wrapped Statements and unwraps the
    base64 ``payload`` field automatically.

    ``predicate_type`` is the canonical URI from the Statement's
    own ``predicateType`` field (e.g.
    ``https://slsa.dev/provenance/v1``). Rules dispatch on this
    string to decide which predicate shape to walk.

    ``predicate`` is the parsed predicate body. The shape varies by
    predicate type (SLSA provenance has ``builder``, ``buildType``;
    SPDX SBOM has ``packages``; CycloneDX has ``components``). Rules
    that don't recognize a predicate type leave the attestation
    alone.

    ``manifest_path`` is the source layout's manifest file (so
    findings can be anchored to a real path), and ``layer_digest``
    is the blob's content-addressable digest for cross-finding
    correlation.
    """

    predicate_type: str
    predicate: dict[str, Any]
    statement_type: str
    subject: tuple[dict[str, Any], ...]
    manifest_path: str
    layer_digest: str
    raw_statement: dict[str, Any] = field(default_factory=dict)

    @property
    def is_slsa_provenance(self) -> bool:
        return self.predicate_type.startswith("https://slsa.dev/provenance/")

    @property
    def is_sbom(self) -> bool:
        return self.predicate_type.startswith((
            "https://spdx.dev/Document",
            "https://cyclonedx.org/bom",
        ))


@dataclass(frozen=True, slots=True)
class OCIManifest:
    """A parsed OCI image manifest or image index loaded from disk."""

    path: str
    media_type: str
    schema_version: int
    annotations: dict[str, str] = field(default_factory=dict)
    #: For an image index, the per-platform / attestation entries.
    #: Empty for single-image manifests.
    entries: tuple[IndexEntry, ...] = ()
    #: For a single-image manifest, the config descriptor's digest.
    #: Empty string for image indexes (config lives on each entry).
    config_digest: str = ""
    config_media_type: str = ""
    #: For a single-image manifest, the raw ``layers`` list. Each
    #: entry is a dict with ``mediaType`` / ``digest`` / ``size``
    #: at minimum. Empty for image indexes.
    layers: tuple[dict[str, Any], ...] = ()
    #: Parsed in-toto Statements extracted from this manifest's
    #: attestation sub-manifests, when the input is an OCI image-
    #: layout directory whose ``blobs/`` tree contains the layer
    #: blobs. Empty for single-file ``index.json`` inputs (the
    #: scanner can see the *entries* but not their *content*) and
    #: for non-attested images. ``ATTEST-NNN`` rules read this
    #: field directly.
    attestations: tuple[Attestation, ...] = ()
    #: Original parsed JSON, for rules that need to reach into a
    #: less-common field without having to round-trip through this
    #: dataclass's structured view.
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_index(self) -> bool:
        return self.media_type in _INDEX_MEDIA_TYPES


class OCIContext:
    """Loaded set of OCI image manifest / image-index documents."""

    def __init__(self, manifests: list[OCIManifest]) -> None:
        self.manifests = manifests
        self.files_scanned: int = len(manifests)
        self.files_skipped: int = 0
        self.warnings: list[str] = []

    @classmethod
    def from_path(cls, path: str | Path) -> OCIContext:
        root = Path(path)
        if not root.exists():
            raise ValueError(
                f"--oci-manifest {root} does not exist. Pass an OCI "
                "image manifest JSON file (the output of "
                "``docker buildx imagetools inspect --raw <ref>``) "
                "or a directory containing one."
            )
        if root.is_file():
            files = [root]
            # When pointed at a single index.json, sibling blobs
            # under ``blobs/sha256/`` (the OCI image-layout
            # convention) are still useful for attestation parsing.
            blob_root = root.parent
        else:
            # ``index.json`` is the canonical name used by the OCI
            # image-layout spec; pick that up first so a layout
            # directory works without spelling out the file. Any
            # other ``*.json`` is also tried so users can save
            # ``inspect --raw`` output under any name they like.
            preferred = sorted(
                p for p in root.rglob("index.json") if p.is_file()
            )
            preferred_set = set(preferred)
            others = sorted(
                p for p in root.rglob("*.json")
                if p.is_file() and p not in preferred_set
            )
            files = preferred + others
            blob_root = root
        # Build a digest -> blob-path index once so attestation
        # resolution is O(1). When no ``blobs/`` tree is present the
        # index is empty; ATTEST-NNN rules degrade to "no attestation
        # content available" silently.
        blob_index = _build_blob_index(blob_root)
        manifests: list[OCIManifest] = []
        warnings: list[str] = []
        skipped = 0
        for f in files:
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"{f}: read error: {exc}")
                skipped += 1
                continue
            try:
                doc = json.loads(text)
            except json.JSONDecodeError as exc:
                warnings.append(
                    f"{f}: JSON parse error: {str(exc).split(chr(10), 1)[0]}"
                )
                skipped += 1
                continue
            if not isinstance(doc, dict):
                skipped += 1
                continue
            parsed = _parse_manifest(str(f), doc)
            if parsed is None:
                # Not an OCI / Docker-v2 manifest; the directory may
                # legitimately hold unrelated JSON files. Skip
                # silently rather than warn so a noisy directory
                # doesn't drown out real warnings.
                skipped += 1
                continue
            # Hydrate attestation content from blob_index. A manifest
            # with no attestation entries gets ``attestations=()``;
            # an entry whose layer blob is missing gets a warning and
            # is skipped, so the rule layer can't false-positive on
            # incomplete inputs.
            attestations, attest_warnings = _resolve_attestations(
                parsed, blob_index,
            )
            warnings.extend(f"{f}: {w}" for w in attest_warnings)
            if attestations:
                parsed = OCIManifest(
                    path=parsed.path,
                    media_type=parsed.media_type,
                    schema_version=parsed.schema_version,
                    annotations=parsed.annotations,
                    entries=parsed.entries,
                    config_digest=parsed.config_digest,
                    config_media_type=parsed.config_media_type,
                    layers=parsed.layers,
                    attestations=attestations,
                    raw=parsed.raw,
                )
            manifests.append(parsed)
        ctx = cls(manifests)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


def _build_blob_index(root: Path) -> dict[str, Path]:
    """Return ``digest -> blob-file`` for every blob under *root*.

    The OCI image-layout spec stores blobs at
    ``blobs/<algorithm>/<encoded-digest>``. When *root* contains a
    ``blobs/`` directory we walk its content and key the result by
    ``"<algorithm>:<encoded-digest>"`` so callers can look up a
    blob by the same digest string the manifest itself uses
    (``"sha256:abc..."``).

    Empty when no ``blobs/`` directory exists; the attestation
    resolver then degrades to "no content available".
    """
    blobs_dir = root / "blobs"
    if not blobs_dir.is_dir():
        return {}
    out: dict[str, Path] = {}
    for algo_dir in blobs_dir.iterdir():
        if not algo_dir.is_dir():
            continue
        algo = algo_dir.name
        for blob in algo_dir.iterdir():
            if not blob.is_file():
                continue
            out[f"{algo}:{blob.name}"] = blob
    return out


def _decode_dsse_payload(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Return the inner Statement when *doc* is a DSSE envelope.

    DSSE wraps a Statement under a base64-encoded ``payload`` field.
    BuildKit emits bare Statements (no DSSE), but cosign-attested
    Statements use this envelope. Detection: ``payloadType`` +
    ``payload`` keys present, no ``_type`` at the top level.

    Returns ``None`` if *doc* doesn't look like a DSSE envelope or
    if the payload doesn't decode to JSON. Defensive: a malformed
    envelope shouldn't abort the scan, just skip the attestation.
    """
    if "_type" in doc:
        return None
    payload = doc.get("payload")
    if not isinstance(payload, str):
        return None
    if not isinstance(doc.get("payloadType"), str):
        return None
    try:
        decoded = base64.b64decode(payload, validate=False)
        statement = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None
    return statement if isinstance(statement, dict) else None


def _statement_to_attestation(
    statement: dict[str, Any],
    *,
    manifest_path: str,
    layer_digest: str,
) -> Attestation | None:
    """Validate the in-toto Statement shape and project it onto an
    :class:`Attestation`. Returns ``None`` for unrecognized shapes.

    Both v0.1 (``https://in-toto.io/Statement/v0.1``) and v1
    (``https://in-toto.io/Statement/v1``) Statements are accepted;
    they share the required fields the rule layer reads
    (``predicateType``, ``predicate``, ``subject``).
    """
    statement_type = statement.get("_type")
    predicate_type = statement.get("predicateType")
    predicate = statement.get("predicate")
    subject = statement.get("subject")
    # Only accept canonical in-toto Statement types; anything else
    # (truncated, mistyped, attacker-supplied JSON masquerading as a
    # Statement) takes the skip path so the attestation rules don't
    # ingest a payload they can't reason about.
    if statement_type not in {
        "https://in-toto.io/Statement/v0.1",
        "https://in-toto.io/Statement/v1",
    }:
        return None
    if not isinstance(predicate_type, str):
        return None
    if not isinstance(predicate, dict):
        return None
    if not isinstance(subject, list):
        return None
    typed_subject = tuple(s for s in subject if isinstance(s, dict))
    return Attestation(
        predicate_type=predicate_type,
        predicate=predicate,
        statement_type=statement_type,
        subject=typed_subject,
        manifest_path=manifest_path,
        layer_digest=layer_digest,
        raw_statement=statement,
    )


def _resolve_attestations(
    manifest: OCIManifest,
    blob_index: dict[str, Path],
) -> tuple[tuple[Attestation, ...], list[str]]:
    """Walk attestation-manifest entries and return parsed Statements.

    Each attestation entry's layer-blob digests are looked up in
    *blob_index*; the blob is read as JSON, optionally unwrapped from
    a DSSE envelope, and projected to an :class:`Attestation`.
    Missing blobs and malformed payloads accumulate warnings rather
    than raising, so a partial layout doesn't abort the scan.
    """
    if not blob_index:
        return ((), [])
    if not manifest.is_index:
        return ((), [])
    attestations: list[Attestation] = []
    warnings: list[str] = []
    for entry in manifest.entries:
        if not entry.is_attestation_manifest:
            continue
        # The entry's digest points at the attestation manifest blob;
        # that manifest's layers point at the actual Statement blobs.
        attest_manifest_blob = blob_index.get(entry.digest)
        if attest_manifest_blob is None:
            warnings.append(
                f"attestation manifest blob {entry.digest} not found in "
                f"blobs/ tree; skipping content parse"
            )
            continue
        try:
            attest_doc = json.loads(
                attest_manifest_blob.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            warnings.append(
                f"attestation manifest {entry.digest} parse error: {exc}"
            )
            continue
        if not isinstance(attest_doc, dict):
            continue
        for layer in attest_doc.get("layers") or []:
            if not isinstance(layer, dict):
                continue
            if layer.get("mediaType") != _INTOTO_LAYER_MEDIA_TYPE:
                continue
            layer_digest = layer.get("digest")
            if not isinstance(layer_digest, str):
                continue
            blob_path = blob_index.get(layer_digest)
            if blob_path is None:
                warnings.append(
                    f"in-toto layer blob {layer_digest} not found; "
                    f"attestation skipped"
                )
                continue
            try:
                payload_doc = json.loads(
                    blob_path.read_text(encoding="utf-8")
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                warnings.append(
                    f"in-toto blob {layer_digest} parse error: {exc}"
                )
                continue
            if not isinstance(payload_doc, dict):
                continue
            # DSSE-wrapped Statements unwrap to the inner Statement;
            # bare Statements pass through.
            inner = _decode_dsse_payload(payload_doc)
            statement = inner if inner is not None else payload_doc
            att = _statement_to_attestation(
                statement,
                manifest_path=manifest.path,
                layer_digest=layer_digest,
            )
            if att is not None:
                attestations.append(att)
    return tuple(attestations), warnings


def _parse_manifest(path: str, doc: dict[str, Any]) -> OCIManifest | None:
    """Classify *doc* and return a typed :class:`OCIManifest`, or
    ``None`` if it isn't a recognized manifest shape.
    """
    media_type = doc.get("mediaType")
    if not isinstance(media_type, str):
        return None
    if (
        media_type not in _INDEX_MEDIA_TYPES
        and media_type not in _MANIFEST_MEDIA_TYPES
    ):
        return None
    schema = doc.get("schemaVersion")
    if not isinstance(schema, int):
        schema = 0
    annotations_raw = doc.get("annotations") or {}
    annotations: dict[str, str] = {
        str(k): str(v) for k, v in annotations_raw.items()
        if isinstance(annotations_raw, dict)
    }
    if media_type in _INDEX_MEDIA_TYPES:
        entries = _parse_entries(doc.get("manifests") or [])
        return OCIManifest(
            path=path,
            media_type=media_type,
            schema_version=schema,
            annotations=annotations,
            entries=entries,
            raw=doc,
        )
    # Single-image manifest.
    config = doc.get("config") or {}
    config_digest = ""
    config_media_type = ""
    if isinstance(config, dict):
        config_digest = str(config.get("digest") or "")
        config_media_type = str(config.get("mediaType") or "")
    layers_raw = doc.get("layers") or []
    layers = tuple(
        layer for layer in layers_raw if isinstance(layer, dict)
    )
    return OCIManifest(
        path=path,
        media_type=media_type,
        schema_version=schema,
        annotations=annotations,
        config_digest=config_digest,
        config_media_type=config_media_type,
        layers=layers,
        raw=doc,
    )


def _parse_entries(raw_entries: Any) -> tuple[IndexEntry, ...]:
    """Materialise the index ``manifests`` list into typed entries.

    Defensive against malformed inputs: any entry that isn't a dict
    or that lacks the minimum fields is dropped silently. The rule
    pack already operates on a "best-effort" assumption (the user
    captured this JSON from some image inspect tool, malformed
    output should produce no false positives).
    """
    out: list[IndexEntry] = []
    if not isinstance(raw_entries, list):
        return ()
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        media_type = entry.get("mediaType")
        digest = entry.get("digest")
        if not isinstance(media_type, str) or not isinstance(digest, str):
            continue
        size = entry.get("size")
        size_int = size if isinstance(size, int) else 0
        platform_raw = entry.get("platform") or {}
        platform: dict[str, Any] = (
            dict(platform_raw) if isinstance(platform_raw, dict) else {}
        )
        ann_raw = entry.get("annotations") or {}
        annotations: dict[str, str] = (
            {str(k): str(v) for k, v in ann_raw.items()}
            if isinstance(ann_raw, dict) else {}
        )
        out.append(IndexEntry(
            media_type=media_type,
            digest=digest,
            size=size_int,
            platform=platform,
            annotations=annotations,
        ))
    return tuple(out)


class OCIBaseCheck(BaseCheck):
    """Base class for OCI-provider rule modules."""

    PROVIDER = "oci"

    def __init__(self, ctx: OCIContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: OCIContext = ctx


# ── Helpers shared by multiple rule modules ────────────────────────────


def iter_attestation_entries(
    manifest: OCIManifest,
) -> Iterator[IndexEntry]:
    """Yield every BuildKit-style attestation-manifest entry.

    Returns nothing for a single-image manifest (no entries to
    iterate) or for an image index that simply has no attestation
    sub-manifests. Rules use this to detect "no provenance / SBOM
    attached" without each one re-scanning the entries list.
    """
    for entry in manifest.entries:
        if entry.is_attestation_manifest:
            yield entry


def primary_image_annotations(manifest: OCIManifest) -> dict[str, str]:
    """Return the annotations carried by the runtime image.

    For a single-image manifest, this is just ``manifest.annotations``.
    For an image index, BuildKit copies the OCI image-spec annotations
    onto every per-platform sub-manifest *and* onto the top-level
    index. This helper unions them, so a rule can ask "is
    org.opencontainers.image.source set anywhere on the runtime
    image?" without caring which of the two layers carries it.
    """
    out: dict[str, str] = dict(manifest.annotations)
    for entry in manifest.entries:
        # Skip attestation manifests: their annotations describe the
        # attestation, not the runtime image. ``unknown/unknown``
        # platform also marks them.
        if entry.is_attestation_manifest:
            continue
        plat = entry.platform or {}
        if (
            plat.get("architecture") == "unknown"
            or plat.get("os") == "unknown"
        ):
            continue
        for k, v in entry.annotations.items():
            out.setdefault(k, v)
    return out


__all__ = [
    "Attestation",
    "IndexEntry",
    "OCIBaseCheck",
    "OCIContext",
    "OCIManifest",
    "iter_attestation_entries",
    "primary_image_annotations",
]
