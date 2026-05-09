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
"""
from __future__ import annotations

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
            manifests.append(parsed)
        ctx = cls(manifests)
        ctx.files_skipped = skipped
        ctx.warnings = warnings
        return ctx


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
    "IndexEntry",
    "OCIBaseCheck",
    "OCIContext",
    "OCIManifest",
    "iter_attestation_entries",
    "primary_image_annotations",
]
