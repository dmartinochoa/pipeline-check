"""OCI provider, scans an image manifest / image-index JSON document
captured via ``docker buildx imagetools inspect --raw <ref>`` (or
equivalent ``oras manifest fetch`` / ``crane manifest`` output).

    pipeline_check --pipeline oci --oci-manifest path/to/manifest.json

Pure parser, no registry pull, no image build, no daemon access. The
JSON itself is the source of truth, the user is responsible for
fetching it; this keeps the scanner read-from-disk-only and
avoids taking on a registry-credential surface.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.oci.base import OCIContext
from ..checks.oci.manifests import OCIManifestChecks
from ..inventory import Component
from .base import BaseProvider


class OCIProvider(BaseProvider):
    """OCI image manifest provider, parses image-spec JSON documents."""

    NAME = "oci"

    def build_context(
        self,
        oci_manifest: str | None = None,
        **_: Any,
    ) -> OCIContext:
        if not oci_manifest:
            raise ValueError(
                "The oci provider requires --oci-manifest "
                "<file-or-dir> pointing at an image-manifest JSON "
                "(the output of ``docker buildx imagetools inspect "
                "--raw <ref>``) or a directory containing one."
            )
        return OCIContext.from_path(oci_manifest)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [OCIManifestChecks]

    def inventory(self, context: OCIContext) -> list[Component]:
        out: list[Component] = []
        for manifest in context.manifests:
            metadata: dict[str, Any] = {
                "media_type": manifest.media_type,
                "schema_version": manifest.schema_version,
            }
            if manifest.is_index:
                metadata["entry_count"] = len(manifest.entries)
                metadata["attestation_count"] = sum(
                    1 for e in manifest.entries if e.is_attestation_manifest
                )
                metadata["platforms"] = sorted({
                    f"{e.platform.get('os', '')}/"
                    f"{e.platform.get('architecture', '')}"
                    for e in manifest.entries
                    if not e.is_attestation_manifest and e.platform
                })
            else:
                metadata["layer_count"] = len(manifest.layers)
                if manifest.config_digest:
                    metadata["config_digest"] = manifest.config_digest
            for ann_key in (
                "org.opencontainers.image.source",
                "org.opencontainers.image.revision",
                "org.opencontainers.image.created",
            ):
                value = manifest.annotations.get(ann_key)
                if value:
                    metadata[ann_key] = value
            out.append(Component(
                provider=self.NAME,
                type=(
                    "image_index" if manifest.is_index else "image_manifest"
                ),
                identifier=manifest.path,
                source=manifest.path,
                metadata=metadata,
            ))
        return out
