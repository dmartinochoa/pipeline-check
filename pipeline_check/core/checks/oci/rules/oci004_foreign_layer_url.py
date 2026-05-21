"""OCI-004. Image layer references an arbitrary URL (foreign layer)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="OCI-004",
    title="Image layer references an arbitrary URL (foreign layer)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-PROVENANCE", "ESF-S-IMMUTABLE"),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Rebuild the image without foreign-layer references. The "
        "OCI / Docker spec lets a layer descriptor carry a "
        "``urls:`` field that tells the client to pull the layer "
        "blob from an arbitrary HTTP location at image-pull time, "
        "bypassing the registry's content-addressed store. The "
        "mechanism exists for proprietary base layers (notably "
        "Windows Server base images that ship from "
        "``mcr.microsoft.com``) but is increasingly deprecated, "
        "modern Windows images at "
        "``mcr.microsoft.com/windows/servercore:ltsc2022`` no "
        "longer use it. If the foreign URL is genuinely required, "
        "host the blob inside your own registry and pin it by "
        "digest the same as any other layer."
    ),
    docs_note=(
        "A layer with a ``urls:`` field is fetched from whatever "
        "URL the manifest declares, not from the registry the "
        "image was pulled from. The digest is still verified "
        "after the fetch, so a passive attacker can't substitute "
        "a different blob, but an attacker who controls the URL "
        "endpoint can serve different content depending on the "
        "client (server-side cloaking) or simply take the "
        "endpoint offline to break image pulls. The rule fires "
        "on any layer whose descriptor includes a non-empty "
        "``urls:`` array; it doesn't try to validate URL hygiene "
        "(HTTPS, allow-list of hosts) since the existence of the "
        "field alone is the policy violation."
    ),
    known_fp=(
        "Legacy Windows Server base images (pre-Windows 11 / "
        "Server 2022) ship layers from ``mcr.microsoft.com`` with "
        "this mechanism. Suppress via ignore-file when the "
        "Windows image is intentional, the rule has no way to "
        "distinguish a Microsoft-blessed URL from any other.",
    ),
    exploit_example=(
        "# Vulnerable: the manifest declares a layer with a\n"
        "# ``urls:`` field. On pull, the client fetches the layer\n"
        "# blob from that arbitrary URL, bypassing the registry's\n"
        "# content-addressed store. An attacker controlling the URL\n"
        "# (DNS, BGP, compromised host) substitutes the blob; the\n"
        "# registry's integrity guarantee doesn't extend to foreign\n"
        "# URLs.\n"
        "{\n"
        "  \"schemaVersion\": 2,\n"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\",\n"
        "  \"layers\": [\n"
        "    {\n"
        "      \"mediaType\": \"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip\",\n"
        "      \"digest\": \"sha256:layer-blob-digest...\",\n"
        "      \"size\": 12345,\n"
        "      \"urls\": [\"https://internal-mirror.example.com/blobs/foo.tgz\"]\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "\n"
        "# Safe: host the layer blob inside the same registry as\n"
        "# the manifest. No ``urls:`` field — the client fetches\n"
        "# the blob from the registry by digest, and the registry's\n"
        "# content-addressed store guarantees the bytes match.\n"
        "{\n"
        "  \"schemaVersion\": 2,\n"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\",\n"
        "  \"layers\": [\n"
        "    {\n"
        "      \"mediaType\": \"application/vnd.oci.image.layer.v1.tar+gzip\",\n"
        "      \"digest\": \"sha256:layer-blob-digest...\",\n"
        "      \"size\": 12345\n"
        "    }\n"
        "  ]\n"
        "}"
    ),
)


_FOREIGN_LAYER_MEDIA_TYPES: frozenset[str] = frozenset({
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar",
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
})


def _layer_has_foreign_url(layer: dict[str, Any]) -> bool:
    """True when *layer* declares a ``urls:`` array or uses a
    foreign-layer media type.

    The OCI spec describes foreign-layer descriptors with a
    ``urls`` field; the legacy Docker manifest spec uses a distinct
    ``foreign.diff`` media type for the same purpose. Either is
    flagged.
    """
    urls = layer.get("urls")
    if isinstance(urls, list) and any(isinstance(u, str) and u for u in urls):
        return True
    media = layer.get("mediaType")
    return isinstance(media, str) and media in _FOREIGN_LAYER_MEDIA_TYPES


def check(manifest: OCIManifest) -> Finding:
    if manifest.is_index:
        # An index doesn't have layers itself, the foreign-layer
        # check applies to the per-platform manifests it points at.
        # Without a registry pull we can't fetch those, so the rule
        # passes by default for indexes; a downstream scan of each
        # per-platform manifest will catch this when it fires.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=manifest.path,
            description=(
                "Image index has no layers of its own, foreign-layer "
                "references can only be detected on a per-platform "
                "image manifest."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, layer in enumerate(manifest.layers):
        if _layer_has_foreign_url(layer):
            digest = str(layer.get("digest") or f"layers[{idx}]")
            offenders.append(digest[:32])
    passed = not offenders
    desc = (
        "No layer carries a foreign-URL reference."
        if passed else
        f"{len(offenders)} layer(s) carry a foreign-URL reference: "
        f"{', '.join(offenders[:3])}"
        f"{'...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
