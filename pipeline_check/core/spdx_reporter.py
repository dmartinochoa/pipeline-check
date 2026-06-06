"""SPDX 2.3 SBOM reporter.

Formats a list of :class:`BuildDependency` objects into an SPDX 2.3 JSON
document (ISO/IEC 5962), the SPDX-format parallel of the CycloneDX
reporter. Some toolchains and procurement processes require SPDX rather
than CycloneDX, so the scanner emits the same build-dependency inventory
in both. No external library needed; the spec's required fields are
emitted directly.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from .sbom import BuildDependency, deduplicate

_SPDX_VERSION = "SPDX-2.3"
_DATA_LICENSE = "CC0-1.0"
_DOC_ID = "SPDXRef-DOCUMENT"

# SPDX element ids (``SPDXRef-...``) allow only letters, digits, ``.`` and
# ``-``; in particular ``_`` (which ``bom_ref`` permits) is not allowed.
_SPDXID_RE = re.compile(r"[^0-9a-zA-Z.-]")
_SHA256_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})$")
_SHA1_RE = re.compile(r"^([0-9a-f]{40})$")


def _package_spdxid(slug: str, idx: int) -> str:
    """Build a unique, schema-valid ``SPDXRef-Package-...`` id.

    The leading index guarantees uniqueness even when two dependencies
    share a name + version, so no de-dup of ids is needed.
    """
    clean = _SPDXID_RE.sub("-", slug).strip("-") or "dep"
    return f"SPDXRef-Package-{idx}-{clean}"[:255]


def _checksum(digest: str) -> dict[str, str] | None:
    """Map a recognized digest to an SPDX ``checksums`` entry, or None."""
    m = _SHA256_RE.search(digest)
    if m:
        return {"algorithm": "SHA256", "checksumValue": m.group(1)}
    m = _SHA1_RE.match(digest)
    if m:
        return {"algorithm": "SHA1", "checksumValue": m.group(1)}
    return None


def report_spdx(
    deps: list[BuildDependency],
    tool_version: str = "",
    scanned_path: str = ".",
) -> str:
    """Serialize *deps* as an SPDX 2.3 JSON document string."""
    unique = deduplicate(deps)
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_name = scanned_path or "."
    slug = _SPDXID_RE.sub("-", doc_name).strip("-") or "scan"
    namespace = (
        f"https://github.com/dmartinochoa/pipeline-check/spdx/{slug}-{created}"
    )

    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    for i, d in enumerate(unique):
        pid = _package_spdxid(d.bom_ref(), i)
        pkg: dict[str, Any] = {
            "SPDXID": pid,
            "name": d.name or "NOASSERTION",
            "versionInfo": d.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": d.purl,
                },
            ],
            "comment": (
                f"provider={d.provider} kind={d.dep_type} "
                f"source={d.source} pinned={str(d.pinned).lower()}"
            ),
        }
        chk = _checksum(d.digest) if d.digest else None
        if chk is not None:
            pkg["checksums"] = [chk]
        packages.append(pkg)
        relationships.append({
            "spdxElementId": _DOC_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": pid,
        })

    doc: dict[str, Any] = {
        "spdxVersion": _SPDX_VERSION,
        "dataLicense": _DATA_LICENSE,
        "SPDXID": _DOC_ID,
        "name": doc_name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: pipeline-check-{tool_version or '0.0.0'}"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    return json.dumps(doc, indent=2)


__all__ = ["report_spdx"]
