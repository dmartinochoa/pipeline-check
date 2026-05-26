"""CycloneDX 1.6 SBOM reporter.

Formats a list of :class:`BuildDependency` objects into a
CycloneDX 1.6 JSON BOM. No external library needed; the spec's
required fields are emitted directly.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .sbom import BuildDependency, deduplicate

_SPEC_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

_DEP_TYPE_TO_CDX: dict[str, str] = {
    "action": "library",
    "workflow": "library",
    "container": "container",
    "npm": "library",
    "pypi": "library",
    "maven": "library",
    "nuget": "library",
    "helm": "library",
    "oci": "container",
}


def report_cyclonedx(
    deps: list[BuildDependency],
    tool_version: str = "",
    scanned_path: str = ".",
) -> str:
    """Serialize *deps* as a CycloneDX 1.6 JSON BOM string."""
    unique = deduplicate(deps)

    components: list[dict[str, Any]] = []
    for d in unique:
        comp: dict[str, Any] = {
            "type": _DEP_TYPE_TO_CDX.get(d.dep_type, "library"),
            "name": d.name,
            "version": d.version,
            "purl": d.purl,
            "bom-ref": d.bom_ref(),
        }
        props: list[dict[str, str]] = [
            {"name": "pipeline-check:provider", "value": d.provider},
            {"name": "pipeline-check:kind", "value": d.dep_type},
            {"name": "pipeline-check:source", "value": d.source},
            {"name": "pipeline-check:pinned", "value": str(d.pinned).lower()},
        ]
        if d.digest:
            props.append(
                {"name": "pipeline-check:digest", "value": d.digest},
            )
        comp["properties"] = props
        components.append(comp)

    bom: dict[str, Any] = {
        "bomFormat": _BOM_FORMAT,
        "specVersion": _SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ",
            ),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pipeline-check",
                        "version": tool_version or "0.0.0",
                    },
                ],
            },
            "component": {
                "type": "application",
                "name": scanned_path,
                "bom-ref": "root",
            },
        },
        "components": components,
    }
    return json.dumps(bom, indent=2)


__all__ = ["report_cyclonedx"]
