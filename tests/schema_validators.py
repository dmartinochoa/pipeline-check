"""Loaders for the vendored external report schemas.

The schemas under ``tests/schemas/`` are the official, unmodified
upstream documents (see ``tests/schemas/README.md`` for provenance and
versions). They let the reporter tests validate generated SARIF /
CycloneDX output against the real specs that downstream tools enforce
(GitHub code scanning for SARIF, SBOM consumers for CycloneDX) rather
than against a hand-rolled approximation that can drift from the spec.

``jsonschema`` and its ``referencing`` dependency are both pinned in
``requirements-dev.txt``; no network access happens at test time.
"""
from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).parent / "schemas"


@cache
def _load(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def sarif_validator() -> Draft7Validator:
    """Validator for SARIF 2.1.0 (a single self-contained schema)."""
    return Draft7Validator(_load("sarif-2.1.0.schema.json"))


def cyclonedx_validator() -> Draft7Validator:
    """Validator for CycloneDX 1.6.

    The BOM schema references the SPDX and JSF sub-schemas by relative
    URL. Both are vendored alongside it and registered by ``$id`` so the
    ``$ref``s resolve from the local registry, not the network.
    """
    names = (
        "cyclonedx-1.6.schema.json",
        "spdx.schema.json",
        "jsf-0.82.schema.json",
    )
    registry = Registry().with_resources(
        [(_load(n)["$id"], Resource.from_contents(_load(n))) for n in names]
    )
    return Draft7Validator(_load("cyclonedx-1.6.schema.json"), registry=registry)


def assert_valid(instance: Any, validator: Draft7Validator) -> None:
    """Fail with a readable message listing every schema violation."""
    errors = sorted(validator.iter_errors(instance), key=str)
    if errors:
        lines = [
            f"  - {list(e.absolute_path)}: {e.message}" for e in errors[:15]
        ]
        raise AssertionError(
            f"output failed schema validation ({len(errors)} error(s)):\n"
            + "\n".join(lines)
        )
