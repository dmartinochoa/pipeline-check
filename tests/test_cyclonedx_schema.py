"""CycloneDX 1.6 schema-compliance tests.

Validates the SBOM reporter's output against the official CycloneDX 1.6
JSON schema (vendored under ``tests/schemas/`` with its SPDX + JSF
sub-schemas). The BOM is consumed by external SBOM tooling, so spec
drift that internal tests miss can silently break those consumers.
"""
from __future__ import annotations

import json

import pytest

from pipeline_check.core.cyclonedx_reporter import report_cyclonedx
from pipeline_check.core.sbom import BuildDependency

from .schema_validators import assert_valid, cyclonedx_validator


def _deps():
    return [
        BuildDependency(
            name="actions/checkout",
            version="v4",
            dep_type="action",
            purl="pkg:github/actions/checkout@v4",
            provider="github",
            source=".github/workflows/ci.yml",
            pinned=False,
        ),
        BuildDependency(
            name="python",
            version="3.12-slim",
            dep_type="container",
            purl="pkg:docker/python@3.12-slim",
            provider="dockerfile",
            source="Dockerfile",
            pinned=True,
            digest="sha256:" + "a" * 64,
        ),
        BuildDependency(
            name="express",
            version="4.18.2",
            dep_type="npm",
            purl="pkg:npm/express@4.18.2",
            provider="npm",
            source="package.json",
            pinned=True,
        ),
    ]


def _validate(*args, **kwargs):
    assert_valid(json.loads(report_cyclonedx(*args, **kwargs)), cyclonedx_validator())


class TestCycloneDXSchemaCompliance:
    def test_empty_bom(self):
        _validate([], tool_version="1.9.0")

    def test_mixed_dependencies(self):
        _validate(_deps(), tool_version="1.9.0", scanned_path="repo")

    def test_no_tool_version(self):
        _validate(_deps())

    def test_single_pinned_with_digest(self):
        _validate([_deps()[1]], tool_version="1.9.0")


class TestCycloneDXSchemaEnforcement:
    """Confirm the validator rejects a malformed BOM, so a green run above
    is meaningful rather than a no-op."""

    def _bom(self):
        return json.loads(report_cyclonedx(_deps(), tool_version="1.9.0"))

    def test_wrong_bom_format_rejected(self):
        bom = self._bom()
        bom["bomFormat"] = "SPDX"
        with pytest.raises(AssertionError):
            assert_valid(bom, cyclonedx_validator())

    def test_missing_spec_version_rejected(self):
        bom = self._bom()
        del bom["specVersion"]
        with pytest.raises(AssertionError):
            assert_valid(bom, cyclonedx_validator())

    def test_invalid_component_type_rejected(self):
        bom = self._bom()
        bom["components"][0]["type"] = "not-a-real-type"
        with pytest.raises(AssertionError):
            assert_valid(bom, cyclonedx_validator())
