"""Tests for the CycloneDX 1.6 SBOM reporter."""
from __future__ import annotations

import json

from pipeline_check.core.cyclonedx_reporter import report_cyclonedx
from pipeline_check.core.sbom import BuildDependency


def _sample_deps() -> list[BuildDependency]:
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
            pinned=False,
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


class TestCycloneDXReporter:
    def test_valid_json(self) -> None:
        text = report_cyclonedx(_sample_deps(), tool_version="1.4.0")
        bom = json.loads(text)
        assert isinstance(bom, dict)

    def test_spec_version(self) -> None:
        bom = json.loads(report_cyclonedx(_sample_deps()))
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"
        assert bom["version"] == 1

    def test_metadata_tool(self) -> None:
        bom = json.loads(report_cyclonedx(_sample_deps(), tool_version="1.4.0"))
        tools = bom["metadata"]["tools"]["components"]
        assert any(t["name"] == "pipeline-check" for t in tools)
        assert any(t["version"] == "1.4.0" for t in tools)

    def test_component_count(self) -> None:
        bom = json.loads(report_cyclonedx(_sample_deps()))
        assert len(bom["components"]) == 3

    def test_component_types(self) -> None:
        bom = json.loads(report_cyclonedx(_sample_deps()))
        types = {c["type"] for c in bom["components"]}
        assert "library" in types
        assert "container" in types

    def test_purl_present(self) -> None:
        bom = json.loads(report_cyclonedx(_sample_deps()))
        for comp in bom["components"]:
            assert "purl" in comp
            assert comp["purl"].startswith("pkg:")

    def test_properties_present(self) -> None:
        bom = json.loads(report_cyclonedx(_sample_deps()))
        for comp in bom["components"]:
            props = {p["name"]: p["value"] for p in comp["properties"]}
            assert "pipeline-check:provider" in props
            assert "pipeline-check:kind" in props
            assert "pipeline-check:source" in props
            assert "pipeline-check:pinned" in props

    def test_deduplicates(self) -> None:
        deps = _sample_deps() + _sample_deps()
        bom = json.loads(report_cyclonedx(deps))
        assert len(bom["components"]) == 3

    def test_empty_deps(self) -> None:
        bom = json.loads(report_cyclonedx([]))
        assert bom["components"] == []
        assert bom["bomFormat"] == "CycloneDX"

    def test_bom_ref_unique(self) -> None:
        bom = json.loads(report_cyclonedx(_sample_deps()))
        refs = [c["bom-ref"] for c in bom["components"]]
        assert len(refs) == len(set(refs))

    def test_scanned_path_in_metadata(self) -> None:
        bom = json.loads(report_cyclonedx(
            _sample_deps(), scanned_path="/my/project",
        ))
        assert bom["metadata"]["component"]["name"] == "/my/project"
