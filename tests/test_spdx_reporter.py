"""Tests for the SPDX 2.3 SBOM reporter."""
from __future__ import annotations

import json
import re

from pipeline_check.core.sbom import BuildDependency
from pipeline_check.core.spdx_reporter import report_spdx

_SPDXID_RE = re.compile(r"^SPDXRef-[0-9a-zA-Z.-]+$")


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
            pinned=True,
            digest="sha256:" + "a" * 64,
        ),
        BuildDependency(
            name="@scope/pkg",
            version="1.0.0",
            dep_type="npm",
            purl="pkg:npm/%40scope/pkg@1.0.0",
            provider="npm",
            source="package.json",
            pinned=True,
        ),
    ]


class TestSPDXReporter:
    def test_valid_json_and_version(self) -> None:
        doc = json.loads(report_spdx(_sample_deps(), tool_version="1.4.0"))
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert doc["SPDXID"] == "SPDXRef-DOCUMENT"

    def test_creation_info(self) -> None:
        doc = json.loads(report_spdx(_sample_deps(), tool_version="9.9.9"))
        ci = doc["creationInfo"]
        assert any("pipeline-check-9.9.9" in c for c in ci["creators"])
        assert ci["created"].endswith("Z")

    def test_document_namespace_is_a_uri(self) -> None:
        doc = json.loads(report_spdx(_sample_deps(), scanned_path="/my/proj"))
        assert doc["documentNamespace"].startswith("https://")
        assert doc["name"] == "/my/proj"

    def test_package_count_and_ids(self) -> None:
        doc = json.loads(report_spdx(_sample_deps()))
        pkgs = doc["packages"]
        assert len(pkgs) == 3
        ids = [p["SPDXID"] for p in pkgs]
        # Schema-valid and unique (no ``_`` even though bom_ref allows it).
        assert all(_SPDXID_RE.match(i) for i in ids)
        assert all("_" not in i for i in ids)
        assert len(ids) == len(set(ids))

    def test_packages_have_required_fields(self) -> None:
        doc = json.loads(report_spdx(_sample_deps()))
        for p in doc["packages"]:
            assert p["name"]
            assert "versionInfo" in p
            assert p["downloadLocation"] == "NOASSERTION"
            assert p["filesAnalyzed"] is False

    def test_purl_external_ref(self) -> None:
        doc = json.loads(report_spdx(_sample_deps()))
        for p in doc["packages"]:
            ref = p["externalRefs"][0]
            assert ref["referenceCategory"] == "PACKAGE-MANAGER"
            assert ref["referenceType"] == "purl"
            assert ref["referenceLocator"].startswith("pkg:")

    def test_digest_becomes_checksum(self) -> None:
        doc = json.loads(report_spdx(_sample_deps()))
        py = next(p for p in doc["packages"] if p["name"] == "python")
        chk = py["checksums"][0]
        assert chk["algorithm"] == "SHA256"
        assert chk["checksumValue"] == "a" * 64
        # The action (no digest) carries no checksums key.
        co = next(p for p in doc["packages"] if p["name"] == "actions/checkout")
        assert "checksums" not in co

    def test_describes_relationships(self) -> None:
        doc = json.loads(report_spdx(_sample_deps()))
        rels = doc["relationships"]
        assert len(rels) == 3
        pkg_ids = {p["SPDXID"] for p in doc["packages"]}
        for r in rels:
            assert r["spdxElementId"] == "SPDXRef-DOCUMENT"
            assert r["relationshipType"] == "DESCRIBES"
            assert r["relatedSpdxElement"] in pkg_ids

    def test_provider_metadata_in_comment(self) -> None:
        doc = json.loads(report_spdx(_sample_deps()))
        co = next(p for p in doc["packages"] if p["name"] == "actions/checkout")
        assert "provider=github" in co["comment"]
        assert "pinned=false" in co["comment"]

    def test_deduplicates(self) -> None:
        doc = json.loads(report_spdx(_sample_deps() + _sample_deps()))
        assert len(doc["packages"]) == 3

    def test_empty_deps(self) -> None:
        doc = json.loads(report_spdx([]))
        assert doc["packages"] == []
        assert doc["relationships"] == []
        assert doc["spdxVersion"] == "SPDX-2.3"
