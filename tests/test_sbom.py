"""Unit tests for SBOM data model and PURL generation."""
from __future__ import annotations

from pipeline_check.core.sbom import (
    BuildDependency,
    deduplicate,
    make_docker_purl,
    make_github_purl,
    make_npm_purl,
    make_pypi_purl,
    parse_docker_ref,
    parse_requirement_line,
)


class TestBuildDependency:
    def test_bom_ref_sanitizes_special_chars(self) -> None:
        dep = BuildDependency(
            name="actions/checkout",
            version="v4",
            dep_type="action",
            purl="pkg:github/actions/checkout@v4",
            provider="github",
            source=".github/workflows/ci.yml",
            pinned=False,
        )
        ref = dep.bom_ref()
        assert "/" not in ref
        assert ref == "actions-checkout-v4"

    def test_bom_ref_truncates_long_names(self) -> None:
        dep = BuildDependency(
            name="a" * 200,
            version="1.0.0",
            dep_type="npm",
            purl="pkg:npm/a@1.0.0",
            provider="npm",
            source="package.json",
            pinned=True,
        )
        assert len(dep.bom_ref()) <= 120


class TestGitHubPurl:
    def test_basic_action(self) -> None:
        assert make_github_purl("actions", "checkout", "v4") == (
            "pkg:github/actions/checkout@v4"
        )

    def test_sha_ref(self) -> None:
        sha = "a5ac7e51b41094c92402da3b24376905380afc29"
        purl = make_github_purl("actions", "checkout", sha)
        assert purl == f"pkg:github/actions/checkout@{sha}"

    def test_subpath(self) -> None:
        purl = make_github_purl(
            "owner", "repo", "v1",
            path=".github/workflows/release.yml",
        )
        assert "subpath=" in purl


class TestDockerPurl:
    def test_simple_image(self) -> None:
        assert make_docker_purl("python", "3.12") == "pkg:docker/python@3.12"

    def test_namespaced_image(self) -> None:
        purl = make_docker_purl("library/python", "3.12-slim")
        assert "library" in purl
        assert "python" in purl

    def test_registry_image(self) -> None:
        purl = make_docker_purl("ghcr.io/owner/app", "latest")
        assert purl.startswith("pkg:docker/ghcr.io")

    def test_digest(self) -> None:
        purl = make_docker_purl("python", "", "sha256:abc123")
        assert "sha256%3Aabc123" in purl


class TestNpmPurl:
    def test_simple_package(self) -> None:
        assert make_npm_purl("express", "4.18.2") == (
            "pkg:npm/express@4.18.2"
        )

    def test_scoped_package(self) -> None:
        purl = make_npm_purl("@types/node", "20.0.0")
        assert purl == "pkg:npm/%40types/node@20.0.0"


class TestPypiPurl:
    def test_simple_package(self) -> None:
        assert make_pypi_purl("requests", "2.31.0") == (
            "pkg:pypi/requests@2.31.0"
        )

    def test_normalizes_name(self) -> None:
        purl = make_pypi_purl("my_Package.Name", "1.0")
        assert "my-package-name" in purl


class TestParseDockerRef:
    def test_image_with_tag(self) -> None:
        assert parse_docker_ref("python:3.12") == ("python", "3.12", "")

    def test_image_with_digest(self) -> None:
        img, tag, digest = parse_docker_ref("python@sha256:abc")
        assert img == "python"
        assert digest == "sha256:abc"

    def test_image_with_tag_and_digest(self) -> None:
        img, tag, digest = parse_docker_ref("python:3.12@sha256:abc")
        assert img == "python"
        assert tag == "3.12"
        assert digest == "sha256:abc"

    def test_registry_image(self) -> None:
        img, tag, _ = parse_docker_ref("ghcr.io/owner/app:v1")
        assert img == "ghcr.io/owner/app"
        assert tag == "v1"

    def test_no_tag(self) -> None:
        img, tag, digest = parse_docker_ref("python")
        assert img == "python"
        assert tag == ""
        assert digest == ""


class TestParseRequirementLine:
    def test_pinned(self) -> None:
        assert parse_requirement_line("requests==2.31.0") == (
            "requests", "2.31.0",
        )

    def test_gte(self) -> None:
        assert parse_requirement_line("flask>=2.0") == ("flask", "2.0")

    def test_extras(self) -> None:
        result = parse_requirement_line("requests[security]>=2.25")
        assert result is not None
        assert result[0] == "requests"

    def test_comment_line(self) -> None:
        assert parse_requirement_line("# comment") is None

    def test_option_line(self) -> None:
        assert parse_requirement_line("--index-url https://pypi.org") is None

    def test_unpinned(self) -> None:
        assert parse_requirement_line("requests") is None

    def test_empty(self) -> None:
        assert parse_requirement_line("") is None


class TestDeduplicate:
    def test_removes_duplicates_by_purl(self) -> None:
        dep = BuildDependency(
            name="actions/checkout", version="v4",
            dep_type="action", purl="pkg:github/actions/checkout@v4",
            provider="github", source="ci.yml", pinned=False,
        )
        result = deduplicate([dep, dep, dep])
        assert len(result) == 1

    def test_preserves_different_purls(self) -> None:
        d1 = BuildDependency(
            name="a", version="1", dep_type="npm",
            purl="pkg:npm/a@1", provider="npm", source="p.json",
            pinned=True,
        )
        d2 = BuildDependency(
            name="b", version="2", dep_type="npm",
            purl="pkg:npm/b@2", provider="npm", source="p.json",
            pinned=True,
        )
        assert len(deduplicate([d1, d2])) == 2
