"""Tests for the ``post_filter()`` remote-resolution path on the
four dependency-supply-chain providers (maven, npm, nuget, pypi),
the ``build_dependencies()`` SBOM extraction on npm and pypi,
and the NuGet ``_is_range()`` helper.

All network calls are mocked so these run fully offline.
"""
from __future__ import annotations

import datetime as dt
from unittest.mock import patch

import pytest

from pipeline_check.core import providers as _providers

# ── _is_range helper (nuget) ──────────────────────────────────────


@pytest.mark.parametrize("version,expected", [
    ("6.0.0", False),
    ("", False),
    ("[1.0,2.0)", True),
    ("(,5.0]", True),
    ("*", True),
    ("1.*", True),
    ("1.0.0-preview", False),
])
def test_nuget_is_range(version: str, expected: bool) -> None:
    from pipeline_check.core.providers.nuget import _is_range
    assert _is_range(version) is expected


# ── post_filter: resolve_remote=False is a no-op ──────────────────


@pytest.mark.parametrize("provider_name,path_kw,file_name,content", [
    (
        "maven", "maven_path", "pom.xml",
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>app</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.junit</groupId>\n"
        "      <artifactId>junit</artifactId>\n"
        "      <version>5.10.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    ),
    (
        "npm", "npm_path", "package.json",
        '{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}'
    ),
    (
        "nuget", "nuget_path", "app.csproj",
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        "  </ItemGroup>\n"
        "</Project>\n",
    ),
    (
        "pypi", "pypi_path", "requirements.txt",
        "requests==2.31.0\nclick>=8.0\n"
    ),
])
def test_post_filter_noop_when_resolve_remote_false(
    tmp_path, provider_name, path_kw, file_name, content,
):
    (tmp_path / file_name).write_text(content)
    provider = _providers.get(provider_name)
    path_val = str(tmp_path) if provider_name == "nuget" else str(tmp_path / file_name)
    ctx = provider.build_context(**{path_kw: path_val})
    provider.post_filter(ctx, resolve_remote=False)
    assert ctx.publish_times == {}
    assert ctx.osv_advisories == {}


# ── post_filter: maven with resolve_remote=True ──────────────────


def test_maven_post_filter_populates_publish_times_and_osv(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>app</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n"
        "      <version>2.17.1</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    fake_times = {
        "org.apache.logging.log4j:log4j-core": {
            "2.17.1": dt.datetime(2021, 12, 28, tzinfo=dt.UTC),
        },
    }
    fake_osv = {
        ("org.apache.logging.log4j:log4j-core", "2.17.1"): [],
    }
    provider = _providers.get("maven")
    ctx = provider.build_context(maven_path=str(pom))
    with (
        patch(
            "pipeline_check.core.providers.maven.fetch_publish_times",
            return_value=(fake_times, []),
        ) as mock_fetch,
        patch(
            "pipeline_check.core.checks._primitives.osv_fetcher.query_osv_batch",
            return_value=fake_osv,
        ) as mock_osv,
    ):
        provider.post_filter(ctx, resolve_remote=True, no_cache=True)
    mock_fetch.assert_called_once()
    mock_osv.assert_called_once()
    assert ctx.publish_times == fake_times
    assert ctx.osv_advisories == fake_osv


# ── post_filter: npm with resolve_remote=True ─────────────────────


def test_npm_post_filter_populates_publish_times_and_osv(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"name":"my-app","version":"1.0.0",'
        '"dependencies":{"lodash":"4.17.21"}}'
    )
    fake_times = {
        "lodash": {"4.17.21": dt.datetime(2021, 2, 20, tzinfo=dt.UTC)},
    }
    fake_osv: dict[tuple[str, str], list[object]] = {}
    provider = _providers.get("npm")
    ctx = provider.build_context(npm_path=str(pkg))
    with (
        patch(
            "pipeline_check.core.providers.npm.fetch_publish_times",
            return_value=(fake_times, []),
        ) as mock_fetch,
        patch(
            "pipeline_check.core.checks._primitives.osv_fetcher.query_osv_batch",
            return_value=fake_osv,
        ),
    ):
        provider.post_filter(ctx, resolve_remote=True, no_cache=True)
    mock_fetch.assert_called_once()
    assert ctx.publish_times == fake_times


# ── post_filter: pypi with resolve_remote=True ────────────────────


def test_pypi_post_filter_populates_publish_times_and_osv(tmp_path):
    from pipeline_check.core.checks._primitives.scorecard import (
        ScorecardResult,
    )

    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nclick>=8.0\n")
    fake_times = {
        "requests": {"2.31.0": dt.datetime(2023, 5, 22, tzinfo=dt.UTC)},
    }
    fake_osv: dict[tuple[str, str], list[object]] = {
        ("requests", "2.31.0"): [],
    }
    fake_prov = {"requests": False, "click": True}
    fake_slugs = {"requests": "psf/requests"}
    fake_scorecards = {
        "requests": ScorecardResult(score=3.0, dangerous_workflow_failed=False),
    }
    provider = _providers.get("pypi")
    ctx = provider.build_context(pypi_path=str(req))
    # Patch every network entry point: publish-times, OSV, and the
    # behavioral-signal passes (provenance / repo-slug / Scorecard).
    # The test must never touch the real registry / Scorecard API.
    with (
        patch(
            "pipeline_check.core.providers.pypi.fetch_publish_times",
            return_value=(fake_times, []),
        ) as mock_fetch,
        patch(
            "pipeline_check.core.checks._primitives.osv_fetcher.query_osv_batch",
            return_value=fake_osv,
        ) as mock_osv,
        patch(
            "pipeline_check.core.providers.pypi.fetch_provenance",
            return_value=(fake_prov, []),
        ) as mock_prov,
        patch(
            "pipeline_check.core.providers.pypi.fetch_repo_slugs",
            return_value=(fake_slugs, []),
        ) as mock_slugs,
        patch(
            "pipeline_check.core.checks._primitives.scorecard.fetch_scorecards",
            return_value=(fake_scorecards, []),
        ) as mock_sc,
    ):
        provider.post_filter(ctx, resolve_remote=True, no_cache=True)
    mock_fetch.assert_called_once()
    mock_osv.assert_called_once()
    mock_prov.assert_called_once()
    mock_slugs.assert_called_once()
    mock_sc.assert_called_once()
    assert ctx.publish_times == fake_times
    assert ctx.osv_advisories == fake_osv
    assert ctx.provenance == fake_prov
    assert ctx.scorecards == fake_scorecards


# ── post_filter: nuget with resolve_remote=True ──────────────────


def test_nuget_post_filter_populates_osv(tmp_path):
    csproj = tmp_path / "app.csproj"
    csproj.write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    fake_osv: dict[tuple[str, str], list[object]] = {
        ("newtonsoft.json", "13.0.3"): [],
    }
    provider = _providers.get("nuget")
    ctx = provider.build_context(nuget_path=str(tmp_path))
    with patch(
        "pipeline_check.core.checks._primitives.osv_fetcher.query_osv_batch",
        return_value=fake_osv,
    ) as mock_osv:
        provider.post_filter(ctx, resolve_remote=True, no_cache=True)
    mock_osv.assert_called_once()
    assert ctx.osv_advisories == fake_osv


def test_nuget_post_filter_skips_ranges(tmp_path):
    csproj = tmp_path / "app.csproj"
    csproj.write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Range.Pkg" Version="[1.0,2.0)" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )
    provider = _providers.get("nuget")
    ctx = provider.build_context(nuget_path=str(tmp_path))
    with patch(
        "pipeline_check.core.checks._primitives.osv_fetcher.query_osv_batch",
    ) as mock_osv:
        provider.post_filter(ctx, resolve_remote=True, no_cache=True)
    mock_osv.assert_not_called()


# ── post_filter: maven skips settings.xml for OSV ─────────────────


def test_maven_post_filter_skips_settings_xml(tmp_path):
    settings = tmp_path / "settings.xml"
    settings.write_text(
        '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">\n'
        "  <mirrors>\n"
        "    <mirror><id>m</id><mirrorOf>*</mirrorOf>"
        "<url>https://nexus.example.com</url></mirror>\n"
        "  </mirrors>\n"
        "</settings>\n"
    )
    provider = _providers.get("maven")
    ctx = provider.build_context(maven_path=str(settings))
    with (
        patch(
            "pipeline_check.core.providers.maven.fetch_publish_times",
        ) as mock_fetch,
        patch(
            "pipeline_check.core.checks._primitives.osv_fetcher.query_osv_batch",
        ) as mock_osv,
    ):
        provider.post_filter(ctx, resolve_remote=True, no_cache=True)
    mock_fetch.assert_not_called()
    mock_osv.assert_not_called()


# ── post_filter: warnings propagate ───────────────────────────────


def test_maven_post_filter_warnings_propagate(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>app</artifactId>\n"
        "  <version>1.0.0</version>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>com.bad</groupId>\n"
        "      <artifactId>lib</artifactId>\n"
        "      <version>1.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    provider = _providers.get("maven")
    ctx = provider.build_context(maven_path=str(pom))
    with (
        patch(
            "pipeline_check.core.providers.maven.fetch_publish_times",
            return_value=({}, ["fetch failed for com.bad:lib"]),
        ),
        patch(
            "pipeline_check.core.checks._primitives.osv_fetcher.query_osv_batch",
            return_value={},
        ),
    ):
        provider.post_filter(ctx, resolve_remote=True, no_cache=True)
    assert "fetch failed for com.bad:lib" in ctx.warnings


# ── build_dependencies: npm ───────────────────────────────────────


def test_npm_build_dependencies(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        '{"name":"app","version":"1.0.0",'
        '"dependencies":{"react":"^18.2.0","lodash":"4.17.21"},'
        '"devDependencies":{"jest":"^29.0.0"}}'
    )
    provider = _providers.get("npm")
    ctx = provider.build_context(npm_path=str(pkg))
    deps = provider.build_dependencies(ctx)
    assert len(deps) == 3
    by_name = {d.name: d for d in deps}
    assert by_name["react"].version == "18.2.0"
    assert by_name["react"].pinned is False
    assert by_name["lodash"].version == "4.17.21"
    assert by_name["lodash"].pinned is True
    assert by_name["jest"].dep_type == "npm"
    assert all(d.purl.startswith("pkg:npm/") for d in deps)


def test_npm_build_dependencies_empty_manifest(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text('{"name":"bare","version":"0.0.1"}')
    provider = _providers.get("npm")
    ctx = provider.build_context(npm_path=str(pkg))
    assert provider.build_dependencies(ctx) == []


# ── build_dependencies: pypi ──────────────────────────────────────


def test_pypi_build_dependencies(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nclick>=8.0\nPyYAML==6.0\n")
    provider = _providers.get("pypi")
    ctx = provider.build_context(pypi_path=str(req))
    deps = provider.build_dependencies(ctx)
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].pinned is True
    assert by_name["click"].pinned is False
    assert by_name["PyYAML"].dep_type == "pypi"
    assert all(d.purl.startswith("pkg:pypi/") for d in deps)


def test_pypi_build_dependencies_empty(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# only comments\n\n")
    provider = _providers.get("pypi")
    ctx = provider.build_context(pypi_path=str(req))
    assert provider.build_dependencies(ctx) == []
