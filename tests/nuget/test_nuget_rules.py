"""Tests for the NuGet provider rules."""
from __future__ import annotations

from pipeline_check.core.checks.nuget.base import (
    NuGetConfig,
    NuGetContext,
    NuGetLock,
    NuGetPackageRef,
    NuGetProject,
    NuGetSource,
    NuGetSourceMapping,
)

from .conftest import run_check


# ── NUGET-001: floating range ──────────────────────────────────────────


class TestNuget001:
    def test_fails_on_bracket_range(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Newtonsoft.Json", "[13.0,14.0)"),),
        )
        f = run_check([proj], check_id="NUGET-001")
        assert not f.passed
        assert "Newtonsoft.Json" in f.description

    def test_fails_on_star(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Serilog", "*"),),
        )
        f = run_check([proj], check_id="NUGET-001")
        assert not f.passed

    def test_passes_on_exact_version(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Serilog", "3.1.1"),),
        )
        assert run_check([proj], check_id="NUGET-001").passed


# ── NUGET-002: wildcard prerelease ─────────────────────────────────────


class TestNuget002:
    def test_fails_on_dash_star(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("xunit", "2.6-*"),),
        )
        f = run_check([proj], check_id="NUGET-002")
        assert not f.passed

    def test_passes_on_stable(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("xunit", "2.6.1"),),
        )
        assert run_check([proj], check_id="NUGET-002").passed


# ── NUGET-003: missing version ─────────────────────────────────────────


class TestNuget003:
    def test_fails_without_central_management(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Serilog", None),),
            is_central_managed=False,
        )
        f = run_check([proj], check_id="NUGET-003")
        assert not f.passed

    def test_passes_with_central_management(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Serilog", None),),
            is_central_managed=True,
        )
        assert run_check([proj], check_id="NUGET-003").passed

    def test_passes_when_version_present(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Serilog", "3.1.1"),),
        )
        assert run_check([proj], check_id="NUGET-003").passed


# ── NUGET-004: HTTP source ─────────────────────────────────────────────


class TestNuget004:
    def test_fails_on_http(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(NuGetSource("internal", "http://pkgs.corp.com/nuget"),),
        )
        f = run_check(configs=[cfg], check_id="NUGET-004")
        assert not f.passed
        assert "http://" in f.description

    def test_passes_on_https(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(NuGetSource("nuget.org", "https://api.nuget.org/v3/index.json"),),
        )
        assert run_check(configs=[cfg], check_id="NUGET-004").passed


# ── NUGET-005: compromised version ─────────────────────────────────────


class TestNuget005:
    def test_fails_on_known_compromised(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("SolarWinds.Orion.Core", "2020.2.1"),),
        )
        f = run_check([proj], check_id="NUGET-005")
        assert not f.passed
        assert "SUNBURST" in f.description or "CVE" in f.description

    def test_passes_on_clean_version(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Newtonsoft.Json", "13.0.3"),),
        )
        assert run_check([proj], check_id="NUGET-005").passed


# ── NUGET-006: missing lockfile ────────────────────────────────────────


class TestNuget006:
    def test_fails_without_lockfile(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Serilog", "3.1.1"),),
        )
        ctx = NuGetContext([proj], [], [])
        f = run_check(check_id="NUGET-006", ctx=ctx)
        assert not f.passed

    def test_passes_with_lockfile(self):
        proj = NuGetProject(
            path="app.csproj",
            package_refs=(NuGetPackageRef("Serilog", "3.1.1"),),
        )
        lock = NuGetLock(path="packages.lock.json", packages={"Serilog": "3.1.1"})
        ctx = NuGetContext([proj], [], [lock])
        f = run_check(check_id="NUGET-006", ctx=ctx)
        assert f.passed


# ── NUGET-007: missing source mapping ──────────────────────────────────


class TestNuget007:
    def test_fails_multiple_sources_no_mapping(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(
                NuGetSource("nuget.org", "https://api.nuget.org/v3/index.json"),
                NuGetSource("internal", "https://pkgs.corp.com/nuget"),
            ),
        )
        f = run_check(configs=[cfg], check_id="NUGET-007")
        assert not f.passed

    def test_passes_with_mapping(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(
                NuGetSource("nuget.org", "https://api.nuget.org/v3/index.json"),
                NuGetSource("internal", "https://pkgs.corp.com/nuget"),
            ),
            source_mappings=(
                NuGetSourceMapping("nuget.org", ("*",)),
                NuGetSourceMapping("internal", ("Corp.*",)),
            ),
        )
        assert run_check(configs=[cfg], check_id="NUGET-007").passed

    def test_passes_single_source(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(NuGetSource("nuget.org", "https://api.nuget.org/v3/index.json"),),
        )
        assert run_check(configs=[cfg], check_id="NUGET-007").passed


# ── Context parsing ────────────────────────────────────────────────────


class TestNuGetContextParsing:
    def test_csproj_parsed(self, tmp_path):
        csproj = tmp_path / "app.csproj"
        csproj.write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            "  <ItemGroup>\n"
            '    <PackageReference Include="Serilog" Version="3.1.1" />\n'
            "  </ItemGroup>\n"
            "</Project>\n",
            encoding="utf-8",
        )
        ctx = NuGetContext.from_path(tmp_path)
        assert len(ctx.projects) == 1
        assert ctx.projects[0].package_refs[0].name == "Serilog"

    def test_nuget_config_parsed(self, tmp_path):
        cfg = tmp_path / "NuGet.config"
        cfg.write_text(
            "<configuration>\n"
            "  <packageSources>\n"
            '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />\n'
            "  </packageSources>\n"
            "</configuration>\n",
            encoding="utf-8",
        )
        ctx = NuGetContext.from_path(tmp_path)
        assert len(ctx.configs) == 1
        assert ctx.configs[0].sources[0].url == "https://api.nuget.org/v3/index.json"

    def test_lock_json_parsed(self, tmp_path):
        lock = tmp_path / "packages.lock.json"
        lock.write_text(
            '{"version": 1, "dependencies": {"net8.0": '
            '{"Serilog": {"resolved": "3.1.1"}}}}',
            encoding="utf-8",
        )
        ctx = NuGetContext.from_path(tmp_path)
        assert len(ctx.locks) == 1
        assert ctx.locks[0].packages["Serilog"] == "3.1.1"

    def test_central_props_resolves_versions(self, tmp_path):
        props = tmp_path / "Directory.Packages.props"
        props.write_text(
            "<Project>\n"
            "  <ItemGroup>\n"
            '    <PackageVersion Include="Serilog" Version="3.1.1" />\n'
            "  </ItemGroup>\n"
            "</Project>\n",
            encoding="utf-8",
        )
        csproj = tmp_path / "app.csproj"
        csproj.write_text(
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            "  <ItemGroup>\n"
            '    <PackageReference Include="Serilog" />\n'
            "  </ItemGroup>\n"
            "</Project>\n",
            encoding="utf-8",
        )
        ctx = NuGetContext.from_path(tmp_path)
        assert ctx.projects[0].package_refs[0].version == "3.1.1"
        assert ctx.projects[0].is_central_managed

    def test_malformed_xml_produces_warning(self, tmp_path):
        bad = tmp_path / "bad.csproj"
        bad.write_text("this is not xml <<<", encoding="utf-8")
        ctx = NuGetContext.from_path(tmp_path)
        assert ctx.files_skipped >= 1
        assert any("parse error" in w for w in ctx.warnings)
