"""Per-rule tests for NUGET-011..015 (NuGet extended pack)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.nuget.base import (
    NuGetConfig,
    NuGetContext,
    NuGetSource,
    NuGetSourceMapping,
)
from pipeline_check.core.checks.nuget.pipelines import NuGetChecks


def _scan(tmp_path: pathlib.Path):
    ctx = NuGetContext.from_path(tmp_path)
    return {f.check_id: f for f in NuGetChecks(ctx).run()}


# ── NUGET-011 ──────────────────────────────────────────────────


class TestNUGET011SourceMappingWildcard:
    def test_fires_on_global_wildcard(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(NuGetSource(name="corp", url="https://corp"),),
            source_mappings=(
                NuGetSourceMapping(source="corp", patterns=("*",)),
            ),
        )
        ctx = NuGetContext(projects=[], configs=[cfg], locks=[])
        finding = next(
            f for f in NuGetChecks(ctx).run() if f.check_id == "NUGET-011"
        )
        assert not finding.passed

    def test_passes_on_explicit_prefixes(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(NuGetSource(name="corp", url="https://corp"),),
            source_mappings=(
                NuGetSourceMapping(
                    source="corp", patterns=("Corp.*", "Internal.*"),
                ),
            ),
        )
        ctx = NuGetContext(projects=[], configs=[cfg], locks=[])
        finding = next(
            f for f in NuGetChecks(ctx).run() if f.check_id == "NUGET-011"
        )
        assert finding.passed


# ── NUGET-012 ──────────────────────────────────────────────────


class TestNUGET012SignatureValidation:
    def test_passes_when_require(self, tmp_path):
        (tmp_path / "NuGet.config").write_text(
            '<configuration><config>'
            '<add key="signatureValidationMode" value="require" />'
            '</config></configuration>',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["NUGET-012"].passed

    def test_fires_when_absent(self, tmp_path):
        (tmp_path / "NuGet.config").write_text(
            '<configuration><packageSources>'
            '<add key="x" value="https://x" />'
            '</packageSources></configuration>',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["NUGET-012"].passed

    def test_fires_when_accept(self, tmp_path):
        (tmp_path / "NuGet.config").write_text(
            '<configuration><config>'
            '<add key="signatureValidationMode" value="accept" />'
            '</config></configuration>',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["NUGET-012"].passed


# ── NUGET-013 ──────────────────────────────────────────────────


class TestNUGET013DotnetToolsUnpinned:
    def test_fires_on_no_version(self, tmp_path):
        (tmp_path / "NuGet.config").write_text(
            '<configuration><packageSources>'
            '<add key="x" value="https://x" /></packageSources></configuration>',
            encoding="utf-8",
        )
        (tmp_path / ".config").mkdir()
        (tmp_path / ".config" / "dotnet-tools.json").write_text(
            '{"version":1,"isRoot":true,"tools":'
            '{"dotnet-ef":{"commands":["dotnet-ef"]}}}',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["NUGET-013"].passed

    def test_passes_with_version_pin(self, tmp_path):
        (tmp_path / "NuGet.config").write_text(
            '<configuration><packageSources>'
            '<add key="x" value="https://x" /></packageSources></configuration>',
            encoding="utf-8",
        )
        (tmp_path / ".config").mkdir()
        (tmp_path / ".config" / "dotnet-tools.json").write_text(
            '{"version":1,"isRoot":true,"tools":'
            '{"dotnet-ef":{"version":"8.0.10","commands":["dotnet-ef"]}}}',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["NUGET-013"].passed

    def test_passes_when_no_manifest(self, tmp_path):
        (tmp_path / "NuGet.config").write_text(
            '<configuration><packageSources>'
            '<add key="x" value="https://x" /></packageSources></configuration>',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["NUGET-013"].passed

    def test_fires_on_wildcard_version(self, tmp_path):
        (tmp_path / "NuGet.config").write_text(
            '<configuration><packageSources>'
            '<add key="x" value="https://x" /></packageSources></configuration>',
            encoding="utf-8",
        )
        (tmp_path / ".config").mkdir()
        (tmp_path / ".config" / "dotnet-tools.json").write_text(
            '{"version":1,"isRoot":true,"tools":'
            '{"dotnet-ef":{"version":"*","commands":["dotnet-ef"]}}}',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["NUGET-013"].passed


# ── NUGET-014 ──────────────────────────────────────────────────


class TestNUGET014SourceUrlCredentials:
    def test_fires_on_embedded_credentials(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(
                NuGetSource(
                    name="corp",
                    url="https://bot:secret@nexus.corp/nuget",
                ),
            ),
        )
        ctx = NuGetContext(projects=[], configs=[cfg], locks=[])
        finding = next(
            f for f in NuGetChecks(ctx).run() if f.check_id == "NUGET-014"
        )
        assert not finding.passed

    def test_passes_on_clean_url(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(
                NuGetSource(
                    name="corp", url="https://nexus.corp/nuget",
                ),
            ),
        )
        ctx = NuGetContext(projects=[], configs=[cfg], locks=[])
        finding = next(
            f for f in NuGetChecks(ctx).run() if f.check_id == "NUGET-014"
        )
        assert finding.passed

    def test_skips_env_var_placeholder(self):
        cfg = NuGetConfig(
            path="NuGet.config",
            sources=(
                NuGetSource(
                    name="corp",
                    url="https://${env:NUGET_TOKEN}@nexus.corp/nuget",
                ),
            ),
        )
        ctx = NuGetContext(projects=[], configs=[cfg], locks=[])
        finding = next(
            f for f in NuGetChecks(ctx).run() if f.check_id == "NUGET-014"
        )
        assert finding.passed


# ── NUGET-015 ──────────────────────────────────────────────────


class TestNUGET015VersionOverride:
    def test_fires_on_override_in_cpm_project(self, tmp_path):
        (tmp_path / "Directory.Packages.props").write_text(
            '<Project><PropertyGroup>'
            '<ManagePackageVersionsCentrally>true'
            '</ManagePackageVersionsCentrally></PropertyGroup>'
            '<ItemGroup>'
            '<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />'
            '</ItemGroup></Project>',
            encoding="utf-8",
        )
        (tmp_path / "app.csproj").write_text(
            '<Project><ItemGroup>'
            '<PackageReference Include="Newtonsoft.Json" '
            'VersionOverride="13.0.1" />'
            '</ItemGroup></Project>',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["NUGET-015"].passed

    def test_passes_when_no_override(self, tmp_path):
        (tmp_path / "Directory.Packages.props").write_text(
            '<Project><PropertyGroup>'
            '<ManagePackageVersionsCentrally>true'
            '</ManagePackageVersionsCentrally></PropertyGroup>'
            '<ItemGroup>'
            '<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />'
            '</ItemGroup></Project>',
            encoding="utf-8",
        )
        (tmp_path / "app.csproj").write_text(
            '<Project><ItemGroup>'
            '<PackageReference Include="Newtonsoft.Json" />'
            '</ItemGroup></Project>',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["NUGET-015"].passed

    def test_passes_when_not_central_managed(self, tmp_path):
        # No Directory.Packages.props => not CPM => override is a no-op.
        (tmp_path / "app.csproj").write_text(
            '<Project><ItemGroup>'
            '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" '
            'VersionOverride="13.0.1" />'
            '</ItemGroup></Project>',
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["NUGET-015"].passed
