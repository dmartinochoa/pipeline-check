"""Regression tests from the 2026-07 rule audit (NuGet)."""
from __future__ import annotations

import datetime as dt

from pipeline_check.core.checks.nuget.base import (
    NuGetConfig,
    NuGetContext,
    NuGetLock,
    NuGetPackageRef,
    NuGetProject,
    NuGetSource,
)
from pipeline_check.core.checks.nuget.rules import nuget006_missing_lockfile as n6
from pipeline_check.core.checks.nuget.rules import nuget008_cooldown as n8
from pipeline_check.core.checks.nuget.rules import nuget009_osv_advisory as n9
from pipeline_check.core.checks.nuget.rules import (
    nuget014_source_url_credentials as n14,
)


class TestAudit202607LowNuget:
    def test_nuget014_percent_env_placeholder_not_a_credential(self):
        cfg = NuGetConfig(path="nuget.config", sources=(
            NuGetSource(name="nexus",
                        url="https://user:%NUGET_TOKEN%@nexus.corp/nuget"),))
        assert n14.check(cfg).passed is True
        # a literal embedded password still fires
        cfg2 = NuGetConfig(path="nuget.config", sources=(
            NuGetSource(name="nexus",
                        url="https://user:hardcodedpw@nexus.corp/nuget"),))
        assert n14.check(cfg2).passed is False

    def test_nuget006_lock_must_be_co_located(self):
        proj_a = NuGetProject(path="a/a.csproj")
        proj_b = NuGetProject(path="b/b.csproj")
        ctx = NuGetContext(
            projects=[proj_a, proj_b], configs=[],
            locks=[NuGetLock(path="a/packages.lock.json")],
        )
        assert n6.check(proj_a, ctx).passed is True
        assert n6.check(proj_b, ctx).passed is False

    def test_nuget008_recent_publish_fires(self):
        proj = NuGetProject(path="a/a.csproj", package_refs=(
            NuGetPackageRef(name="PopularLib", version="5.4.0"),))
        ctx = NuGetContext(projects=[proj], configs=[], locks=[])
        ctx.publish_times = {
            "popularlib": {"5.4.0": dt.datetime.now(dt.UTC) - dt.timedelta(days=2)}
        }
        assert n8.check(proj, ctx).passed is False

    def test_nuget009_osv_advisory_fires(self):
        proj = NuGetProject(path="a/a.csproj", package_refs=(
            NuGetPackageRef(name="PopularLib", version="5.4.0"),))
        ctx = NuGetContext(projects=[proj], configs=[], locks=[])
        ctx.osv_advisories = {("popularlib", "5.4.0"): [{"id": "GHSA-xxxx"}]}
        assert n9.check(proj, ctx).passed is False


class TestAudit202607LowNugetC2:
    """2026-07 audit LOW findings (nuget_c2 chunk)."""

    def test_nuget018_user_pkg_property_import_not_flagged(self):
        import xml.etree.ElementTree as ET

        from pipeline_check.core.checks.nuget.rules import (
            nuget018_build_time_msbuild_exec as n18,
        )
        # A user-defined $(PkgOutputPath) property is not a generated
        # package build-path import.
        user = ET.fromstring(
            "<Project>"
            "<PropertyGroup><PkgOutputPath>x</PkgOutputPath></PropertyGroup>"
            "<Import Project='$(PkgOutputPath)/common.targets' />"
            "</Project>"
        )
        assert n18._offenders(user) == []
        # The GeneratePathProperty-generated $(Pkg<Id>) import still fires.
        generated = ET.fromstring(
            "<Project>"
            "<Import Project='$(PkgNewtonsoft_Json)/build/x.targets' />"
            "</Project>"
        )
        assert n18._offenders(generated)

    def test_nuget017_numeric_value_leaves_gallery_enabled(self, tmp_path):
        from pipeline_check.core.checks.nuget.rules import (
            nuget017_public_gallery_not_disabled as n17,
        )
        cfg_path = tmp_path / "nuget.config"
        cfg_path.write_text(
            "<configuration><disabledPackageSources>"
            "<add key=\"nuget.org\" value=\"1\" />"
            "</disabledPackageSources></configuration>",
            encoding="utf-8",
        )
        cfg = NuGetConfig(path=str(cfg_path), sources=(
            NuGetSource(name="nuget.org", url="https://api.nuget.org/v3/index.json"),
            NuGetSource(name="corp", url="https://gems.corp/nuget"),
        ))
        ctx = NuGetContext(projects=[], configs=[cfg], locks=[])
        # value="1" is not bool.TryParse-able, so the gallery is still
        # enabled and the rule must fire.
        assert n17.check(cfg, ctx).passed is False
        # value="true" genuinely disables it -> pass.
        cfg_path.write_text(
            "<configuration><disabledPackageSources>"
            "<add key=\"nuget.org\" value=\"true\" />"
            "</disabledPackageSources></configuration>",
            encoding="utf-8",
        )
        assert n17.check(cfg, ctx).passed is True
