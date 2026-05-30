"""Tests for NUGET-017 (public gallery active alongside a private feed)."""
from __future__ import annotations

import pathlib

from pipeline_check.core.checks.nuget.base import NuGetContext
from pipeline_check.core.checks.nuget.pipelines import NuGetChecks


def _scan(tmp_path: pathlib.Path, config_body: str):
    (tmp_path / "NuGet.config").write_text(
        '<?xml version="1.0"?>\n<configuration>\n'
        f"{config_body}</configuration>\n",
        encoding="utf-8",
    )
    ctx = NuGetContext.from_path(tmp_path)
    return {f.check_id: f for f in NuGetChecks(ctx).run()}

_INTERNAL = '    <add key="internal" value="https://nuget.corp.local/v3/index.json" />\n'
_GALLERY = '    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />\n'


class TestNuget017PublicGalleryNotDisabled:
    def test_both_feeds_active_fails(self, tmp_path):
        findings = _scan(tmp_path, (
            "  <packageSources>\n    <clear />\n"
            + _INTERNAL + _GALLERY + "  </packageSources>\n"
        ))
        assert not findings["NUGET-017"].passed
        # Assert on a non-host substring (a ``"<host>" in url``-shaped
        # check trips CodeQL's incomplete-url-sanitization query).
        assert "public gallery" in findings["NUGET-017"].description

    def test_gallery_disabled_passes(self, tmp_path):
        findings = _scan(tmp_path, (
            "  <packageSources>\n    <clear />\n"
            + _INTERNAL + _GALLERY + "  </packageSources>\n"
            "  <disabledPackageSources>\n"
            '    <add key="nuget.org" value="true" />\n'
            "  </disabledPackageSources>\n"
        ))
        assert findings["NUGET-017"].passed

    def test_only_private_feed_passes(self, tmp_path):
        # Gallery inherited, not explicit -> NUGET-016's case, not 017.
        findings = _scan(tmp_path, (
            "  <packageSources>\n" + _INTERNAL + "  </packageSources>\n"
        ))
        assert findings["NUGET-017"].passed

    def test_only_public_gallery_passes(self, tmp_path):
        findings = _scan(tmp_path, (
            "  <packageSources>\n" + _GALLERY + "  </packageSources>\n"
        ))
        assert findings["NUGET-017"].passed
