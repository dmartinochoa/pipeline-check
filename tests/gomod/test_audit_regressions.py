"""Regression tests from the 2026-07 rule audit (Go modules)."""
from __future__ import annotations

from pipeline_check.core.checks.gomod.base import GoReplace
from pipeline_check.core.checks.gomod.rules.gomod009_prerelease_direct_require import (
    _is_prerelease,
)


def test_gomod009_prerelease_base_pseudo_version_is_a_commit_pin():
    # Form-2 pseudo-version (pre-release base) is a commit pin, not a
    # pre-release require.
    assert _is_prerelease("v1.2.3-rc.0.20230101120000-abcdef123456") is False
    assert _is_prerelease("v1.2.3-20230101120000-abcdef123456") is False
    assert _is_prerelease("v1.2.4-0.20230101120000-abcdef123456") is False


def test_gomod009_arbitrary_prerelease_identifiers_flagged():
    for v in ("v1.0.0-preview", "v1.0.0-M1", "v1.0.0-snapshot",
              "v1.0.0-canary", "v2.0.0-rc.1"):
        assert _is_prerelease(v) is True
    assert _is_prerelease("v1.2.3") is False


def test_gomod012_windows_forward_slash_drive_is_local():
    fwd = GoReplace(orig_path="x", orig_version=None,
                    new_path="C:/local/fork", new_version=None)
    assert fwd.is_local is True
    back = GoReplace(orig_path="x", orig_version=None,
                     new_path=r"C:\local\fork", new_version=None)
    assert back.is_local is True
    hostport = GoReplace(orig_path="x", orig_version=None,
                         new_path="example.com:8080/pkg", new_version=None)
    assert hostport.is_local is False
