"""NPM-010 (OSV advisory lookup) fire-path test.

Added by the 2026-07 rule audit (the rule was wired but untested).
"""
from __future__ import annotations

from pipeline_check.core.checks.npm.rules import npm010_osv_advisory as npm010

from .conftest import manifest_ctx


def test_npm010_offline_silent_pass():
    # With no ctx (offline default), the rule passes with a "no OSV data"
    # note rather than firing.
    data = {"name": "x", "version": "1.0.0", "dependencies": {"json5": "2.2.1"}}
    ctx = manifest_ctx(data)
    f = npm010.check(ctx.manifests[0])
    assert f.passed is True


def test_npm010_fires_when_osv_advisory_present():
    data = {"name": "x", "version": "1.0.0", "dependencies": {"json5": "2.2.1"}}
    ctx = manifest_ctx(data)
    # Populate the advisory map the way --resolve-remote would.
    ctx.osv_advisories = {("json5", "2.2.1"): [{"id": "GHSA-xxxx"}]}
    f = npm010.check(ctx.manifests[0], ctx)
    assert f.passed is False
