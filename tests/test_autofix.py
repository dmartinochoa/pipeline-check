"""Tests for core.autofix."""
from __future__ import annotations

from pipeline_check.core import autofix
from pipeline_check.core.checks.base import Finding, Severity


def _finding(check_id: str, resource: str = "wf.yml") -> Finding:
    return Finding(
        check_id=check_id,
        title="x",
        severity=Severity.MEDIUM,
        resource=resource,
        description="",
        recommendation="",
        passed=False,
    )


def test_gha004_adds_permissions_block_before_jobs():
    wf = (
        "name: ci\n"
        "\n"
        "on: push\n"
        "\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps: [{run: echo}]\n"
    )
    after = autofix.generate_fix(_finding("GHA-004"), wf)
    assert after is not None
    assert "permissions:\n  contents: read" in after
    # The inserted block sits above `jobs:`.
    assert after.index("permissions:") < after.index("jobs:")


def test_gha004_idempotent_when_block_exists():
    wf = (
        "name: ci\n"
        "permissions:\n"
        "  contents: read\n"
        "on: push\n"
        "jobs: {}\n"
    )
    assert autofix.generate_fix(_finding("GHA-004"), wf) is None


def test_generate_fix_returns_none_for_unknown_check_id():
    assert autofix.generate_fix(_finding("UNKNOWN-999"), "anything") is None


def test_render_patch_produces_unified_diff():
    patch = autofix.render_patch("wf.yml", "a\n", "b\n")
    assert "--- a/wf.yml" in patch
    assert "+++ b/wf.yml" in patch
    assert "-a" in patch
    assert "+b" in patch


def test_available_fixers_includes_gha004():
    assert "GHA-004" in autofix.available_fixers()
