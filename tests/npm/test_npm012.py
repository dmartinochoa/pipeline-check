"""NPM-012 (.npmrc publish-token restriction) fire-path test.

Added by the 2026-07 rule audit (the rule was wired but untested).
"""
from __future__ import annotations

from .conftest import run_check_rc


def test_npm012_legacy_token_fires():
    rc = "//registry.npmjs.org/:_authToken=abc123-legacy-uuid-token"
    assert run_check_rc(rc, "NPM-012").passed is False


def test_npm012_granular_npm_prefix_token_passes():
    rc = "//registry.npmjs.org/:_authToken=npm_granulartoken"
    assert run_check_rc(rc, "NPM-012").passed is True


def test_npm012_env_var_token_passes():
    rc = "//registry.npmjs.org/:_authToken=${NPM_TOKEN}"
    assert run_check_rc(rc, "NPM-012").passed is True
