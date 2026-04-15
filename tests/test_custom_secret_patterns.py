"""Tests for user-supplied secret patterns."""
from __future__ import annotations

import pytest

from pipeline_check.core.checks import _secrets as secrets_mod


@pytest.fixture(autouse=True)
def _clean_registry():
    """Each test starts with only the built-in pattern registered."""
    secrets_mod.reset_patterns()
    yield
    secrets_mod.reset_patterns()


def test_custom_pattern_flags_org_specific_token():
    # `acme_` prefix + 32 hex chars is an internal org token shape.
    secrets_mod.register_pattern(r"^acme_[a-f0-9]{32}$")
    doc = {
        "jobs": {"b": {"steps": [{"run": "echo acme_deadbeefcafebabe0123456789abcdef"}]}}
    }
    hits = secrets_mod.find_secret_values(doc)
    assert hits, "custom pattern should have matched the acme_ token"


def test_builtin_pattern_still_fires_after_register():
    secrets_mod.register_pattern(r"^acme_[a-f0-9]{32}$")
    doc = {"env": {"KEY": "AKIAIOSFODNN7EXAMPLE"}}
    assert secrets_mod.find_secret_values(doc)


def test_duplicate_registration_is_idempotent():
    before = len(secrets_mod._PATTERNS)
    secrets_mod.register_pattern(r"^acme_[a-f0-9]{32}$")
    secrets_mod.register_pattern(r"^acme_[a-f0-9]{32}$")
    assert len(secrets_mod._PATTERNS) == before + 1


def test_reset_restores_only_builtin():
    secrets_mod.register_pattern(r"^foo$")
    assert len(secrets_mod._PATTERNS) == 2
    secrets_mod.reset_patterns()
    assert len(secrets_mod._PATTERNS) == 1
