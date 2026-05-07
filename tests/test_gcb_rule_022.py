"""Unit tests for GCB-022 — options.substitutionOption ALLOW_LOOSE."""
from __future__ import annotations

from typing import Any

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb022_substitution_option_loose as r22,
)


def _doc(**fields: Any) -> dict[str, Any]:
    return dict(fields)


class TestGCB022SubstitutionOptionLoose:
    def test_fails_on_allow_loose(self):
        f = r22.check("cb.yaml", _doc(options={
            "substitutionOption": "ALLOW_LOOSE",
        }))
        assert not f.passed
        assert "ALLOW_LOOSE" in f.description

    def test_fails_on_lowercase_allow_loose(self):
        f = r22.check("cb.yaml", _doc(options={
            "substitutionOption": "allow_loose",
        }))
        assert not f.passed

    def test_passes_on_must_match(self):
        f = r22.check("cb.yaml", _doc(options={
            "substitutionOption": "MUST_MATCH",
        }))
        assert f.passed

    def test_passes_when_option_unset(self):
        # Default behavior is MUST_MATCH; the rule short-circuits to
        # passing rather than warning on the unset case.
        f = r22.check("cb.yaml", _doc(options={}))
        assert f.passed

    def test_passes_when_no_options_block(self):
        f = r22.check("cb.yaml", _doc())
        assert f.passed

    def test_passes_on_unrelated_options_value(self):
        # Non-string values (a misconfigured doc) don't crash the rule.
        f = r22.check("cb.yaml", _doc(options={
            "substitutionOption": 42,
        }))
        assert f.passed
