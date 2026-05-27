"""Tests for the ``hooks/mkdocs_standards_stats.py`` MkDocs hook.

The hook walks ``pipeline_check/core/standards/data/*.py`` via the
``ast`` module, counts the keys in each ``STANDARD = Standard(...)``
call's ``mappings`` and ``controls`` kwargs, and substitutes
``{{ standards.<name>.<field> }}`` tokens in markdown at build time.

These tests verify three contracts:

  1. The hook's index covers every registered standard, with
     non-zero check counts (a standard without mappings is a bug).
  2. Token substitution replaces known standard tokens with the
     parsed integer.
  3. Unknown standards / unknown fields leave the token in place
     rather than crashing the build (the docs editor sees the
     unrendered token and fixes the typo).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from hooks import mkdocs_standards_stats as hook


def test_index_covers_every_registered_standard():
    """Every Python file under ``standards/data/`` (skipping dunders)
    is parsed and produces a non-zero check count."""
    expected = {
        p.stem
        for p in (REPO / "pipeline_check/core/standards/data").glob("*.py")
        if not p.name.startswith("_")
    }
    assert set(hook._INDEX.keys()) == expected
    for name, info in hook._INDEX.items():
        assert info["checks"] > 0, f"{name}: zero mappings parsed"
        assert info["controls"] > 0, f"{name}: zero controls parsed"


def test_substitutes_known_token():
    md = "OWASP covers {{ standards.owasp_cicd_top_10.checks }} checks."
    out = hook.on_page_markdown(md)
    assert "{{ standards." not in out
    # The actual count is registry-dependent, so just assert the
    # substitution produced a digit string.
    assert any(ch.isdigit() for ch in out)


def test_substitutes_controls_field():
    md = "{{ standards.nist_800_53.controls }} families."
    out = hook.on_page_markdown(md)
    assert "{{ standards." not in out
    expected = hook._INDEX["nist_800_53"]["controls"]
    assert str(expected) in out


def test_unknown_standard_leaves_token_in_place():
    """Typo-resilience: an unknown standard name should NOT crash
    the build. The token stays unrendered so the docs editor sees
    the typo on the live page and fixes it."""
    md = "{{ standards.does_not_exist.checks }} bogus."
    out = hook.on_page_markdown(md)
    assert "{{ standards.does_not_exist.checks }}" in out


def test_unknown_field_leaves_token_in_place():
    md = "{{ standards.owasp_cicd_top_10.bogus }}"
    out = hook.on_page_markdown(md)
    # Pattern doesn't match unknown fields, so the original text
    # passes through unchanged.
    assert "{{ standards.owasp_cicd_top_10.bogus }}" in out


def test_no_token_short_circuits():
    """Pages without any ``{{ standards.`` token should pass through
    untouched (and skip the regex altogether for speed)."""
    md = "Plain prose with no template tokens."
    assert hook.on_page_markdown(md) == md


def test_substitution_does_not_break_repeated_tokens():
    md = (
        "{{ standards.owasp_cicd_top_10.checks }} + "
        "{{ standards.owasp_cicd_top_10.controls }} on the same line."
    )
    out = hook.on_page_markdown(md)
    # Both digits should appear; neither token should remain.
    assert "{{ standards." not in out
