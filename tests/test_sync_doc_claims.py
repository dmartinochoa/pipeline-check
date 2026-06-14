"""Tests for scripts/sync_doc_claims.py, the doc-claim writer.

Pairs with ``test_doc_claims.py`` (the checker): this verifies the
writer (a) agrees the in-tree docs are already in sync, and (b) actually
corrects a stale number while leaving an already-valid one untouched
(the "make it pass, don't churn" contract).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import sync_doc_claims as sdc  # noqa: E402


def test_in_sync_tree_reports_no_drift():
    # Equivalent guarantee to test_doc_claims passing, but it also proves
    # the writer's derivation agrees with the live docs: if a count is
    # bumped without running the writer, this fails too.
    ch = sdc.sync(write=False)
    assert not ch.changes, f"writer sees stale claims: {ch.changes}"
    assert not ch.manual, f"writer flags manual drift: {ch.manual}"


def test_rewrites_stale_provider_count():
    actual = sdc._count_providers()
    ch = sdc.Changer()
    out = sdc._rewrite_aggregate("Scans 999 providers today.", "x.md", ch)
    assert f"{actual} providers" in out
    assert "999 providers" not in out
    assert ch.changes


def test_leaves_correct_count_untouched():
    actual = sdc._count_providers()
    ch = sdc.Changer()
    text = f"Scans {actual} providers today."
    out = sdc._rewrite_aggregate(text, "x.md", ch)
    assert out == text
    assert not ch.changes


def test_standards_prose_allows_n_minus_one():
    # "OWASP plus <N-1> frameworks" is valid prose the checker accepts;
    # the writer must not rewrite it to N.
    actual = sdc._count_standards()
    ch = sdc.Changer()
    text = f"OWASP CI/CD Top 10 plus {actual - 1} compliance frameworks"
    out = sdc._rewrite_aggregate(text, "x.md", ch)
    assert out == text
    assert not ch.changes


def test_check_floor_only_rewrites_when_out_of_band():
    total = sdc._count_total_checks()
    ch = sdc.Changer()
    # A claim within [total-20, total] is a valid floor and is left alone.
    in_band = f"{total - 5}+ checks"
    assert sdc._rewrite_aggregate(in_band, "x.md", ch) == in_band
    assert not ch.changes
    # A wildly low claim is bumped to the rounded-down current floor.
    ch2 = sdc.Changer()
    out = sdc._rewrite_aggregate("only 10+ checks", "x.md", ch2)
    assert f"{sdc._floor10(total)}+ checks" in out
    assert ch2.changes


def test_rewrites_stale_readme_table_row():
    actual = sdc._count_rules_in("github")
    bogus = actual + 7
    ch = sdc.Changer()
    row = f"| **GitHub Actions** | `.github/workflows/*.yml` | `--gha-path` | {bogus} checks · stuff |"
    out = sdc._rewrite_readme_provider_table(row, ch)
    assert f"| {actual} checks" in out
    assert ch.changes
