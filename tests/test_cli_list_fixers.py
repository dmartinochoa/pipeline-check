"""Tests for ``--list-fixers`` (fixer discoverability)."""
from __future__ import annotations

import re

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.autofix import iter_fixers
from pipeline_check.core.explain import render_fixers

# A row looks like ``GHA-004  HIGH  safe  <title>``. Anchor on the ID +
# tier columns so the assertions don't hinge on a rule's exact title.
_ROW_RE = re.compile(r"^([A-Z0-9]+-\d+)\s+\S+\s+(safe|unsafe)\s+\S", re.MULTILINE)


def _rows(body: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in _ROW_RE.finditer(body)]


def test_render_lists_every_fixer_and_partitions_by_tier():
    """``all`` lists one row per registered fixer; ``safe`` + ``unsafe``
    partition that set exactly."""
    registry = iter_fixers()
    all_body, all_code = render_fixers("all")
    safe_body, safe_code = render_fixers("safe")
    unsafe_body, unsafe_code = render_fixers("unsafe")

    assert all_code == safe_code == unsafe_code == 0
    assert len(_rows(all_body)) == len(registry)
    assert len(_rows(safe_body)) + len(_rows(unsafe_body)) == len(registry)


def test_render_tier_filter_is_exclusive():
    """A safe fixer (GHA-004) appears only in the safe slice; an unsafe
    one (ADO-017, the docker-flag strip) only in the unsafe slice."""
    safe_ids = {cid for cid, _ in _rows(render_fixers("safe")[0])}
    unsafe_ids = {cid for cid, _ in _rows(render_fixers("unsafe")[0])}

    assert "GHA-004" in safe_ids and "GHA-004" not in unsafe_ids
    assert "ADO-017" in unsafe_ids and "ADO-017" not in safe_ids
    assert safe_ids.isdisjoint(unsafe_ids)


def test_render_every_row_matches_requested_tier():
    """No row in a filtered listing carries the other tier."""
    for tier in ("safe", "unsafe"):
        body, _ = render_fixers(tier)
        assert all(t == tier for _, t in _rows(body))


def test_render_rows_carry_severity_and_title():
    """Every listed fixer resolves to real rule metadata (no placeholder
    severity ``?`` or ``(no rule metadata)`` titles)."""
    body, _ = render_fixers("all")
    assert "(no rule metadata)" not in body
    for line in body.splitlines():
        cid, _, rest = line.partition("  ")
        assert not rest.lstrip().startswith("?  "), line


def test_render_unknown_tier_yields_empty_non_error():
    """A tier with no members is a normal empty result, exit 0, not an
    error. (Belt-and-suspenders: click already rejects bad values, but
    the renderer must not raise.)"""
    body, code = render_fixers("nonexistent")
    assert code == 0
    assert "No nonexistent autofixers" in body


def test_cli_list_fixers_exits_zero_and_lists_a_known_id():
    result = CliRunner().invoke(scan, ["--list-fixers"])
    assert result.exit_code == 0
    assert "GHA-004" in result.output


def test_cli_list_fixers_default_is_all():
    """Bare ``--list-fixers`` lists the full registry (default tier)."""
    result = CliRunner().invoke(scan, ["--list-fixers"])
    assert result.exit_code == 0
    assert len(_rows(result.output)) == len(iter_fixers())


def test_cli_invalid_safety_value_is_rejected():
    result = CliRunner().invoke(scan, ["--list-fixers", "--safety", "bogus"])
    assert result.exit_code == 2
    assert "Invalid value for '--safety'" in result.output
