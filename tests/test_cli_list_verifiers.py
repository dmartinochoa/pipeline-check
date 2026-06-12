"""Tests for ``--list-verifiers`` (secret-verifier discoverability)."""
from __future__ import annotations

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks._primitives.secret_verifiers import (
    has_verifier,
    verifier_names,
)


def test_verifier_names_is_sorted_and_matches_registry():
    names = verifier_names()
    assert names == sorted(names)
    assert names  # non-empty
    # Every listed name really resolves to a verifier.
    assert all(has_verifier(n) for n in names)
    # A spread of known detectors across providers / cycles.
    for det in ("github_token", "stripe_secret", "figma_token", "doppler_token"):
        assert det in names


def test_cli_list_verifiers_exits_zero_and_lists_a_known_detector():
    result = CliRunner().invoke(scan, ["--list-verifiers"])
    assert result.exit_code == 0
    assert "github_token" in result.output


def test_cli_list_verifiers_shows_the_shape_description():
    result = CliRunner().invoke(scan, ["--list-verifiers"])
    assert result.exit_code == 0
    # The Figma row carries its shape blurb, not just the name.
    assert "figma_token" in result.output
    assert "figd_" in result.output


def test_cli_list_verifiers_lists_every_registered_verifier():
    result = CliRunner().invoke(scan, ["--list-verifiers"])
    assert result.exit_code == 0
    for name in verifier_names():
        assert name in result.output, f"{name} not listed"
