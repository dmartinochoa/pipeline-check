"""Tests for the ``--man`` longform-help flag and the underlying
manual content registry."""
from __future__ import annotations

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core import manual

# ────────────────────────────────────────────────────────────────────────
# Content registry
# ────────────────────────────────────────────────────────────────────────


def test_topics_list_excludes_internal_index():
    """The public topic list must NOT advertise the internal "index"
    name — the empty/no-arg form already prints it."""
    names = manual.topics()
    assert "index" not in names
    # Sanity: every topic we promise in --help is actually registered.
    expected = {"gate", "autofix", "diff", "secrets", "standards",
                "config", "output", "lambda", "recipes"}
    assert expected.issubset(set(names))


def test_render_known_topic():
    body = manual.render("gate")
    assert "TOPIC: gate" in body
    assert "--fail-on" in body
    assert body.endswith("\n")


def test_render_index_when_no_topic():
    body = manual.render("")
    assert "Available topics:" in body
    # Lists every public topic for discoverability.
    for t in manual.topics():
        assert t in body


def test_render_unknown_topic_falls_back_to_index_with_error():
    body = manual.render("frobnicate")
    assert "Unknown topic: 'frobnicate'" in body
    assert "Available:" in body
    # Still includes the index so the user can see what they meant.
    assert "Available topics:" in body


def test_render_is_case_insensitive():
    assert manual.render("Gate") == manual.render("gate")
    assert manual.render("AUTOFIX") == manual.render("autofix")


def test_every_topic_has_a_consistent_header():
    """Every public topic body opens with ``TOPIC: <name>`` so a user
    grepping the output knows which page they're looking at."""
    for name in manual.topics():
        body = manual.render(name)
        assert body.startswith(f"TOPIC: {name}\n"), (
            f"topic {name!r} body must start with 'TOPIC: {name}\\n'"
        )


# ────────────────────────────────────────────────────────────────────────
# CLI integration
# ────────────────────────────────────────────────────────────────────────


def test_cli_man_with_no_topic_prints_index():
    """``pipeline_check --man`` (no value) prints the topic index and
    exits cleanly without running a scan."""
    result = CliRunner().invoke(scan, ["--man"])
    assert result.exit_code == 0
    assert "Available topics:" in result.output
    # No scan ran — no [error] / [auto] / [gate] markers from the
    # scan code path leaked through.
    assert "[error]" not in result.output
    assert "[gate]" not in result.output


def test_cli_man_with_topic_prints_only_that_topic():
    result = CliRunner().invoke(scan, ["--man", "gate"])
    assert result.exit_code == 0
    assert "TOPIC: gate" in result.output
    # Other topic headers should NOT appear — we want focused output.
    assert "TOPIC: autofix" not in result.output


def test_cli_man_unknown_topic_exits_nonzero_with_error():
    """Unknown topic exits 3 (config error) so automation piping the
    output through ``| grep`` catches the typo. The previous "print
    index and exit 0" behavior hid typos in CI scripts."""
    result = CliRunner().invoke(scan, ["--man", "nope"])
    assert result.exit_code == 3
    assert "Unknown topic: 'nope'" in result.output


def test_cli_man_short_circuits_path_validation(tmp_path, monkeypatch):
    """``--man`` should run regardless of which provider is selected,
    and must NOT trip the per-provider path validation that normal
    scans go through."""
    monkeypatch.chdir(tmp_path)  # no .gitlab-ci.yml present
    result = CliRunner().invoke(scan, ["--pipeline", "gitlab", "--man", "gate"])
    assert result.exit_code == 0
    assert "TOPIC: gate" in result.output
    # The "missing .gitlab-ci.yml" error must NOT have been raised.
    assert "--gitlab-path" not in result.output


# ────────────────────────────────────────────────────────────────────────
# Dynamic-content drift traps
#
# The standards / autofix / secrets topics build their bodies from
# the live registries. The tests below assert that every entry in
# each registry actually appears in the rendered topic, so adding a
# new standard / fixer / detector either auto-updates the page (via
# the registry walk) or fails this test (when the page needs a
# matching description entry).
# ────────────────────────────────────────────────────────────────────────


def test_standards_topic_lists_every_registered_standard():
    from pipeline_check.core import standards as _standards

    body = manual.render("standards")
    for name in _standards.available():
        assert name in body, f"standards topic missing {name!r}"


def test_autofix_topic_lists_every_registered_fixer():
    from pipeline_check.core.autofix import available_fixers

    body = manual.render("autofix")
    for cid in available_fixers():
        assert cid in body, f"autofix topic missing fixer {cid!r}"


def test_secrets_topic_lists_every_built_in_detector():
    from pipeline_check.core.checks._patterns import _BUILTIN_PATTERNS

    body = manual.render("secrets")
    for name in _BUILTIN_PATTERNS:
        assert name in body, f"secrets topic missing detector {name!r}"


def test_detector_descriptions_cover_registry():
    """Every entry in ``_BUILTIN_PATTERNS`` must have a hand-curated
    description in the manual so the rendered catalog isn't peppered
    with ``(see _patterns.py)`` placeholders. Adding a new detector
    without documenting its shape fails here."""
    from pipeline_check.core.checks._patterns import _BUILTIN_PATTERNS
    from pipeline_check.core.manual import _DETECTOR_DESCRIPTIONS

    missing = sorted(set(_BUILTIN_PATTERNS) - set(_DETECTOR_DESCRIPTIONS))
    assert not missing, (
        f"Add shape descriptions to manual._DETECTOR_DESCRIPTIONS "
        f"for: {', '.join(missing)}"
    )
    extra = sorted(set(_DETECTOR_DESCRIPTIONS) - set(_BUILTIN_PATTERNS))
    assert not extra, (
        f"Stale entries in manual._DETECTOR_DESCRIPTIONS (no longer "
        f"in _BUILTIN_PATTERNS): {', '.join(extra)}"
    )
