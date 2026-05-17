"""Per-rule tests for NPM-007 (.npmrc ignore-scripts enforcement)."""

from pipeline_check.core.checks.npm.base import parse_npmrc

from .conftest import run_check_rc

# ── .npmrc parser ─────────────────────────────────────────────────────


class TestNpmrcParser:
    def test_parses_key_value(self):
        s = parse_npmrc("ignore-scripts=true\n")
        assert s == {"ignore-scripts": "true"}

    def test_lowercases_keys_preserves_values(self):
        s = parse_npmrc("REGISTRY=https://EXAMPLE.com/\n")
        assert s == {"registry": "https://EXAMPLE.com/"}

    def test_strips_quotes(self):
        s = parse_npmrc('ignore-scripts="true"\n')
        assert s == {"ignore-scripts": "true"}

    def test_skips_comments_and_blank_lines(self):
        body = (
            "# top-level comment\n"
            "\n"
            "ignore-scripts=true   # trailing comment\n"
            "; another comment style\n"
        )
        s = parse_npmrc(body)
        assert s == {"ignore-scripts": "true"}

    def test_ignores_bracket_sections(self):
        # npm config doesn't commonly use sections; we drop them.
        body = "[scope]\nignore-scripts=true\n"
        s = parse_npmrc(body)
        assert s == {"ignore-scripts": "true"}

    def test_handles_spaces_around_equals(self):
        s = parse_npmrc("ignore-scripts = true\n")
        assert s == {"ignore-scripts": "true"}


# ── Rule behavior ─────────────────────────────────────────────────────


class TestNPM007:
    def test_passes_with_ignore_scripts_true(self):
        text = "registry=https://registry.npmjs.org/\nignore-scripts=true\n"
        f = run_check_rc(text, "NPM-007")
        assert f.passed
        assert "ignore-scripts=true" in f.description

    def test_passes_with_alternate_truthy_values(self):
        for value in ("true", "1", "yes", "on", "True", "YES"):
            f = run_check_rc(f"ignore-scripts={value}\n", "NPM-007")
            assert f.passed, f"value {value!r} should pass"

    def test_fails_when_explicitly_disabled(self):
        text = "ignore-scripts=false\n"
        f = run_check_rc(text, "NPM-007")
        assert not f.passed
        assert "explicitly disabled" in f.description

    def test_fails_when_not_declared(self):
        text = "registry=https://registry.npmjs.org/\n"
        f = run_check_rc(text, "NPM-007")
        assert not f.passed
        assert "does not declare" in f.description

    def test_fails_on_unrecognized_value(self):
        # Anything that isn't true/false-ish: npm treats this as
        # default-on (scripts run). The rule flags it explicitly so
        # the operator sees the gap.
        text = "ignore-scripts=maybe\n"
        f = run_check_rc(text, "NPM-007")
        assert not f.passed
        assert "maybe" in f.description

    def test_quoted_truthy_value_passes(self):
        text = 'ignore-scripts="true"\n'
        f = run_check_rc(text, "NPM-007")
        assert f.passed
