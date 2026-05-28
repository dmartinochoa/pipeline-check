"""Per-rule tests for NPM-013 (broad files-field include patterns)."""

from .conftest import run_check_manifest


class TestNPM013:
    def test_fails_on_single_star(self):
        # A lone ``"*"`` includes every file in the package root.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["*"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed
        assert "'*'" in f.description

    def test_fails_on_double_star(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["**"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed

    def test_fails_on_double_star_slash_star(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["**/*"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed

    def test_fails_on_star_slash_double_star(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["*/**"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed

    def test_fails_on_bare_dot(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["."],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed

    def test_fails_on_dot_slash(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["./"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed

    def test_fails_when_broad_entry_mixed_with_narrow(self):
        # One broad literal in a larger list still trips the rule —
        # the broad entry's effect isn't undone by the others.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["dist/**", "README.md", "**"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed

    def test_passes_on_narrow_subdirectory_glob(self):
        # ``dist/**`` narrows the include with a directory prefix.
        # This is the recommended shape.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["dist/**", "README.md", "LICENSE"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert f.passed

    def test_passes_on_typed_subglob(self):
        # ``src/**/*.js`` is bounded by both a directory prefix and a
        # filename suffix.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["src/**/*.js"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert f.passed

    def test_passes_when_files_absent(self):
        # NPM-013's surface is the positive-list shape; absence of
        # the field is a different (out-of-scope) failure mode.
        data = {"name": "x", "version": "1.0.0"}
        f = run_check_manifest(data, "NPM-013")
        assert f.passed

    def test_passes_when_files_empty(self):
        data = {"name": "x", "version": "1.0.0", "files": []}
        f = run_check_manifest(data, "NPM-013")
        assert f.passed

    def test_non_string_entries_are_ignored(self):
        # Malformed entries (numbers, objects) shouldn't crash the
        # rule. Treat them as non-matches.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["dist/**", 42, {"foo": "bar"}],
        }
        f = run_check_manifest(data, "NPM-013")
        assert f.passed

    def test_location_points_at_entry(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["dist/**", "**"],
        }
        f = run_check_manifest(data, "NPM-013")
        assert not f.passed
        assert f.locations, "expected a location for the offending entry"
        assert f.locations[0].start_line >= 1
