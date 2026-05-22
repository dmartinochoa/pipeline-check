"""Per-rule tests for GHA-065 (zero-width / bidi Unicode in workflow body)."""
from __future__ import annotations

from .conftest import run_check


class TestGHA065ZeroWidthUnicode:
    def test_fails_on_right_to_left_override(self):
        # U+202E RIGHT-TO-LEFT OVERRIDE embedded in a run body.
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: 'bash override‮--harmless'\n"
        )
        f = run_check(wf, "GHA-065")
        assert not f.passed
        assert "0x202e" in f.description

    def test_fails_on_first_strong_isolate(self):
        # U+2066 LEFT-TO-RIGHT ISOLATE
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: 'echo ⁦hi'\n"
        )
        assert not run_check(wf, "GHA-065").passed

    def test_fails_on_zero_width_joiner(self):
        # U+200D ZERO WIDTH JOINER embedded between letters.
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: 'echo hello‍world'\n"
        )
        assert not run_check(wf, "GHA-065").passed

    def test_fails_on_bom(self):
        # U+FEFF (BOM / ZERO WIDTH NO-BREAK SPACE)
        wf = (
            "name: \"﻿my workflow\"\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo\n"
        )
        f = run_check(wf, "GHA-065")
        assert not f.passed
        assert "0xfeff" in f.description

    def test_fails_on_bidi_in_env_value(self):
        # Bidi in a non-run-block field still fires.
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      MSG: \"hello‮world\"\n"
            "    steps:\n"
            "      - run: echo\n"
        )
        assert not run_check(wf, "GHA-065").passed

    def test_passes_on_clean_workflow(self):
        wf = """
        name: clean
        on: push
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: bash override --harmless
        """
        assert run_check(wf, "GHA-065").passed

    def test_passes_on_emoji(self):
        # Regular emoji and CJK characters are not in the suspicious set.
        wf = (
            "name: \"build \U0001F680\"\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        assert run_check(wf, "GHA-065").passed

    def test_multiple_codepoint_count(self):
        # Three bidi characters in one string.
        wf = (
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: 'echo ‮⁦⁩stuff'\n"
        )
        f = run_check(wf, "GHA-065")
        assert not f.passed
        # All three codepoints surfaced in the description.
        assert "0x202e" in f.description and "0x2066" in f.description
