"""Unit tests for the shared YAML batch loader (``_yaml_files``).

This loader is the single read + parse + warn path behind every
workflow provider's context. These cover its defensive guards in
isolation: the 5 MB size cap (an alias-expansion-bomb shield), read
errors, and parse errors. A failure on one file must never abort the
batch, it becomes a warning and that file is skipped so the rest still
load.
"""
from __future__ import annotations

from pipeline_check.core.checks import _yaml_files as yaml_files
from pipeline_check.core.checks._yaml_files import load_yaml_files


class TestHappyPath:
    def test_single_doc_loads(self, tmp_path):
        p = tmp_path / "a.yml"
        p.write_text("name: ci\njobs: {build: 1}\n")
        loaded, warnings, skipped = load_yaml_files([p])
        assert warnings == [] and skipped == 0
        assert len(loaded) == 1
        assert loaded[0].path == p
        assert loaded[0].docs == [{"name": "ci", "jobs": {"build": 1}}]
        assert loaded[0].doc_lines is None

    def test_multi_doc_splits_and_records_lines(self, tmp_path):
        p = tmp_path / "m.yml"
        p.write_text("kind: a\n---\nkind: b\n")
        loaded, warnings, skipped = load_yaml_files([p], multi_doc=True)
        assert warnings == [] and skipped == 0
        assert loaded[0].docs == [{"kind": "a"}, {"kind": "b"}]
        assert loaded[0].doc_lines == [1, 3]

    def test_input_order_preserved(self, tmp_path):
        a = tmp_path / "a.yml"
        a.write_text("k: 1\n")
        b = tmp_path / "b.yml"
        b.write_text("k: 2\n")
        loaded, _, _ = load_yaml_files([a, b])
        assert [lf.path for lf in loaded] == [a, b]


class TestDefensiveGuards:
    def test_oversize_file_skipped_not_parsed(self, tmp_path, monkeypatch):
        # Shrink the cap so the test doesn't have to write 5 MB to disk.
        monkeypatch.setattr(yaml_files, "_MAX_YAML_BYTES", 4)
        p = tmp_path / "big.yml"
        p.write_text("name: ci\n")  # well over 4 bytes
        loaded, warnings, skipped = load_yaml_files([p])
        assert loaded == []
        assert skipped == 1
        assert "exceeds" in warnings[0] and "byte limit" in warnings[0]

    def test_read_error_becomes_warning(self, tmp_path):
        missing = tmp_path / "does-not-exist.yml"
        loaded, warnings, skipped = load_yaml_files([missing])
        assert loaded == [] and skipped == 1
        assert "read error" in warnings[0]

    def test_parse_error_becomes_warning(self, tmp_path):
        p = tmp_path / "bad.yml"
        p.write_text("on: [push\n")  # unclosed flow sequence
        loaded, warnings, skipped = load_yaml_files([p])
        assert loaded == [] and skipped == 1
        assert "YAML parse error" in warnings[0]

    def test_one_bad_file_does_not_abort_the_batch(self, tmp_path):
        bad = tmp_path / "bad.yml"
        bad.write_text("on: [push\n")
        good = tmp_path / "good.yml"
        good.write_text("k: 1\n")
        loaded, warnings, skipped = load_yaml_files([bad, good])
        # The good file still loads despite the bad one earlier in the batch.
        assert [lf.path for lf in loaded] == [good]
        assert skipped == 1 and len(warnings) == 1
