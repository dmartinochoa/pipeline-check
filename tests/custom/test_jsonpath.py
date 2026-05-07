"""Unit tests for the jsonpath subset used by the custom-rule DSL."""
from __future__ import annotations

import pytest

from pipeline_check.core.checks.custom.jsonpath import (
    JsonPathError,
    compile_path,
)


class TestParse:

    def test_root_only(self):
        p = compile_path("$")
        assert p.find({"a": 1}) == [{"a": 1}]

    def test_field_chain(self):
        p = compile_path("$.a.b.c")
        assert p.find({"a": {"b": {"c": 7}}}) == [7]

    def test_quoted_field_with_dashes(self):
        p = compile_path("$['x-y']")
        assert p.find({"x-y": 1}) == [1]

    def test_index_access(self):
        p = compile_path("$.items[1]")
        assert p.find({"items": ["a", "b", "c"]}) == ["b"]

    def test_negative_index(self):
        p = compile_path("$.items[-1]")
        assert p.find({"items": ["a", "b", "c"]}) == ["c"]

    def test_wildcard_brackets(self):
        p = compile_path("$.items[*]")
        assert p.find({"items": [1, 2, 3]}) == [1, 2, 3]

    def test_wildcard_dot(self):
        # ``.*`` is the convenience form of ``[*]`` and walks both
        # list elements and dict values.
        p = compile_path("$.jobs.*.steps[0]")
        doc = {
            "jobs": {
                "build": {"steps": [{"run": "x"}]},
                "test":  {"steps": [{"run": "y"}]},
            }
        }
        assert p.find(doc) == [{"run": "x"}, {"run": "y"}]

    def test_missing_field_returns_empty(self):
        assert compile_path("$.a.b").find({"a": {}}) == []

    def test_index_out_of_range_returns_empty(self):
        assert compile_path("$.x[10]").find({"x": [1, 2]}) == []

    def test_type_mismatch_returns_empty(self):
        # Field traversal on a list doesn't crash.
        assert compile_path("$.x.y").find({"x": [1, 2]}) == []


class TestErrors:

    @pytest.mark.parametrize("expr", ["", "foo", ".bar", "[*]"])
    def test_must_start_with_dollar(self, expr):
        with pytest.raises(JsonPathError):
            compile_path(expr)

    def test_unterminated_bracket(self):
        with pytest.raises(JsonPathError, match="unterminated"):
            compile_path("$.a[1")

    def test_invalid_index_raises(self):
        with pytest.raises(JsonPathError):
            compile_path("$.a[foo]")

    def test_dotted_dash_field_rejected(self):
        # Use ['x-y'] for keys with dashes — ``.x-y`` is rejected
        # so the failure mode is loud rather than silently zero matches.
        with pytest.raises(JsonPathError, match="not a valid identifier"):
            compile_path("$.x-y")

    def test_double_dot_rejected(self):
        with pytest.raises(JsonPathError, match="empty field"):
            compile_path("$..a")
