"""Unit tests for the predicate evaluator and template renderer."""
from __future__ import annotations

import pytest

from pipeline_check.core.checks.custom.evaluator import (
    PredicateError,
    compile_predicate,
    compile_rule_body,
    compile_template,
)

# ── Leaf operators ─────────────────────────────────────────────────


class TestEqNe:

    def test_eq_match(self):
        pred = compile_predicate({"eq": {"path": "x", "value": 1}})
        assert pred({"x": 1})
        assert not pred({"x": 2})

    def test_eq_missing_is_false(self):
        # Missing field cannot equal anything.
        pred = compile_predicate({"eq": {"path": "x", "value": 1}})
        assert not pred({})

    def test_ne_missing_is_true(self):
        # Missing field is "not equal to" everything (vacuous).
        pred = compile_predicate({"ne": {"path": "x", "value": 1}})
        assert pred({})


class TestRegex:

    def test_regex_search(self):
        pred = compile_predicate({"regex": {"path": "image", "pattern": "^acme/"}})
        assert pred({"image": "acme/web:1"})
        assert not pred({"image": "nginx:latest"})

    def test_invalid_regex_at_compile_raises(self):
        with pytest.raises(PredicateError, match="invalid regex"):
            compile_predicate({"regex": {"pattern": "["}})


class TestExistsMissing:

    def test_exists_present(self):
        pred = compile_predicate({"exists": {"path": "image"}})
        assert pred({"image": "x"})
        assert not pred({})

    def test_missing_absent(self):
        pred = compile_predicate({"missing": {"path": "image"}})
        assert pred({})
        assert not pred({"image": "x"})


class TestIn:

    def test_in_match(self):
        pred = compile_predicate({"in": {"path": "kind", "values": ["A", "B"]}})
        assert pred({"kind": "A"})
        assert not pred({"kind": "C"})

    def test_not_in_missing_is_true(self):
        pred = compile_predicate(
            {"not_in": {"path": "kind", "values": ["A", "B"]}}
        )
        assert pred({})


class TestNumericCompare:

    def test_gt(self):
        pred = compile_predicate({"gt": {"path": "n", "value": 5}})
        assert pred({"n": 6})
        assert not pred({"n": 5})
        assert not pred({"n": "string"})  # non-numeric → false

    def test_lte(self):
        pred = compile_predicate({"lte": {"path": "n", "value": 5}})
        assert pred({"n": 5})
        assert pred({"n": 4})
        assert not pred({"n": 6})


class TestLen:

    def test_len_eq_list(self):
        pred = compile_predicate({"len_eq": {"path": "xs", "value": 2}})
        assert pred({"xs": [1, 2]})
        assert not pred({"xs": [1]})

    def test_len_gt_string(self):
        pred = compile_predicate({"len_gt": {"path": "name", "value": 3}})
        assert pred({"name": "abcd"})
        assert not pred({"name": "ab"})


# ── Boolean glue ───────────────────────────────────────────────────


class TestBooleans:

    def test_all_of(self):
        pred = compile_predicate({
            "all_of": [
                {"eq":     {"path": "kind", "value": "Pod"}},
                {"exists": {"path": "image"}},
            ]
        })
        assert pred({"kind": "Pod", "image": "x"})
        assert not pred({"kind": "Pod"})
        assert not pred({"kind": "Service", "image": "x"})

    def test_any_of(self):
        pred = compile_predicate({
            "any_of": [
                {"eq": {"path": "k", "value": 1}},
                {"eq": {"path": "k", "value": 2}},
            ]
        })
        assert pred({"k": 1})
        assert pred({"k": 2})
        assert not pred({"k": 3})

    def test_not(self):
        pred = compile_predicate({
            "not": {"eq": {"path": "k", "value": 1}}
        })
        assert not pred({"k": 1})
        assert pred({"k": 2})

    def test_empty_all_of_rejected(self):
        with pytest.raises(PredicateError, match="non-empty"):
            compile_predicate({"all_of": []})


class TestParseErrors:

    def test_unknown_operator(self):
        with pytest.raises(PredicateError, match="unknown operator"):
            compile_predicate({"weird_op": {"path": "x", "value": 1}})

    def test_predicate_must_be_mapping(self):
        with pytest.raises(PredicateError, match="must be a mapping"):
            compile_predicate(["not", "a", "mapping"])

    def test_predicate_must_have_one_key(self):
        with pytest.raises(PredicateError, match="exactly one key"):
            compile_predicate({"eq": {"value": 1}, "ne": {"value": 2}})


# ── Template renderer ─────────────────────────────────────────────


class TestTemplate:

    def test_bare_name_iterated_node_first(self):
        # Iterated node has its own ``name`` — it wins over ambient.
        tmpl = compile_template("container {{name}} fails")
        out = tmpl.render({"name": "web"}, ambient={"name": "deploy-app"})
        assert out == "container web fails"

    def test_bare_name_falls_back_to_ambient(self):
        # Iterated node has no ``kind`` field — ambient wins.
        tmpl = compile_template("in {{kind}}/{{name}}")
        out = tmpl.render(
            {"name": "web"}, ambient={"kind": "Deployment", "name": "app"}
        )
        # ``name`` is present on the iterated node, ``kind`` is not.
        assert out == "in Deployment/web"

    def test_explicit_dollar_path_no_ambient(self):
        tmpl = compile_template("image {{$.image}} blocked")
        out = tmpl.render(
            {"image": "nginx:1"}, ambient={"image": "should-be-shadowed"}
        )
        assert out == "image nginx:1 blocked"

    def test_missing_renders_question_mark(self):
        tmpl = compile_template("found {{whatever}} oops")
        assert tmpl.render({}, ambient={}) == "found ? oops"

    def test_no_placeholders(self):
        tmpl = compile_template("static text")
        assert tmpl.render({}) == "static text"


# ── Full body integration ──────────────────────────────────────────


class TestCompileRuleBody:

    def test_walk_and_assert(self):
        body = compile_rule_body(
            for_each="$.steps[*]",
            assert_spec={
                "regex": {"path": "uses", "pattern": "@[0-9a-f]{40}$"}
            },
            description="step uses {{uses}} not pinned",
        )
        doc = {"steps": [
            {"uses": "actions/checkout@v4"},
            {"uses": "actions/setup-python@" + "a" * 40},
        ]}
        passed, offenders = body.apply(doc)
        assert not passed
        assert offenders == ["step uses actions/checkout@v4 not pinned"]

    def test_passing_doc_no_offenders(self):
        body = compile_rule_body(
            for_each="$.steps[*]",
            assert_spec={"exists": {"path": "name"}},
            description="step missing name",
        )
        passed, offenders = body.apply({"steps": [{"name": "a"}, {"name": "b"}]})
        assert passed
        assert offenders == []

    def test_for_each_no_matches_passes(self):
        # No offenders to find → rule passes by vacuous truth.
        body = compile_rule_body(
            for_each="$.does.not.exist[*]",
            assert_spec={"exists": {"path": "name"}},
            description="x",
        )
        passed, offenders = body.apply({})
        assert passed
        assert offenders == []
