"""Tests for the CFN intrinsic-reducer ``resolve_literal``."""
from __future__ import annotations

from pipeline_check.core.checks.cloudformation.base import resolve_literal


def test_literal_string_returned_as_is():
    assert resolve_literal("vpc-aaa") == "vpc-aaa"


def test_bool_and_numeric_stringified():
    assert resolve_literal(True) == "true"
    assert resolve_literal(False) == "false"
    assert resolve_literal(42) == "42"


def test_ref_to_parameter_with_default():
    assert resolve_literal({"Ref": "Vpc"}, {"Vpc": "vpc-aaa"}) == "vpc-aaa"


def test_ref_missing_default_unresolved():
    assert resolve_literal({"Ref": "Unknown"}, {}) is None


def test_ref_pseudo_parameter_unresolved():
    # AWS::Region / AWS::AccountId are only knowable at stack creation.
    assert resolve_literal({"Ref": "AWS::Region"}, {}) is None


def test_sub_no_variables_returns_template():
    assert resolve_literal({"Fn::Sub": "arn:aws:lambda:us-east-1:1:function:*"}) \
        == "arn:aws:lambda:us-east-1:1:function:*"


def test_sub_with_parameter_variable():
    got = resolve_literal(
        {"Fn::Sub": "arn:aws:lambda:us-east-1:1:function:${Suffix}"},
        {"Suffix": "*"},
    )
    assert got == "arn:aws:lambda:us-east-1:1:function:*"


def test_sub_var_map_form():
    got = resolve_literal(
        {"Fn::Sub": ["hello-${Target}", {"Target": "world"}]},
    )
    assert got == "hello-world"


def test_sub_missing_variable_unresolved():
    assert resolve_literal({"Fn::Sub": "prefix-${MissingVar}"}, {}) is None


def test_join_literal_parts():
    got = resolve_literal({"Fn::Join": [":", ["arn", "aws", "lambda", "*"]]})
    assert got == "arn:aws:lambda:*"


def test_join_with_ref_part_resolves():
    got = resolve_literal(
        {"Fn::Join": ["-", [{"Ref": "Env"}, "bucket"]]},
        {"Env": "prod"},
    )
    assert got == "prod-bucket"


def test_join_with_unresolvable_part_unresolved():
    assert resolve_literal(
        {"Fn::Join": ["-", [{"Ref": "Env"}, "bucket"]]},
        {},
    ) is None


def test_unknown_intrinsic_unresolved():
    assert resolve_literal({"Fn::GetAtt": ["X", "Arn"]}) is None
    assert resolve_literal({"Fn::If": ["Cond", "a", "b"]}) is None
