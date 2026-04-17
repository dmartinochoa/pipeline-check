"""Tests for the CloudFormation parser and context."""
from __future__ import annotations

import pytest

from pipeline_check.core.checks.cloudformation.base import (
    CloudFormationContext,
    _parse_template,
    is_intrinsic,
    is_true,
)


def test_parse_yaml_short_form_ref():
    tmpl = _parse_template("""
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      ManagedPolicyArns:
        - !Ref MyPolicy
""")
    arns = tmpl["Resources"]["R"]["Properties"]["ManagedPolicyArns"]
    assert arns == [{"Ref": "MyPolicy"}]


def test_parse_yaml_short_form_getatt_dotted():
    """``!GetAtt Resource.Attr`` must normalise to the JSON-form list."""
    tmpl = _parse_template("""
Resources:
  R:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !GetAtt OtherBucket.Arn
""")
    val = tmpl["Resources"]["R"]["Properties"]["BucketName"]
    assert val == {"Fn::GetAtt": ["OtherBucket", "Arn"]}


def test_parse_yaml_sub_form():
    tmpl = _parse_template("""
Resources:
  R:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub fn-${AWS::Region}
""")
    val = tmpl["Resources"]["R"]["Properties"]["FunctionName"]
    assert val == {"Fn::Sub": "fn-${AWS::Region}"}


def test_parse_yaml_if_form():
    tmpl = _parse_template("""
Resources:
  R:
    Type: AWS::CloudTrail::Trail
    Properties:
      EnableLogFileValidation: !If [IsProd, true, false]
""")
    val = tmpl["Resources"]["R"]["Properties"]["EnableLogFileValidation"]
    assert val == {"Fn::If": ["IsProd", True, False]}


def test_parse_json_template():
    tmpl = _parse_template('{"Resources": {"R": {"Type": "AWS::S3::Bucket", "Properties": {}}}}')
    assert tmpl["Resources"]["R"]["Type"] == "AWS::S3::Bucket"


def test_parse_invalid_yaml_returns_none():
    assert _parse_template(":\n  broken: [unclosed") is None


def test_context_ignores_non_template_yaml(tmp_path):
    """A YAML file with no ``Resources`` key isn't a template — skip it."""
    (tmp_path / "not_a_template.yml").write_text("foo: bar\n")
    ctx = CloudFormationContext.from_path(tmp_path)
    assert ctx._templates == []


def test_context_loads_yaml_and_json(tmp_path):
    (tmp_path / "a.yml").write_text(
        "Resources:\n  R1:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
    )
    (tmp_path / "b.json").write_text(
        '{"Resources": {"R2": {"Type": "AWS::IAM::Role", "Properties": {}}}}'
    )
    ctx = CloudFormationContext.from_path(tmp_path)
    ids = sorted(r.logical_id for r in ctx.resources())
    assert ids == ["R1", "R2"]


def test_context_rejects_missing_path():
    with pytest.raises(ValueError, match="does not exist"):
        CloudFormationContext.from_path("/definitely/not/a/real/path")


def test_resource_attributes_preserve_deletion_policy():
    """Resource-level attributes outside ``Properties`` are kept."""
    tmpl = _parse_template("""
Resources:
  R:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      BucketName: foo
""")
    ctx = CloudFormationContext.__new__(CloudFormationContext)
    ctx._templates = [("x", tmpl)]
    from pipeline_check.core.checks.cloudformation.base import _iter_resources
    ctx._resources = list(_iter_resources(ctx._templates))
    r = next(ctx.resources())
    assert r.attributes["DeletionPolicy"] == "Retain"
    assert r.attributes["UpdateReplacePolicy"] == "Retain"


def test_is_true_literal_bool():
    assert is_true(True) is True
    assert is_true(False) is False


def test_is_true_string_true():
    assert is_true("true") is True
    assert is_true("TRUE") is True
    assert is_true(" true ") is True


def test_is_true_intrinsic_is_false():
    """Unresolved intrinsic → not provably true → False."""
    assert is_true({"Ref": "EnableValidation"}) is False
    assert is_true({"Fn::If": ["IsProd", True, False]}) is False


def test_is_intrinsic_detects_fn_and_ref():
    assert is_intrinsic({"Ref": "X"}) is True
    assert is_intrinsic({"Fn::GetAtt": ["X", "Arn"]}) is True
    assert is_intrinsic({"Foo": "bar"}) is False
    assert is_intrinsic("plain string") is False
