"""Tests for TerraformContext resource/data-source partitioning."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext


def _plan(resources):
    return {"planned_values": {"root_module": {"resources": resources, "child_modules": []}}}


def test_managed_and_data_resources_partitioned():
    plan = _plan([
        {"address": "aws_iam_policy.p", "mode": "managed",
         "type": "aws_iam_policy", "name": "p",
         "values": {"name": "p", "policy": "{}"}},
        {"address": "data.aws_iam_policy_document.d", "mode": "data",
         "type": "aws_iam_policy_document", "name": "d",
         "values": {"json": '{"Statement":[]}'}},
        {"address": "data.aws_caller_identity.me", "mode": "data",
         "type": "aws_caller_identity", "name": "me",
         "values": {"account_id": "1"}},
    ])
    ctx = TerraformContext(plan)
    managed = list(ctx.resources())
    data = list(ctx.data_sources())
    assert [r.address for r in managed] == ["aws_iam_policy.p"]
    assert {r.type for r in data} == {"aws_iam_policy_document", "aws_caller_identity"}


def test_data_source_filter_by_type():
    plan = _plan([
        {"address": "data.aws_iam_policy_document.a", "mode": "data",
         "type": "aws_iam_policy_document", "name": "a", "values": {}},
        {"address": "data.aws_caller_identity.me", "mode": "data",
         "type": "aws_caller_identity", "name": "me", "values": {}},
    ])
    ctx = TerraformContext(plan)
    polys = list(ctx.data_sources("aws_iam_policy_document"))
    assert len(polys) == 1
    assert polys[0].address == "data.aws_iam_policy_document.a"


def test_unknown_mode_skipped():
    plan = _plan([
        {"address": "x", "mode": "other", "type": "x", "name": "x", "values": {}},
    ])
    ctx = TerraformContext(plan)
    assert list(ctx.resources()) == []
    assert list(ctx.data_sources()) == []


def test_child_modules_walked_for_both_kinds():
    plan = {"planned_values": {"root_module": {
        "resources": [],
        "child_modules": [{
            "resources": [
                {"address": "module.a.aws_s3_bucket.b", "mode": "managed",
                 "type": "aws_s3_bucket", "name": "b", "values": {}},
                {"address": "module.a.data.aws_iam_policy_document.p", "mode": "data",
                 "type": "aws_iam_policy_document", "name": "p", "values": {}},
            ],
        }],
    }}}
    ctx = TerraformContext(plan)
    assert [r.address for r in ctx.resources()] == ["module.a.aws_s3_bucket.b"]
    assert [r.address for r in ctx.data_sources()] == [
        "module.a.data.aws_iam_policy_document.p"
    ]
