"""Tests for ``_filter_terraform_by_diff`` — the terraform half of the
``--diff-base`` parity work.

The filter mutates a plan context in place so only resources whose
module maps to a changed .tf file stay in play. These tests exercise
each branch: root-module changes, module-scoped changes, and the
"nothing changed" result.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from pipeline_check.core import diff as diff_mod
from pipeline_check.core.scanner import _filter_context_by_diff


def _ctx(resources):
    """Return a fake Terraform context with a ``plan`` attribute the
    scanner's filter walks."""
    return SimpleNamespace(plan={
        "planned_values": {"root_module": {"resources": list(resources)}},
    })


def _res(address: str) -> dict:
    return {"address": address, "type": "aws_s3_bucket", "name": "x"}


def test_root_module_change_keeps_root_resources():
    ctx = _ctx([_res("aws_s3_bucket.root"), _res("module.vpc.aws_subnet.a")])
    # ``main.tf`` at repo root changed — the filter considers this a
    # "root module change" and keeps root resources, drops modules.
    with patch.object(diff_mod, "changed_files", return_value={"main.tf"}):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    kept = [r["address"] for r in ctx.plan["planned_values"]["root_module"]["resources"]]
    assert kept == ["aws_s3_bucket.root"]


def test_module_dir_change_keeps_only_that_module():
    ctx = _ctx([
        _res("module.vpc.aws_subnet.a"),
        _res("module.kms.aws_kms_key.a"),
        _res("aws_s3_bucket.root"),
    ])
    # A change under modules/vpc/main.tf — keep only module.vpc.*.
    with patch.object(diff_mod, "changed_files", return_value={"modules/vpc/main.tf"}):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    kept = [r["address"] for r in ctx.plan["planned_values"]["root_module"]["resources"]]
    assert kept == ["module.vpc.aws_subnet.a"]


def test_non_tf_changes_drop_everything():
    """If only non-.tf files changed, no resources can possibly have
    changed — the filter should empty the plan."""
    ctx = _ctx([_res("module.vpc.aws_subnet.a"), _res("aws_s3_bucket.root")])
    with patch.object(diff_mod, "changed_files", return_value={"README.md", "src/app.py"}):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    assert ctx.plan["planned_values"]["root_module"]["resources"] == []


def test_git_failure_is_noop():
    """``changed_files`` returning None means git is unavailable;
    filter must leave the plan untouched so CI doesn't silently skip
    the whole scan."""
    original = [_res("aws_s3_bucket.root"), _res("module.vpc.aws_subnet.a")]
    ctx = _ctx(original)
    with patch.object(diff_mod, "changed_files", return_value=None):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    kept = [r["address"] for r in ctx.plan["planned_values"]["root_module"]["resources"]]
    assert kept == [r["address"] for r in original]


def test_missing_planned_values_is_noop():
    """A plan without the ``planned_values.root_module.resources``
    structure should be left untouched, not crash."""
    ctx = SimpleNamespace(plan={})
    with patch.object(diff_mod, "changed_files", return_value={"main.tf"}):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    assert ctx.plan == {}


def test_empty_resource_address_defaults_to_root():
    """A resource with no ``module.`` prefix is treated as root — a
    root .tf change keeps it."""
    ctx = _ctx([{"address": "aws_s3_bucket.x", "type": "aws_s3_bucket", "name": "x"}])
    with patch.object(diff_mod, "changed_files", return_value={"main.tf"}):
        _filter_context_by_diff(ctx, "origin/main", "terraform")
    assert ctx.plan["planned_values"]["root_module"]["resources"] == [
        {"address": "aws_s3_bucket.x", "type": "aws_s3_bucket", "name": "x"}
    ]
