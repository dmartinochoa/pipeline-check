"""Terraform S3 tests."""
from __future__ import annotations

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.s3 import S3Checks


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": resources, "child_modules": []}}}


def _pipeline(bucket):
    return {
        "address": "aws_codepipeline.p", "mode": "managed",
        "type": "aws_codepipeline", "name": "p",
        "values": {
            "name": "p", "stage": [],
            "artifact_store": [{"location": bucket, "encryption_key": [{"id": "k"}]}],
        },
    }


def _helper(type_, bucket, extra):
    vals = {"bucket": bucket}
    vals.update(extra)
    return {"address": f"{type_}.x", "mode": "managed", "type": type_,
            "name": "x", "values": vals}


def _run(plan):
    return S3Checks(TerraformContext(plan)).run()


def _by(findings, cid):
    return next(f for f in findings if f.check_id == cid)


def test_no_pipelines_returns_empty():
    assert _run(_plan([])) == []


class TestS3001:
    def test_missing_pab_fails(self):
        plan = _plan([_pipeline("bkt")])
        assert not _by(_run(plan), "S3-001").passed

    def test_all_four_enabled_passes(self):
        plan = _plan([_pipeline("bkt"),
                      _helper("aws_s3_bucket_public_access_block", "bkt", {
                          "block_public_acls": True, "ignore_public_acls": True,
                          "block_public_policy": True, "restrict_public_buckets": True,
                      })])
        assert _by(_run(plan), "S3-001").passed


class TestS3002:
    def test_no_encryption_fails(self):
        plan = _plan([_pipeline("bkt")])
        assert not _by(_run(plan), "S3-002").passed

    def test_aes256_passes(self):
        plan = _plan([_pipeline("bkt"),
                      _helper("aws_s3_bucket_server_side_encryption_configuration", "bkt", {
                          "rule": [{"apply_server_side_encryption_by_default": [
                              {"sse_algorithm": "AES256"}]}],
                      })])
        assert _by(_run(plan), "S3-002").passed


class TestS3003:
    def test_no_versioning_fails(self):
        plan = _plan([_pipeline("bkt")])
        assert not _by(_run(plan), "S3-003").passed

    def test_enabled_versioning_passes(self):
        plan = _plan([_pipeline("bkt"),
                      _helper("aws_s3_bucket_versioning", "bkt", {
                          "versioning_configuration": [{"status": "Enabled"}],
                      })])
        assert _by(_run(plan), "S3-003").passed


class TestS3004:
    def test_no_logging_fails(self):
        plan = _plan([_pipeline("bkt")])
        assert not _by(_run(plan), "S3-004").passed

    def test_logging_passes(self):
        plan = _plan([_pipeline("bkt"),
                      _helper("aws_s3_bucket_logging", "bkt", {
                          "target_bucket": "log-bkt", "target_prefix": "p/",
                      })])
        assert _by(_run(plan), "S3-004").passed
