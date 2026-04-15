"""Terraform ECR tests."""
from __future__ import annotations

import json

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.ecr import ECRChecks


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": resources, "child_modules": []}}}


def _repo(name, **kw):
    vals = {"name": name}
    vals.update(kw)
    return {
        "address": f"aws_ecr_repository.{name}",
        "mode": "managed",
        "type": "aws_ecr_repository",
        "name": name,
        "values": vals,
    }


def _policy(repo, doc):
    return {
        "address": f"aws_ecr_repository_policy.{repo}",
        "mode": "managed",
        "type": "aws_ecr_repository_policy",
        "name": repo,
        "values": {"repository": repo, "policy": json.dumps(doc)},
    }


def _lifecycle(repo):
    return {
        "address": f"aws_ecr_lifecycle_policy.{repo}",
        "mode": "managed",
        "type": "aws_ecr_lifecycle_policy",
        "name": repo,
        "values": {"repository": repo, "policy": "{}"},
    }


def _run(plan):
    return ECRChecks(TerraformContext(plan)).run()


def _by(findings, cid):
    return next(f for f in findings if f.check_id == cid)


class TestECR001:
    def test_scan_on_push_disabled_fails(self):
        plan = _plan([_repo("r", image_scanning_configuration=[{"scan_on_push": False}])])
        assert not _by(_run(plan), "ECR-001").passed

    def test_scan_on_push_enabled_passes(self):
        plan = _plan([_repo("r", image_scanning_configuration=[{"scan_on_push": True}])])
        assert _by(_run(plan), "ECR-001").passed


class TestECR002:
    def test_mutable_fails(self):
        plan = _plan([_repo("r", image_tag_mutability="MUTABLE")])
        assert not _by(_run(plan), "ECR-002").passed

    def test_immutable_passes(self):
        plan = _plan([_repo("r", image_tag_mutability="IMMUTABLE")])
        assert _by(_run(plan), "ECR-002").passed


class TestECR003:
    def test_no_policy_passes(self):
        plan = _plan([_repo("r")])
        assert _by(_run(plan), "ECR-003").passed

    def test_wildcard_principal_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}]}
        plan = _plan([_repo("r"), _policy("r", doc)])
        assert not _by(_run(plan), "ECR-003").passed

    def test_scoped_principal_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}}]}
        plan = _plan([_repo("r"), _policy("r", doc)])
        assert _by(_run(plan), "ECR-003").passed


class TestECR004:
    def test_no_lifecycle_fails(self):
        plan = _plan([_repo("r")])
        assert not _by(_run(plan), "ECR-004").passed

    def test_lifecycle_passes(self):
        plan = _plan([_repo("r"), _lifecycle("r")])
        assert _by(_run(plan), "ECR-004").passed


class TestECR005:
    def test_default_aes256_fails(self):
        plan = _plan([_repo("r")])
        assert not _by(_run(plan), "ECR-005").passed

    def test_explicit_aes256_fails(self):
        plan = _plan([_repo("r", encryption_configuration=[{"encryption_type": "AES256"}])])
        assert not _by(_run(plan), "ECR-005").passed

    def test_kms_without_key_fails(self):
        plan = _plan([_repo("r", encryption_configuration=[{"encryption_type": "KMS"}])])
        assert not _by(_run(plan), "ECR-005").passed

    def test_kms_with_cmk_passes(self):
        plan = _plan([_repo("r", encryption_configuration=[{
            "encryption_type": "KMS",
            "kms_key": "arn:aws:kms:us-east-1:123:key/abc",
        }])])
        assert _by(_run(plan), "ECR-005").passed
