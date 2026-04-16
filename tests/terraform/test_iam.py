"""Terraform IAM tests."""
from __future__ import annotations

import json

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.iam import IAMChecks

_CB_TRUST = json.dumps({
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"},
                   "Action": "sts:AssumeRole"}]
})
_NON_CICD_TRUST = json.dumps({
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}]
})


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": resources, "child_modules": []}}}


def _role(name, trust=_CB_TRUST, **kw):
    vals = {"name": name, "assume_role_policy": trust}
    vals.update(kw)
    return {
        "address": f"aws_iam_role.{name}",
        "mode": "managed", "type": "aws_iam_role", "name": name,
        "values": vals,
    }


def _attach(role, arn):
    return {
        "address": f"aws_iam_role_policy_attachment.{role}",
        "mode": "managed", "type": "aws_iam_role_policy_attachment", "name": role,
        "values": {"role": role, "policy_arn": arn},
    }


def _inline(role, pname, doc):
    return {
        "address": f"aws_iam_role_policy.{role}",
        "mode": "managed", "type": "aws_iam_role_policy", "name": pname,
        "values": {"role": role, "name": pname, "policy": json.dumps(doc)},
    }


def _run(plan):
    return IAMChecks(TerraformContext(plan)).run()


def _by(findings, cid):
    return next((f for f in findings if f.check_id == cid), None)


def test_non_cicd_role_ignored():
    plan = _plan([_role("ec2role", trust=_NON_CICD_TRUST)])
    assert _run(plan) == []


class TestIAM001:
    def test_admin_attached_fails(self):
        plan = _plan([
            _role("r"),
            _attach("r", "arn:aws:iam::aws:policy/AdministratorAccess"),
        ])
        assert not _by(_run(plan), "IAM-001").passed

    def test_no_admin_passes(self):
        plan = _plan([_role("r"),
                      _attach("r", "arn:aws:iam::aws:policy/ReadOnlyAccess")])
        assert _by(_run(plan), "IAM-001").passed

    def test_admin_via_managed_policy_arns_fails(self):
        plan = _plan([_role("r", managed_policy_arns=[
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ])])
        assert not _by(_run(plan), "IAM-001").passed


class TestIAM002:
    def test_wildcard_in_separate_policy_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        plan = _plan([_role("r"), _inline("r", "bad", doc)])
        assert not _by(_run(plan), "IAM-002").passed

    def test_scoped_action_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        plan = _plan([_role("r"), _inline("r", "ok", doc)])
        assert _by(_run(plan), "IAM-002").passed


class TestIAM003:
    def test_no_boundary_fails(self):
        plan = _plan([_role("r")])
        assert not _by(_run(plan), "IAM-003").passed

    def test_boundary_passes(self):
        plan = _plan([_role("r", permissions_boundary="arn:aws:iam::123:policy/boundary")])
        assert _by(_run(plan), "IAM-003").passed


class TestIAM004:
    def test_passrole_wildcard_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
        plan = _plan([_role("r"), _inline("r", "bad", doc)])
        assert not _by(_run(plan), "IAM-004").passed

    def test_passrole_scoped_resource_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole",
                              "Resource": "arn:aws:iam::123:role/target"}]}
        plan = _plan([_role("r"), _inline("r", "ok", doc)])
        assert _by(_run(plan), "IAM-004").passed

    def test_iam_wildcard_action_with_wildcard_resource_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
        plan = _plan([_role("r"), _inline("r", "bad", doc)])
        assert not _by(_run(plan), "IAM-004").passed

    def test_inline_policy_block_on_role_detected(self):
        doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]})
        plan = _plan([_role("r", inline_policy=[{"name": "ip", "policy": doc}])])
        assert not _by(_run(plan), "IAM-004").passed


class TestIAM005:
    def test_external_aws_principal_without_externalid_fails(self):
        trust = json.dumps({"Statement": [
            {"Effect": "Allow",
             "Principal": {"Service": "codebuild.amazonaws.com"},
             "Action": "sts:AssumeRole"},
            {"Effect": "Allow",
             "Principal": {"AWS": "arn:aws:iam::999:root"},
             "Action": "sts:AssumeRole"},
        ]})
        plan = _plan([_role("r", trust=trust)])
        assert not _by(_run(plan), "IAM-005").passed

    def test_external_aws_principal_with_externalid_passes(self):
        trust = json.dumps({"Statement": [
            {"Effect": "Allow",
             "Principal": {"Service": "codebuild.amazonaws.com"},
             "Action": "sts:AssumeRole"},
            {"Effect": "Allow",
             "Principal": {"AWS": "arn:aws:iam::999:root"},
             "Action": "sts:AssumeRole",
             "Condition": {"StringEquals": {"sts:ExternalId": "secret-value"}}},
        ]})
        plan = _plan([_role("r", trust=trust)])
        assert _by(_run(plan), "IAM-005").passed

    def test_service_only_principal_passes(self):
        plan = _plan([_role("r")])
        assert _by(_run(plan), "IAM-005").passed


class TestIAM006:
    def test_sensitive_action_wildcard_resource_fails(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        plan = _plan([_role("r"), _inline("r", "bad", doc)])
        assert not _by(_run(plan), "IAM-006").passed

    def test_sensitive_action_scoped_resource_passes(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                              "Resource": "arn:aws:s3:::my-bucket/*"}]}
        plan = _plan([_role("r"), _inline("r", "ok", doc)])
        assert _by(_run(plan), "IAM-006").passed

    def test_wildcard_action_does_not_double_report(self):
        # IAM-002 handles Action:"*"; IAM-006 should pass.
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        plan = _plan([_role("r"), _inline("r", "wild", doc)])
        assert _by(_run(plan), "IAM-006").passed

    def test_customer_managed_via_attachment_detected(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]}
        pol = {
            "address": "aws_iam_policy.p", "mode": "managed",
            "type": "aws_iam_policy", "name": "p",
            "values": {"name": "p", "arn": "arn:aws:iam::123:policy/p",
                       "policy": json.dumps(doc)},
        }
        plan = _plan([_role("r"), pol, _attach("r", "arn:aws:iam::123:policy/p")])
        assert not _by(_run(plan), "IAM-006").passed
