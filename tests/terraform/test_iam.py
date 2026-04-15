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
