"""Regression tests from the rule audit (Terraform crash / FN fixes).

Each test pins a specific defect the 2026-07 audit found: a check that
crashed on valid-but-unusual input, or that produced a false positive /
false negative. Grouped here so the audit's Terraform coverage is
auditable in one place.
"""
from __future__ import annotations

import json

from pipeline_check.core.checks._iam_policy import is_oidc_trust_stmt
from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.codebuild import _cb004_timeout
from pipeline_check.core.checks.terraform.ecr import _ecr003_public_policy
from pipeline_check.core.checks.terraform.iam import IAMChecks
from pipeline_check.core.checks.terraform.rules import iam001_admin_access as iam001
from pipeline_check.core.checks.terraform.s3 import _s3005_secure_transport
from pipeline_check.core.checks.terraform.services import _lambda

_ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _plan(resources):
    return {"format_version": "1.2", "planned_values": {"root_module": {
        "resources": resources, "child_modules": []}}}


def _role(name, trust, **kw):
    vals = {"name": name, "assume_role_policy": trust}
    vals.update(kw)
    return {
        "address": f"aws_iam_role.{name}", "mode": "managed",
        "type": "aws_iam_role", "name": name, "values": vals,
    }


class TestIamContextScalarShapes:
    """``_role_is_cicd`` used to iterate ``Statement`` and index
    ``Principal`` assuming a list-of-dicts with dict principals, so a
    single-dict ``Statement`` or a bare string ``Principal`` raised and
    (via ``_guard_check``) degraded every IAM-* rule to a silent pass.
    """

    def test_single_dict_statement_codebuild_admin_fires(self):
        # A codebuild-trusted admin role whose trust policy is authored
        # with a single-dict ``Statement`` (not a list) must still be
        # recognized as CI/CD-scoped and flagged by IAM-001.
        trust = json.dumps({"Statement": {
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole"}})
        ctx = TerraformContext(_plan([
            _role("ci", trust, managed_policy_arns=[_ADMIN])]))
        f = iam001.check(ctx)
        assert f and not f[0].passed

    def test_list_statement_still_fires(self):
        # Regression guard: the common list form is unaffected.
        trust = json.dumps({"Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole"}]})
        ctx = TerraformContext(_plan([
            _role("ci", trust, managed_policy_arns=[_ADMIN])]))
        f = iam001.check(ctx)
        assert f and not f[0].passed

    def test_public_string_principal_does_not_crash(self):
        # ``Principal: "*"`` (a public trust, string not dict) is not a
        # CI/CD role; the check must skip it, not raise.
        trust = json.dumps({"Statement": {
            "Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}})
        ctx = TerraformContext(_plan([
            _role("pub", trust, managed_policy_arns=[_ADMIN])]))
        assert iam001.check(ctx) == []
        # The legacy per-service class path must also not raise.
        assert IAMChecks(ctx).run() == []


class TestIsOidcTrustStmtStringPrincipal:
    def test_string_principal_returns_none(self):
        # A bare ``Principal: "*"`` is a public/anonymous trust, not a
        # Federated OIDC one; must be a non-match rather than a crash.
        assert is_oidc_trust_stmt(
            {"Effect": "Allow", "Principal": "*"}) is None

    def test_federated_oidc_still_matched(self):
        host = is_oidc_trust_stmt({"Effect": "Allow", "Principal": {
            "Federated": "arn:aws:iam::123456789012:oidc-provider/"
            "token.actions.githubusercontent.com"}})
        assert host == "token.actions.githubusercontent.com"


class TestScalarPolicyAndBlockCrashes:
    """Policy documents and nested blocks can arrive in scalar / single-dict
    / unresolved-reference forms that used to raise and (via the per-rule
    guard) silently drop the finding.
    """

    def test_s3005_single_dict_deny_recognized(self):
        # A bucket policy authored with a single-dict Statement (not a
        # list) that denies non-TLS requests must be credited, not crash.
        doc = json.dumps({"Statement": {
            "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}})
        assert _s3005_secure_transport({"bucket": "b", "policy": doc}, "b").passed

    def test_s3005_non_object_policy_does_not_crash(self):
        assert _s3005_secure_transport(
            {"bucket": "b", "policy": "[1,2,3]"}, "b").passed is False

    def test_ecr003_single_dict_public_detected(self):
        doc = json.dumps({"Statement": {
            "Effect": "Allow", "Principal": "*", "Action": "ecr:*"}})
        assert _ecr003_public_policy(doc, "r").passed is False

    def test_ecr003_non_object_policy_does_not_crash(self):
        assert _ecr003_public_policy("[1,2]", "r").passed is True

    def test_lmb003_string_variables_does_not_crash(self):
        # environment.variables can be an unresolved HCL reference (string)
        # in plan mode; the check must treat it as no variables, not iterate.
        plan = _plan([{
            "address": "aws_lambda_function.fn", "mode": "managed",
            "type": "aws_lambda_function", "name": "fn",
            "values": {"function_name": "fn",
                       "environment": {"variables": "${local.envmap}"}}}])
        lmb003 = [f for f in _lambda(TerraformContext(plan))
                  if f.check_id == "LMB-003"]
        assert lmb003 and lmb003[0].passed is True

    def test_cb004_string_timeout_does_not_crash(self):
        # build_timeout as an unresolved reference string must not raise on
        # a ``str < int`` comparison; it degrades to "unknown / not set".
        f = _cb004_timeout({"build_timeout": "${var.t}"}, "aws_codebuild_project.p")
        assert f.check_id == "CB-004" and f.passed is False

    def test_cb004_numeric_string_parsed(self):
        f = _cb004_timeout({"build_timeout": "60"}, "aws_codebuild_project.p")
        assert f.passed is True

    def test_cb004_integer_still_works(self):
        assert _cb004_timeout(
            {"build_timeout": 60}, "aws_codebuild_project.p").passed is True
        assert _cb004_timeout(
            {"build_timeout": 600}, "aws_codebuild_project.p").passed is False
