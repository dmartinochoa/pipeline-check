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
from pipeline_check.core.checks.terraform.iam import IAMChecks
from pipeline_check.core.checks.terraform.rules import iam001_admin_access as iam001

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
