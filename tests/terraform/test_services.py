"""Phase-2 Terraform parity tests — CA-*, CCM-*, LMB-*, KMS-*, SSM-*."""
from __future__ import annotations

import json

from pipeline_check.core.checks.terraform.base import TerraformContext
from pipeline_check.core.checks.terraform.services import ServiceChecks


def _plan(resources):
    return {"planned_values": {"root_module": {"resources": resources, "child_modules": []}}}


def _r(addr, rtype, name, values):
    return {"address": addr, "mode": "managed", "type": rtype, "name": name, "values": values}


def _run(resources):
    return ServiceChecks(TerraformContext(_plan(resources))).run()


# ---------- CA-001 ----------

def test_ca001_aws_owned_fails():
    d = _r("aws_codeartifact_domain.d", "aws_codeartifact_domain", "d", {})
    f = next(x for x in _run([d]) if x.check_id == "CA-001")
    assert not f.passed


def test_ca001_cmk_passes():
    d = _r("aws_codeartifact_domain.d", "aws_codeartifact_domain", "d", {
        "encryption_key": "arn:aws:kms:us-east-1:1:key/abc",
    })
    f = next(x for x in _run([d]) if x.check_id == "CA-001")
    assert f.passed


# ---------- CA-002 ----------

def test_ca002_public_fails():
    r = _r("aws_codeartifact_repository.r", "aws_codeartifact_repository", "r", {
        "external_connections": ["public:npmjs"],
    })
    f = next(x for x in _run([r]) if x.check_id == "CA-002")
    assert not f.passed


# ---------- CA-003 ----------

def test_ca003_wildcard_fails():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}]})
    p = _r("aws_codeartifact_domain_permissions_policy.p",
           "aws_codeartifact_domain_permissions_policy", "p", {"policy_document": doc})
    f = next(x for x in _run([p]) if x.check_id == "CA-003")
    assert not f.passed


# ---------- CCM-001 ----------

def test_ccm001_no_template_fails():
    repo = _r("aws_codecommit_repository.r", "aws_codecommit_repository", "r", {
        "repository_name": "r",
    })
    f = next(x for x in _run([repo]) if x.check_id == "CCM-001")
    assert not f.passed


def test_ccm001_with_template_passes():
    repo = _r("aws_codecommit_repository.r", "aws_codecommit_repository", "r", {
        "repository_name": "r",
    })
    assoc = _r("aws_codecommit_approval_rule_template_association.a",
               "aws_codecommit_approval_rule_template_association", "a",
               {"repository_name": "r"})
    f = next(x for x in _run([repo, assoc]) if x.check_id == "CCM-001")
    assert f.passed


# ---------- LMB-001/002/003 ----------

def test_lmb001_no_signing_fails():
    fn = _r("aws_lambda_function.fn", "aws_lambda_function", "fn", {"function_name": "fn"})
    f = next(x for x in _run([fn]) if x.check_id == "LMB-001")
    assert not f.passed


def test_lmb002_none_auth_fails():
    fn = _r("aws_lambda_function.fn", "aws_lambda_function", "fn", {"function_name": "fn"})
    url = _r("aws_lambda_function_url.u", "aws_lambda_function_url", "u", {
        "function_name": "fn", "authorization_type": "NONE",
    })
    f = next(x for x in _run([fn, url]) if x.check_id == "LMB-002")
    assert not f.passed


def test_lmb003_secret_name_fails():
    fn = _r("aws_lambda_function.fn", "aws_lambda_function", "fn", {
        "function_name": "fn",
        "environment": [{"variables": {"DB_PASSWORD": "x"}}],
    })
    f = next(x for x in _run([fn]) if x.check_id == "LMB-003")
    assert not f.passed


# ---------- KMS-001/002 ----------

def test_kms001_no_rotation_fails():
    k = _r("aws_kms_key.k", "aws_kms_key", "k", {"enable_key_rotation": False})
    f = next(x for x in _run([k]) if x.check_id == "KMS-001")
    assert not f.passed


def test_kms002_wildcard_fails():
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "kms:*"}]})
    k = _r("aws_kms_key.k", "aws_kms_key", "k", {"enable_key_rotation": True, "policy": doc})
    f = next(x for x in _run([k]) if x.check_id == "KMS-002")
    assert not f.passed


# ---------- SSM-001/002 ----------

def test_ssm001_secret_as_string_fails():
    p = _r("aws_ssm_parameter.p", "aws_ssm_parameter", "p", {
        "name": "/app/DB_PASSWORD", "type": "String",
    })
    f = next(x for x in _run([p]) if x.check_id == "SSM-001")
    assert not f.passed


def test_ssm002_default_key_fails():
    p = _r("aws_ssm_parameter.p", "aws_ssm_parameter", "p", {
        "name": "/x", "type": "SecureString", "key_id": "alias/aws/ssm",
    })
    f = next(x for x in _run([p]) if x.check_id == "SSM-002")
    assert not f.passed
