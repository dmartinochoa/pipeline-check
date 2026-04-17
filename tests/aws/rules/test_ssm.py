"""SSM-001/002 — SecureString usage."""
from __future__ import annotations

from pipeline_check.core.checks.aws.rules import ssm001_secret_string_type, ssm002_default_key
from tests.aws.rules.conftest import FakeClient


def _ssm_client(params):
    client = FakeClient()
    client.set_paginator("describe_parameters", [{"Parameters": params}])
    return client


def test_ssm001_secret_as_string_fails(make_catalog):
    cat = make_catalog(ssm=_ssm_client([{"Name": "/app/DB_PASSWORD", "Type": "String"}]))
    findings = ssm001_secret_string_type.check(cat)
    assert len(findings) == 1
    assert findings[0].passed is False


def test_ssm001_non_secret_skipped(make_catalog):
    cat = make_catalog(ssm=_ssm_client([{"Name": "/app/LOG_LEVEL", "Type": "String"}]))
    assert ssm001_secret_string_type.check(cat) == []


def test_ssm001_secure_string_skipped(make_catalog):
    cat = make_catalog(ssm=_ssm_client([{"Name": "/app/DB_PASSWORD", "Type": "SecureString"}]))
    assert ssm001_secret_string_type.check(cat) == []


def test_ssm002_default_key_fails(make_catalog):
    cat = make_catalog(ssm=_ssm_client([
        {"Name": "/x", "Type": "SecureString", "KeyId": "alias/aws/ssm"},
    ]))
    assert ssm002_default_key.check(cat)[0].passed is False


def test_ssm002_cmk_passes(make_catalog):
    cat = make_catalog(ssm=_ssm_client([
        {"Name": "/x", "Type": "SecureString", "KeyId": "arn:aws:kms:us-east-1:1:key/abc"},
    ]))
    assert ssm002_default_key.check(cat)[0].passed is True


def test_ssm002_plain_string_skipped(make_catalog):
    cat = make_catalog(ssm=_ssm_client([{"Name": "/x", "Type": "String"}]))
    assert ssm002_default_key.check(cat) == []
