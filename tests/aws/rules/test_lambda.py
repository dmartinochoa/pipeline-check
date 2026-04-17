"""LMB-001..004 — Lambda rules."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from pipeline_check.core.checks.aws.rules import (
    lmb001_code_signing,
    lmb002_function_url_auth,
    lmb003_plaintext_env,
    lmb004_resource_policy_public,
)
from tests.aws.rules.conftest import FakeClient


def _lambda_client(
    functions=None,
    signing_cfg=None,
    url_cfg=None,
    policy=None,
):
    client = FakeClient()
    client.set_paginator("list_functions", [{"Functions": functions or []}])
    client._responses["get_function_code_signing_config"] = signing_cfg or {}
    client._responses["get_function_url_config"] = (
        url_cfg if url_cfg is not None
        else (lambda **_: (_ for _ in ()).throw(
            ClientError({"Error": {"Code": "ResourceNotFoundException", "Message": ""}}, "op")
        ))
    )
    client._responses["get_policy"] = policy if policy is not None else {}
    return client


def test_lmb001_no_signing_fails(make_catalog):
    cat = make_catalog(**{"lambda": _lambda_client(functions=[{"FunctionName": "f"}])})
    assert lmb001_code_signing.check(cat)[0].passed is False


def test_lmb001_signed_passes(make_catalog):
    cat = make_catalog(**{"lambda": _lambda_client(
        functions=[{"FunctionName": "f"}],
        signing_cfg={"CodeSigningConfigArn": "arn:aws:lambda:us-east-1:1:code-signing-config:x"},
    )})
    assert lmb001_code_signing.check(cat)[0].passed is True


def test_lmb002_none_auth_fails(make_catalog):
    cat = make_catalog(**{"lambda": _lambda_client(
        functions=[{"FunctionName": "f"}],
        url_cfg={"AuthType": "NONE"},
    )})
    assert lmb002_function_url_auth.check(cat)[0].passed is False


def test_lmb002_iam_auth_passes(make_catalog):
    cat = make_catalog(**{"lambda": _lambda_client(
        functions=[{"FunctionName": "f"}],
        url_cfg={"AuthType": "AWS_IAM"},
    )})
    assert lmb002_function_url_auth.check(cat)[0].passed is True


def test_lmb003_secret_name_fails(make_catalog):
    fn = {"FunctionName": "f", "Environment": {"Variables": {"DB_PASSWORD": "value"}}}
    cat = make_catalog(**{"lambda": _lambda_client(functions=[fn])})
    assert lmb003_plaintext_env.check(cat)[0].passed is False


def test_lmb003_clean_env_passes(make_catalog):
    fn = {"FunctionName": "f", "Environment": {"Variables": {"LOG_LEVEL": "info"}}}
    cat = make_catalog(**{"lambda": _lambda_client(functions=[fn])})
    assert lmb003_plaintext_env.check(cat)[0].passed is True


_PUBLIC = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction"}]})
_SCOPED = json.dumps({"Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "lambda:InvokeFunction",
    "Condition": {"StringEquals": {"aws:SourceArn": "arn:aws:execute-api:::x"}},
}]})


def test_lmb004_unscoped_wildcard_fails(make_catalog):
    cat = make_catalog(**{"lambda": _lambda_client(
        functions=[{"FunctionName": "f"}],
        policy={"Policy": _PUBLIC},
    )})
    assert lmb004_resource_policy_public.check(cat)[0].passed is False


def test_lmb004_scoped_wildcard_passes(make_catalog):
    cat = make_catalog(**{"lambda": _lambda_client(
        functions=[{"FunctionName": "f"}],
        policy={"Policy": _SCOPED},
    )})
    assert lmb004_resource_policy_public.check(cat)[0].passed is True
