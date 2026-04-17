"""KMS-001/002 — key rotation and wildcard policy."""
from __future__ import annotations

import json

from pipeline_check.core.checks.aws.rules import kms001_rotation, kms002_policy_wildcard
from tests.aws.rules.conftest import FakeClient


def _kms_client(keys=None, rotation_enabled=True, policy=None):
    client = FakeClient()
    client.set_paginator("list_keys", [{"Keys": [{"KeyId": k["KeyId"]} for k in (keys or [])]}])

    def _describe(KeyId=None, **_):
        for k in keys or []:
            if k.get("KeyId") == KeyId:
                return {"KeyMetadata": k}
        return {"KeyMetadata": {}}

    client._responses["describe_key"] = _describe
    client._responses["get_key_rotation_status"] = {"KeyRotationEnabled": rotation_enabled}
    if policy is not None:
        client._responses["get_key_policy"] = {"Policy": policy}
    return client


def _cmk(key_id="abc", spec="SYMMETRIC_DEFAULT"):
    return {
        "KeyId": key_id,
        "Arn": f"arn:aws:kms:us-east-1:1:key/{key_id}",
        "KeyManager": "CUSTOMER",
        "KeySpec": spec,
    }


def test_kms001_rotation_off_fails(make_catalog):
    cat = make_catalog(kms=_kms_client(keys=[_cmk()], rotation_enabled=False))
    assert kms001_rotation.check(cat)[0].passed is False


def test_kms001_rotation_on_passes(make_catalog):
    cat = make_catalog(kms=_kms_client(keys=[_cmk()], rotation_enabled=True))
    assert kms001_rotation.check(cat)[0].passed is True


def test_kms001_asymmetric_skipped(make_catalog):
    cat = make_catalog(kms=_kms_client(keys=[_cmk(spec="RSA_2048")], rotation_enabled=False))
    assert kms001_rotation.check(cat) == []


_WILDCARD = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/r"}, "Action": "kms:*"}]})
_SCOPED = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/r"}, "Action": "kms:Decrypt"}]})


def test_kms002_wildcard_fails(make_catalog):
    cat = make_catalog(kms=_kms_client(keys=[_cmk()], policy=_WILDCARD))
    assert kms002_policy_wildcard.check(cat)[0].passed is False


def test_kms002_scoped_passes(make_catalog):
    cat = make_catalog(kms=_kms_client(keys=[_cmk()], policy=_SCOPED))
    assert kms002_policy_wildcard.check(cat)[0].passed is True
