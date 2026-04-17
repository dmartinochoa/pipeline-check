"""SM-001/002 — Secrets Manager rotation and resource policies."""
from __future__ import annotations

import json

from pipeline_check.core.checks.aws.rules import sm001_rotation, sm002_public_policy
from tests.aws.rules.conftest import FakeClient


def _sm_client(secrets, resource_policy=None):
    client = FakeClient()
    client.set_paginator("list_secrets", [{"SecretList": secrets}])
    if resource_policy is not None:
        client._responses["get_resource_policy"] = {"ResourcePolicy": resource_policy}
    return client


def _cb_client(projects):
    client = FakeClient(batch_get_projects={"projects": projects})
    client.set_paginator("list_projects", [{"projects": [p["name"] for p in projects]}])
    return client


def test_sm001_no_cb_reference_emits_nothing(make_catalog):
    cat = make_catalog(
        codebuild=_cb_client([]),
        secretsmanager=_sm_client([{"Name": "x", "ARN": "arn:aws:secretsmanager:::x"}]),
    )
    assert sm001_rotation.check(cat) == []


def test_sm001_referenced_secret_without_rotation_fails(make_catalog):
    project = {
        "name": "build",
        "environment": {"environmentVariables": [
            {"name": "DB", "type": "SECRETS_MANAGER", "value": "my-secret"},
        ]},
    }
    cat = make_catalog(
        codebuild=_cb_client([project]),
        secretsmanager=_sm_client([
            {"Name": "my-secret", "ARN": "arn:aws:secretsmanager:::my-secret", "RotationEnabled": False},
        ]),
    )
    findings = sm001_rotation.check(cat)
    assert len(findings) == 1
    assert findings[0].passed is False


def test_sm001_referenced_secret_with_rotation_passes(make_catalog):
    project = {
        "name": "build",
        "environment": {"environmentVariables": [
            {"name": "DB", "type": "SECRETS_MANAGER", "value": "my-secret"},
        ]},
    }
    cat = make_catalog(
        codebuild=_cb_client([project]),
        secretsmanager=_sm_client([
            {"Name": "my-secret", "ARN": "arn:aws:secretsmanager:::my-secret", "RotationEnabled": True},
        ]),
    )
    assert sm001_rotation.check(cat)[0].passed is True


_PUBLIC_POLICY = json.dumps({
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "secretsmanager:GetSecretValue"}]
})

_SCOPED_POLICY = json.dumps({
    "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:role/r"}, "Action": "secretsmanager:GetSecretValue"}]
})


def test_sm002_wildcard_principal_fails(make_catalog):
    cat = make_catalog(
        codebuild=_cb_client([]),
        secretsmanager=_sm_client(
            [{"Name": "x", "ARN": "arn:aws:secretsmanager:::x"}],
            resource_policy=_PUBLIC_POLICY,
        ),
    )
    assert sm002_public_policy.check(cat)[0].passed is False


def test_sm002_scoped_policy_passes(make_catalog):
    cat = make_catalog(
        codebuild=_cb_client([]),
        secretsmanager=_sm_client(
            [{"Name": "x", "ARN": "arn:aws:secretsmanager:::x"}],
            resource_policy=_SCOPED_POLICY,
        ),
    )
    assert sm002_public_policy.check(cat)[0].passed is True
