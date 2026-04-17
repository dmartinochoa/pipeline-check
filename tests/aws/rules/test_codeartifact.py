"""CA-001..004 — CodeArtifact rules."""
from __future__ import annotations

import json

from pipeline_check.core.checks.aws.rules import (
    ca001_domain_encryption,
    ca002_public_upstream,
    ca003_domain_policy_public,
    ca004_repo_wildcard_actions,
)
from tests.aws.rules.conftest import FakeClient


def _ca_client(domains=None, repos=None, repo_detail=None, domain_policy=None, repo_policy=None):
    client = FakeClient()
    client.set_paginator("list_domains", [{"domains": domains or []}])
    client.set_paginator("list_repositories", [{"repositories": repos or []}])
    client._responses["describe_repository"] = repo_detail or {"repository": {}}
    client._responses["get_domain_permissions_policy"] = (
        {"policy": {"document": domain_policy}} if domain_policy else {}
    )
    client._responses["get_repository_permissions_policy"] = (
        {"policy": {"document": repo_policy}} if repo_policy else {}
    )
    return client


def test_ca001_aws_owned_fails(make_catalog):
    cat = make_catalog(codeartifact=_ca_client(domains=[{"name": "d", "encryptionKey": ""}]))
    assert ca001_domain_encryption.check(cat)[0].passed is False


def test_ca001_cmk_passes(make_catalog):
    cat = make_catalog(codeartifact=_ca_client(
        domains=[{"name": "d", "encryptionKey": "arn:aws:kms:us-east-1:1:key/abc"}]
    ))
    assert ca001_domain_encryption.check(cat)[0].passed is True


def test_ca002_public_connection_fails(make_catalog):
    cat = make_catalog(codeartifact=_ca_client(
        repos=[{"name": "r", "domainName": "d"}],
        repo_detail={"repository": {"externalConnections": [{"externalConnectionName": "public:npmjs"}]}},
    ))
    assert ca002_public_upstream.check(cat)[0].passed is False


def test_ca002_private_passes(make_catalog):
    cat = make_catalog(codeartifact=_ca_client(
        repos=[{"name": "r", "domainName": "d"}],
        repo_detail={"repository": {"externalConnections": []}},
    ))
    assert ca002_public_upstream.check(cat)[0].passed is True


def test_ca003_wildcard_principal_fails(make_catalog):
    policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}]})
    cat = make_catalog(codeartifact=_ca_client(domains=[{"name": "d"}], domain_policy=policy))
    assert ca003_domain_policy_public.check(cat)[0].passed is False


def test_ca003_scoped_passes(make_catalog):
    policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "*"}]})
    cat = make_catalog(codeartifact=_ca_client(domains=[{"name": "d"}], domain_policy=policy))
    assert ca003_domain_policy_public.check(cat)[0].passed is True


def test_ca004_wildcard_action_and_resource_fails(make_catalog):
    policy = json.dumps({"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"},
        "Action": "codeartifact:*", "Resource": "*",
    }]})
    cat = make_catalog(codeartifact=_ca_client(
        repos=[{"name": "r", "domainName": "d"}],
        repo_policy=policy,
    ))
    assert ca004_repo_wildcard_actions.check(cat)[0].passed is False


def test_ca004_scoped_action_passes(make_catalog):
    policy = json.dumps({"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"},
        "Action": "codeartifact:ReadFromRepository", "Resource": "arn:aws:codeartifact:::r/*",
    }]})
    cat = make_catalog(codeartifact=_ca_client(
        repos=[{"name": "r", "domainName": "d"}],
        repo_policy=policy,
    ))
    assert ca004_repo_wildcard_actions.check(cat)[0].passed is True
