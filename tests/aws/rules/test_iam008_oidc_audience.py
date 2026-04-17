"""IAM-008 — OIDC audience/subject pinning."""
from __future__ import annotations

import json

from pipeline_check.core.checks.aws.rules import iam008_oidc_audience as rule
from tests.aws.rules.conftest import FakeClient


def _iam_client(roles):
    client = FakeClient()
    client.set_paginator("list_roles", [{"Roles": roles}])
    return client


def _role(name, trust_doc):
    return {"RoleName": name, "AssumeRolePolicyDocument": json.dumps(trust_doc)}


_GH_OIDC_ARN = "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"


def test_non_oidc_role_skipped(make_catalog):
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    cat = make_catalog(iam=_iam_client([_role("svc", doc)]))
    assert rule.check(cat) == []


def test_oidc_no_audience_fails(make_catalog):
    doc = {"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC_ARN},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }]}
    cat = make_catalog(iam=_iam_client([_role("gh", doc)]))
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "missing :aud" in f.description


def test_oidc_audience_but_no_subject_fails(make_catalog):
    doc = {"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC_ARN},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}},
    }]}
    cat = make_catalog(iam=_iam_client([_role("gh", doc)]))
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "missing :sub" in f.description


def test_oidc_subject_wildcard_fails(make_catalog):
    doc = {"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC_ARN},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:sub": "*"},
        },
    }]}
    cat = make_catalog(iam=_iam_client([_role("gh", doc)]))
    assert rule.check(cat)[0].passed is False


def test_oidc_pinned_passes(make_catalog):
    doc = {"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": _GH_OIDC_ARN},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {
            "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
            "StringLike": {"token.actions.githubusercontent.com:sub": "repo:myorg/*:ref:refs/heads/main"},
        },
    }]}
    cat = make_catalog(iam=_iam_client([_role("gh", doc)]))
    assert rule.check(cat)[0].passed is True
