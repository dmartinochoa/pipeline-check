"""IAM-007 — access-key age."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pipeline_check.core.checks.aws.rules import iam007_key_age as rule
from tests.aws.rules.conftest import FakeClient


def _iam_client(users, keys_by_user):
    client = FakeClient()
    client.set_paginator("list_users", [{"Users": users}])

    def _list_keys(UserName=None, **_):
        return {"AccessKeyMetadata": keys_by_user.get(UserName, [])}

    client._responses["list_access_keys"] = _list_keys
    client._responses["get_access_key_last_used"] = {"AccessKeyLastUsed": {}}
    return client


def _key(key_id, days_old, status="Active"):
    return {
        "AccessKeyId": key_id,
        "Status": status,
        "CreateDate": datetime.now(tz=timezone.utc) - timedelta(days=days_old),
    }


def test_no_users(make_catalog):
    cat = make_catalog(iam=_iam_client([], {}))
    assert rule.check(cat) == []


def test_user_with_no_active_keys_skipped(make_catalog):
    users = [{"UserName": "alice"}]
    keys = {"alice": [_key("AKIA1", days_old=1000, status="Inactive")]}
    cat = make_catalog(iam=_iam_client(users, keys))
    assert rule.check(cat) == []


def test_fresh_key_passes(make_catalog):
    users = [{"UserName": "bob"}]
    keys = {"bob": [_key("AKIA1", days_old=30)]}
    cat = make_catalog(iam=_iam_client(users, keys))
    findings = rule.check(cat)
    assert len(findings) == 1
    assert findings[0].passed is True


def test_old_key_fails(make_catalog):
    users = [{"UserName": "bob"}]
    keys = {"bob": [_key("AKIA1", days_old=400)]}
    cat = make_catalog(iam=_iam_client(users, keys))
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "400d" in f.description
