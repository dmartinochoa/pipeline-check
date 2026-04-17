"""CB-010 — fork-PR builds without actor filter."""
from __future__ import annotations

from pipeline_check.core.checks.aws.rules import cb010_fork_pr_builds as rule
from tests.aws.rules.conftest import FakeClient


def _project(name="p", webhook=None):
    proj = {"name": name}
    if webhook is not None:
        proj["webhook"] = webhook
    return proj


def _cat(projects, make_catalog):
    client = FakeClient(batch_get_projects={"projects": projects})
    client.set_paginator("list_projects", [{"projects": [p["name"] for p in projects]}])
    return make_catalog(codebuild=client)


def test_no_webhook_skipped(make_catalog):
    cat = _cat([_project(webhook=None)], make_catalog)
    assert rule.check(cat) == []


def test_push_only_passes(make_catalog):
    webhook = {"filterGroups": [[
        {"type": "EVENT", "pattern": "PUSH"},
    ]]}
    cat = _cat([_project(webhook=webhook)], make_catalog)
    assert rule.check(cat)[0].passed is True


def test_pr_without_actor_fails(make_catalog):
    webhook = {"filterGroups": [[
        {"type": "EVENT", "pattern": "PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED"},
    ]]}
    cat = _cat([_project(webhook=webhook)], make_catalog)
    assert rule.check(cat)[0].passed is False


def test_pr_with_actor_passes(make_catalog):
    webhook = {"filterGroups": [[
        {"type": "EVENT", "pattern": "PULL_REQUEST_CREATED"},
        {"type": "ACTOR_ACCOUNT_ID", "pattern": "1234567"},
    ]]}
    cat = _cat([_project(webhook=webhook)], make_catalog)
    assert rule.check(cat)[0].passed is True


def test_mixed_groups_fail_if_any_pr_group_lacks_actor(make_catalog):
    webhook = {"filterGroups": [
        # group 0 — push, no actor (OK)
        [{"type": "EVENT", "pattern": "PUSH"}],
        # group 1 — PR without actor (FAIL)
        [{"type": "EVENT", "pattern": "PULL_REQUEST_UPDATED"}],
    ]}
    cat = _cat([_project(webhook=webhook)], make_catalog)
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "[1]" in f.description
