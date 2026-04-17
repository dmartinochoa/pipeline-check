"""CB-009 — image digest pinning."""
from __future__ import annotations

from pipeline_check.core.checks.aws.rules import cb009_image_not_digest as rule
from tests.aws.rules.conftest import FakeClient


def _project(name="p", image=""):
    return {"name": name, "environment": {"image": image}}


def _cat(projects, make_catalog):
    client = FakeClient(batch_get_projects={"projects": projects})
    client.set_paginator("list_projects", [{"projects": [p["name"] for p in projects]}])
    return make_catalog(codebuild=client)


def test_aws_managed_image_passes(make_catalog):
    cat = _cat([_project(image="aws/codebuild/standard:7.0")], make_catalog)
    assert rule.check(cat)[0].passed is True


def test_digest_pinned_passes(make_catalog):
    digest = "@sha256:" + "a" * 64
    cat = _cat([_project(image=f"ghcr.io/org/img{digest}")], make_catalog)
    assert rule.check(cat)[0].passed is True


def test_tag_only_fails(make_catalog):
    cat = _cat([_project(image="ghcr.io/org/img:v1")], make_catalog)
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "tag-pinned" in f.description


def test_latest_fails(make_catalog):
    cat = _cat([_project(image="docker.io/library/node:latest")], make_catalog)
    assert rule.check(cat)[0].passed is False
