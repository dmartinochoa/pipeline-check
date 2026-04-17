"""CB-008 — inline buildspec."""
from __future__ import annotations

from pipeline_check.core.checks.aws.rules import cb008_inline_buildspec as rule
from tests.aws.rules.conftest import FakeClient


def _project(name="p", buildspec=""):
    return {"name": name, "source": {"type": "GITHUB", "buildspec": buildspec}}


def _catalog_with(projects, make_catalog):
    client = FakeClient(batch_get_projects={"projects": projects})
    client.set_paginator("list_projects", [{"projects": [p["name"] for p in projects]}])
    return make_catalog(codebuild=client)


def test_empty_buildspec_passes(make_catalog):
    cat = _catalog_with([_project(buildspec="")], make_catalog)
    findings = rule.check(cat)
    assert findings[0].passed is True


def test_repo_path_passes(make_catalog):
    cat = _catalog_with([_project(buildspec="ci/build.yml")], make_catalog)
    assert rule.check(cat)[0].passed is True


def test_multiline_inline_fails(make_catalog):
    cat = _catalog_with(
        [_project(buildspec="version: 0.2\nphases:\n  build:\n    commands: echo hi")],
        make_catalog,
    )
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "inline YAML" in f.description


def test_s3_arn_fails(make_catalog):
    cat = _catalog_with(
        [_project(buildspec="arn:aws:s3:::my-bucket/buildspec.yml")],
        make_catalog,
    )
    f = rule.check(cat)[0]
    assert f.passed is False
    assert "S3" in f.description


def test_yaml_block_marker_fails(make_catalog):
    cat = _catalog_with([_project(buildspec="version: 0.2")], make_catalog)
    assert rule.check(cat)[0].passed is False
