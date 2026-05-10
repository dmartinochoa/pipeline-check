"""Tests for the SCM fetcher implementations.

The HTTP fetcher isn't unit-tested here (network-dependent and
exercised via integration); the disk fetcher is the production-
relevant offline-mode path so it gets full coverage.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline_check.core.checks.scm.base import DiskSCMFetcher


def test_disk_fetcher_returns_dict_when_file_exists(tmp_path: Path):
    target = tmp_path / "repos_o_r.json"
    target.write_text(json.dumps({"default_branch": "main"}))
    f = DiskSCMFetcher([tmp_path])
    assert f.fetch("repos/o/r") == {"default_branch": "main"}


def test_disk_fetcher_returns_none_when_missing(tmp_path: Path):
    f = DiskSCMFetcher([tmp_path])
    assert f.fetch("repos/o/r") is None


def test_disk_fetcher_collapses_slash_to_underscore(tmp_path: Path):
    """The on-disk filename mirrors the API endpoint with ``/`` ->
    ``_`` so deeply nested endpoints fit a single flat directory."""
    target = tmp_path / "repos_o_r_branches_main_protection.json"
    target.write_text(json.dumps({"required_pull_request_reviews": {}}))
    f = DiskSCMFetcher([tmp_path])
    out = f.fetch("repos/o/r/branches/main/protection")
    assert out == {"required_pull_request_reviews": {}}


def test_disk_fetcher_rejects_path_traversal(tmp_path: Path):
    """An attacker-controlled fixture name with ``..`` segments must
    not escape the search root, even though the fixture-mode flag is
    only meaningful in test environments."""
    f = DiskSCMFetcher([tmp_path])
    # The fetcher collapses slashes to underscores before lookup, so
    # ``../../etc/passwd`` becomes ``..__..__etc_passwd.json``. The
    # path-component validation happens on the post-collapse form.
    assert f.fetch("../../etc/passwd") is None


def test_disk_fetcher_returns_none_on_invalid_json(tmp_path: Path):
    target = tmp_path / "repos_o_r.json"
    target.write_text("{ this is not :: valid")
    f = DiskSCMFetcher([tmp_path])
    assert f.fetch("repos/o/r") is None


def test_disk_fetcher_returns_none_on_non_object_body(tmp_path: Path):
    """Scalar JSON values (a bare number, string, or null) aren't
    valid endpoint responses; fetcher returns None so the rule
    layer treats them as 'unavailable'."""
    target = tmp_path / "repos_o_r.json"
    target.write_text("42")
    f = DiskSCMFetcher([tmp_path])
    assert f.fetch("repos/o/r") is None
