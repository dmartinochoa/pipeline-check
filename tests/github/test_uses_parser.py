"""Per-shape tests for the canonical ``uses:`` parser."""
from __future__ import annotations

import pytest

from pipeline_check.core.checks.github.uses_parser import parse_uses


class TestParseUses:
    @pytest.mark.parametrize("raw,kind,owner,repo,path,ref", [
        # Remote action with semver tag.
        ("actions/checkout@v4", "remote-action", "actions", "checkout", "", "v4"),
        # Remote action pinned to SHA.
        (
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
            "remote-action",
            "actions", "checkout", "",
            "b4ffde65f46336ab88eb53be808477a3936bae11",
        ),
        # Remote action with a subpath (e.g. /lib).
        (
            "actions/setup-node/lib@v4",
            "remote-action",
            "actions", "setup-node", "lib", "v4",
        ),
        # Remote reusable workflow.
        (
            "myorg/shared/.github/workflows/release.yml@v1",
            "remote-workflow",
            "myorg", "shared", ".github/workflows/release.yml", "v1",
        ),
        # Remote reusable workflow with .yaml extension.
        (
            "myorg/shared/.github/workflows/release.yaml@v1",
            "remote-workflow",
            "myorg", "shared", ".github/workflows/release.yaml", "v1",
        ),
    ])
    def test_remote_shapes(self, raw, kind, owner, repo, path, ref):
        u = parse_uses(raw)
        assert u is not None
        assert u.kind == kind
        assert u.owner == owner
        assert u.repo == repo
        assert u.path == path
        assert u.ref == ref

    def test_local_action(self):
        u = parse_uses("./.github/actions/build")
        assert u is not None
        assert u.kind == "local-action"
        assert u.path == "./.github/actions/build"

    def test_local_reusable_workflow(self):
        u = parse_uses("./.github/workflows/release.yml")
        assert u is not None
        assert u.kind == "local-workflow"
        assert u.path == "./.github/workflows/release.yml"

    def test_docker_image(self):
        u = parse_uses("docker://ghcr.io/foo/bar:1.2.3")
        assert u is not None
        assert u.kind == "docker"

    def test_returns_none_for_non_string(self):
        assert parse_uses(None) is None
        assert parse_uses({"foo": "bar"}) is None
        assert parse_uses(123) is None
        assert parse_uses("") is None

    def test_returns_none_for_remote_without_at(self):
        # Without an ``@``, we can't distinguish a remote ref from a
        # malformed string; the parser returns None and rules ignore
        # it the same way they ignore docker refs.
        assert parse_uses("actions/checkout") is None

    def test_is_pinned_to_sha(self):
        sha = "b4ffde65f46336ab88eb53be808477a3936bae11"
        assert parse_uses(f"actions/checkout@{sha}").is_pinned_to_sha
        assert not parse_uses("actions/checkout@v4").is_pinned_to_sha
        assert not parse_uses("actions/checkout@main").is_pinned_to_sha
