"""GLGRP-* GitLab group-governance tests (in-memory fetcher, no network)."""
from __future__ import annotations

import urllib.parse
from typing import Any

from pipeline_check.core.checks.base import Severity
from pipeline_check.core.checks.gitlab_group.base import GitLabGroupContext
from pipeline_check.core.checks.gitlab_group.checks import GitLabGroupChecks

_GROUP = "acme"
_GROUP_PATH = f"groups/{urllib.parse.quote(_GROUP, safe='')}"


class FakeFetcher:
    """In-memory ``path -> json`` map; anything else returns ``None``."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.mapping = mapping
        self.calls: list[str] = []

    def fetch(self, path: str) -> Any:
        self.calls.append(path)
        return self.mapping.get(path)


def _ctx(group_meta: dict | None) -> GitLabGroupContext:
    mapping = {_GROUP_PATH: group_meta} if group_meta is not None else {}
    return GitLabGroupContext.for_group(_GROUP, FakeFetcher(mapping))


def _findings(ctx: GitLabGroupContext) -> list:
    return GitLabGroupChecks(ctx).run()


def _for(findings: list, check_id: str) -> list:
    return [f for f in findings if f.check_id == check_id]


class TestContextLoad:
    def test_fetches_group_endpoint(self):
        fetcher = FakeFetcher({_GROUP_PATH: {"id": 1, "full_path": "acme"}})
        ctx = GitLabGroupContext.for_group(_GROUP, fetcher)
        assert ctx.group_meta == {"id": 1, "full_path": "acme"}
        assert ctx.files_scanned == 1
        assert _GROUP_PATH in fetcher.calls

    def test_missing_group_degrades_with_warning(self):
        ctx = _ctx(None)
        assert ctx.group_meta is None
        assert ctx.files_skipped == 1
        assert any("could not fetch" in w for w in ctx.warnings)

    def test_non_dict_payload_degrades(self):
        ctx = GitLabGroupContext.for_group(_GROUP, FakeFetcher({_GROUP_PATH: ["x"]}))
        assert ctx.group_meta is None
        assert ctx.files_skipped == 1

    def test_subgroup_path_is_url_encoded(self):
        sub = "acme/platform"
        enc = f"groups/{urllib.parse.quote(sub, safe='')}"
        fetcher = FakeFetcher({enc: {"id": 2}})
        ctx = GitLabGroupContext.for_group(sub, fetcher)
        assert ctx.group_meta == {"id": 2}
        assert enc in fetcher.calls  # %2F-encoded, not a literal slash


class TestGLGRP001TwoFactor:
    def test_metadata(self):
        f = _for(_findings(_ctx({})), "GLGRP-001")[0]
        assert f.check_id == "GLGRP-001"
        assert f.severity == Severity.HIGH

    def test_fails_when_2fa_not_required(self):
        f = _for(_findings(_ctx({"require_two_factor_authentication": False})), "GLGRP-001")[0]
        assert not f.passed

    def test_passes_when_2fa_required(self):
        f = _for(_findings(_ctx({"require_two_factor_authentication": True})), "GLGRP-001")[0]
        assert f.passed

    def test_passes_when_field_absent(self):
        f = _for(_findings(_ctx({"id": 1})), "GLGRP-001")[0]
        assert f.passed

    def test_passes_when_group_unavailable(self):
        f = _for(_findings(_ctx(None)), "GLGRP-001")[0]
        assert f.passed


class TestGLGRP002ForkingOutsideGroup:
    def test_metadata(self):
        f = _for(_findings(_ctx({})), "GLGRP-002")[0]
        assert f.check_id == "GLGRP-002"
        assert f.severity == Severity.MEDIUM

    def test_fails_when_forking_outside_allowed(self):
        f = _for(_findings(_ctx({"prevent_forking_outside_group": False})), "GLGRP-002")[0]
        assert not f.passed

    def test_passes_when_forking_outside_prevented(self):
        f = _for(_findings(_ctx({"prevent_forking_outside_group": True})), "GLGRP-002")[0]
        assert f.passed

    def test_passes_when_field_absent_free_tier(self):
        # Premium-only field absent on free tier -> pass with note, no FP.
        f = _for(_findings(_ctx({"id": 1})), "GLGRP-002")[0]
        assert f.passed
