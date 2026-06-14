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


_HOOKS_PATH = f"{_GROUP_PATH}/hooks"
_VARS_PATH = f"{_GROUP_PATH}/variables"

# A fake but catalog-matching GitLab PAT shape (gitlab_pat detector).
_SECRET = "glpat-ABCDEFGHIJ1234567890"


def _ctx(
    group_meta: dict | None,
    hooks: list | None = None,
    variables: list | None = None,
) -> GitLabGroupContext:
    mapping: dict[str, Any] = {}
    if group_meta is not None:
        mapping[_GROUP_PATH] = group_meta
    if hooks is not None:
        mapping[_HOOKS_PATH] = hooks
    if variables is not None:
        mapping[_VARS_PATH] = variables
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


class TestGLGRP003SharingOutsideHierarchy:
    def test_metadata(self):
        f = _for(_findings(_ctx({})), "GLGRP-003")[0]
        assert f.check_id == "GLGRP-003"
        assert f.severity == Severity.MEDIUM

    def test_fails_when_sharing_outside_allowed(self):
        f = _for(_findings(_ctx({"prevent_sharing_groups_outside_hierarchy": False})), "GLGRP-003")[0]
        assert not f.passed

    def test_passes_when_sharing_outside_prevented(self):
        f = _for(_findings(_ctx({"prevent_sharing_groups_outside_hierarchy": True})), "GLGRP-003")[0]
        assert f.passed

    def test_passes_when_field_absent(self):
        f = _for(_findings(_ctx({"id": 1})), "GLGRP-003")[0]
        assert f.passed

    def test_passes_when_group_unavailable(self):
        f = _for(_findings(_ctx(None)), "GLGRP-003")[0]
        assert f.passed


class TestGLGRP004DefaultBranchProtection:
    def test_metadata(self):
        f = _for(_findings(_ctx({})), "GLGRP-004")[0]
        assert f.check_id == "GLGRP-004"
        assert f.severity == Severity.MEDIUM

    def test_fails_when_not_protected(self):
        f = _for(_findings(_ctx({"default_branch_protection": 0})), "GLGRP-004")[0]
        assert not f.passed

    def test_passes_when_partially_protected(self):
        f = _for(_findings(_ctx({"default_branch_protection": 1})), "GLGRP-004")[0]
        assert f.passed

    def test_passes_when_fully_protected(self):
        f = _for(_findings(_ctx({"default_branch_protection": 2})), "GLGRP-004")[0]
        assert f.passed

    def test_passes_when_only_newer_dict_form(self):
        # GitLab migrating to default_branch_protection_defaults: the integer
        # is absent -> conservative pass-with-note, no guess at the object.
        ctx = _ctx({"default_branch_protection_defaults": {"allow_force_push": True}})
        f = _for(_findings(ctx), "GLGRP-004")[0]
        assert f.passed

    def test_passes_when_group_unavailable(self):
        f = _for(_findings(_ctx(None)), "GLGRP-004")[0]
        assert f.passed


class TestGLGRP005WebhookTransport:
    def test_metadata(self):
        f = _for(_findings(_ctx({}, hooks=[])), "GLGRP-005")[0]
        assert f.check_id == "GLGRP-005"
        assert f.severity == Severity.HIGH

    def test_fails_on_http_url(self):
        hooks = [{"id": 7, "url": "http://hooks.example.com/gl"}]
        f = _for(_findings(_ctx({}, hooks=hooks)), "GLGRP-005")[0]
        assert not f.passed
        assert "http://hooks.example.com/gl" in f.description

    def test_fails_on_https_with_ssl_verification_off(self):
        hooks = [{"id": 8, "url": "https://hooks.example.com/gl",
                  "enable_ssl_verification": False}]
        f = _for(_findings(_ctx({}, hooks=hooks)), "GLGRP-005")[0]
        assert not f.passed
        assert "SSL verification disabled" in f.description

    def test_passes_on_https_with_ssl_verification_on(self):
        hooks = [{"id": 9, "url": "https://hooks.example.com/gl",
                  "enable_ssl_verification": True}]
        f = _for(_findings(_ctx({}, hooks=hooks)), "GLGRP-005")[0]
        assert f.passed

    def test_http_url_does_not_double_report_ssl(self):
        # An http:// endpoint has no TLS to verify; only the plain-HTTP
        # label should appear, not an SSL-verification one.
        hooks = [{"id": 10, "url": "http://hooks.example.com/gl",
                  "enable_ssl_verification": False}]
        f = _for(_findings(_ctx({}, hooks=hooks)), "GLGRP-005")[0]
        assert not f.passed
        assert "plain-HTTP URL" in f.description
        assert "SSL verification disabled" not in f.description

    def test_passes_when_no_hooks(self):
        f = _for(_findings(_ctx({}, hooks=[])), "GLGRP-005")[0]
        assert f.passed

    def test_passes_when_hooks_unavailable(self):
        # No hooks endpoint in the fetcher map -> slot is None -> not
        # evaluated (pass with a note), no false finding on absence.
        f = _for(_findings(_ctx({"id": 1})), "GLGRP-005")[0]
        assert f.passed
        assert "not evaluated" in f.description

    def test_counts_multiple_offenders(self):
        hooks = [
            {"id": 1, "url": "http://a.example.com/x"},
            {"id": 2, "url": "https://b.example.com/x",
             "enable_ssl_verification": False},
            {"id": 3, "url": "https://c.example.com/x",
             "enable_ssl_verification": True},
        ]
        f = _for(_findings(_ctx({}, hooks=hooks)), "GLGRP-005")[0]
        assert not f.passed
        assert "2 webhook(s)" in f.description

    def test_hooks_endpoint_fetched(self):
        fetcher = FakeFetcher({_GROUP_PATH: {"id": 1}, _HOOKS_PATH: []})
        ctx = GitLabGroupContext.for_group(_GROUP, fetcher)
        assert ctx.group_hooks == []
        assert _HOOKS_PATH in fetcher.calls
        assert ctx.files_scanned == 1


class TestGLGRP006SecretVariableWeakProtection:
    def _var(self, **kw):
        base = {"key": "DEPLOY_TOKEN", "value": _SECRET,
                "protected": True, "masked": True}
        base.update(kw)
        return base

    def test_metadata(self):
        f = _for(_findings(_ctx({}, variables=[])), "GLGRP-006")[0]
        assert f.check_id == "GLGRP-006"
        assert f.severity == Severity.HIGH

    def test_fails_secret_not_protected(self):
        f = _for(_findings(_ctx({}, variables=[self._var(protected=False)])),
                 "GLGRP-006")[0]
        assert not f.passed
        assert "DEPLOY_TOKEN" in f.description
        assert "not protected" in f.description
        # the detector label, never the raw value, is surfaced
        assert "gitlab_pat" in f.description
        assert _SECRET not in f.description

    def test_fails_secret_not_masked(self):
        f = _for(_findings(_ctx({}, variables=[self._var(masked=False)])),
                 "GLGRP-006")[0]
        assert not f.passed
        assert "not masked" in f.description

    def test_passes_secret_protected_and_masked(self):
        f = _for(_findings(_ctx({}, variables=[self._var()])), "GLGRP-006")[0]
        assert f.passed

    def test_passes_non_secret_value_even_if_unprotected(self):
        # An ordinary unprotected config var must not be flagged: the
        # value-shape gate is what keeps this rule low-FP.
        var = {"key": "REGISTRY_URL", "value": "https://reg.example.com",
               "protected": False, "masked": False}
        f = _for(_findings(_ctx({}, variables=[var])), "GLGRP-006")[0]
        assert f.passed

    def test_passes_when_flags_absent(self):
        # Neither protected nor masked present -> can't assess -> no FP.
        var = {"key": "TOK", "value": _SECRET}
        f = _for(_findings(_ctx({}, variables=[var])), "GLGRP-006")[0]
        assert f.passed

    def test_passes_when_no_variables(self):
        f = _for(_findings(_ctx({}, variables=[])), "GLGRP-006")[0]
        assert f.passed

    def test_passes_when_variables_unavailable(self):
        f = _for(_findings(_ctx({"id": 1})), "GLGRP-006")[0]
        assert f.passed
        assert "not evaluated" in f.description

    def test_counts_multiple_offenders(self):
        variables = [
            self._var(key="A", protected=False),
            self._var(key="B", masked=False),
            self._var(key="C"),  # protected + masked -> safe
            {"key": "D", "value": "plain-text", "protected": False,
             "masked": False},  # not a secret -> safe
        ]
        f = _for(_findings(_ctx({}, variables=variables)), "GLGRP-006")[0]
        assert not f.passed
        assert "2 CI/CD variable(s)" in f.description

    def test_variables_endpoint_fetched(self):
        fetcher = FakeFetcher({_GROUP_PATH: {"id": 1}, _VARS_PATH: []})
        ctx = GitLabGroupContext.for_group(_GROUP, fetcher)
        assert ctx.group_variables == []
        assert _VARS_PATH in fetcher.calls
        assert ctx.files_scanned == 1
