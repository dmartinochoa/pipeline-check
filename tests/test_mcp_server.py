"""Tests for the MCP server.

Two layers:

1. Tool functions in ``pipeline_check.mcp_server.tools`` — pure
   functions, return JSON-serializable dicts. Tested by direct
   invocation; no MCP loop needed.
2. Server harness in ``pipeline_check.mcp_server.server`` — binds
   the tool functions to MCP request types. Tested by driving the
   registered handlers with synthetic ``ListToolsRequest`` /
   ``CallToolRequest`` instances, again no stdio loop.

The MCP SDK is an optional extra. Tests skip the harness layer
when it isn't importable, but the tools layer (the bulk of the
logic) always runs.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from pipeline_check.mcp_server import tools as _tools

# The harness layer (``server_app`` + the MCP types) is only used by
# ``TestServerRegistration``. Importing it conditionally lets the
# bulk of this file (the tools-layer tests, ten classes) run on a
# bare install that doesn't carry the optional ``[mcp]`` extra.
#
# ImportError / ModuleNotFoundError is the only legitimate skip
# trigger (extra not installed). Any other exception coming out of
# ``pipeline_check.mcp_server.server`` (TypeError on a decorator
# signature change, AttributeError on a renamed symbol, etc.) is a
# real scanner-side bug; letting it raise here surfaces the bug
# instead of hiding it behind a quiet skip.
try:
    import mcp.types as mcp_types

    from pipeline_check.mcp_server.server import server_app
    _HAS_MCP = True
except (ImportError, ModuleNotFoundError):  # pragma: no cover - environment-dependent
    _HAS_MCP = False
    mcp_types = None  # type: ignore[assignment]
    server_app = None  # type: ignore[assignment]

GITLAB_FIXTURE = Path(
    "tests/fixtures/workflows/gitlab/insecure.gitlab-ci.yml"
)


# ── tools layer ─────────────────────────────────────────────────────


class TestToolListProviders:
    def test_returns_every_supported_provider(self):
        out = _tools.list_providers()
        names = {p["name"] for p in out["providers"]}
        # Everything pipeline-check supports today.
        for required in (
            "github", "gitlab", "drone", "argo", "argocd", "tekton",
            "buildkite", "kubernetes", "aws", "oci",
            "npm", "pypi", "maven", "scm",
        ):
            assert required in names

    def test_aws_has_no_path_kwarg(self):
        out = _tools.list_providers()
        aws = next(p for p in out["providers"] if p["name"] == "aws")
        assert aws["requires_path"] is False
        assert aws["path_kwarg"] is None

    def test_scm_has_no_path_kwarg(self):
        # ``scm`` is the second path-less provider, the MCP wrapper
        # translates the agent-supplied ``scm_platform`` / ``scm_repo``
        # into Scanner kwargs internally.
        out = _tools.list_providers()
        scm = next(p for p in out["providers"] if p["name"] == "scm")
        assert scm["requires_path"] is False
        assert scm["path_kwarg"] is None

    def test_path_providers_advertise_correct_kwarg(self):
        out = _tools.list_providers()
        gha = next(p for p in out["providers"] if p["name"] == "github")
        assert gha["requires_path"] is True
        assert gha["path_kwarg"] == "gha_path"

    def test_parity_with_rule_registry(self):
        # Lock the MCP provider list to ``scripts/gen_provider_docs.py``'s
        # ``SUPPORTED_PROVIDERS``, the canonical provider registry. Any
        # provider added there must show up in the MCP catalog (and the
        # ``_RULES_FQN`` lookup); the original test only checked a
        # hand-picked subset, so argocd / maven / npm / pypi / scm could
        # silently fall out of sync. This guard fails the moment a new
        # provider lands without an MCP wiring.
        from scripts.gen_provider_docs import SUPPORTED_PROVIDERS

        expected = set(SUPPORTED_PROVIDERS.keys())
        advertised = {p["name"] for p in _tools.list_providers()["providers"]}
        missing = expected - advertised
        extra = advertised - expected
        assert not missing, (
            f"MCP catalog missing providers from SUPPORTED_PROVIDERS: "
            f"{sorted(missing)}. Add them to ``_PROVIDER_PATH_KW`` and "
            f"``_RULES_FQN`` in pipeline_check/mcp_server/tools.py."
        )
        assert not extra, (
            f"MCP advertises providers not in SUPPORTED_PROVIDERS: "
            f"{sorted(extra)}. Either remove them from ``_PROVIDER_PATH_KW`` "
            f"or wire them into scripts/gen_provider_docs.py."
        )

    def test_rules_fqn_parity_with_path_kw(self):
        # ``_PROVIDER_PATH_KW`` (used by scan/inventory) and
        # ``_RULES_FQN`` (used by list_checks/explain_check) must agree:
        # a provider in one but not the other is a half-wired addition
        # that fails the moment an agent asks ``list_checks(provider=X)``.
        assert set(_tools._PROVIDER_PATH_KW) == set(_tools._RULES_FQN)

    def test_rules_fqn_derived_from_filesystem(self):
        # ``_RULES_FQN`` is derived from the on-disk ``rules/`` packages
        # (no longer a hand-maintained list). A broken glob (e.g. a moved
        # package dir) would silently empty it and take ``list_checks``
        # down with it, so guard the derivation: non-empty, the core
        # providers present, and FQNs shaped correctly.
        fqns = _tools._RULES_FQN
        assert len(fqns) >= 30
        for core in ("github", "gitlab", "terraform", "aws", "npm"):
            assert fqns.get(core) == f"pipeline_check.core.checks.{core}.rules"


class TestToolListChecks:
    def test_unfiltered_lists_every_provider(self):
        out = _tools.list_checks()
        # Should be > 300 with the current catalog; just sanity-check
        # the floor so this test doesn't churn on every rule add.
        assert out["count"] > 300
        providers_in_output = {c["provider"] for c in out["checks"]}
        # At minimum a couple of providers we always ship.
        assert "github" in providers_in_output
        assert "gitlab" in providers_in_output

    def test_provider_filter_scopes_correctly(self):
        out = _tools.list_checks(provider="drone")
        providers = {c["provider"] for c in out["checks"]}
        assert providers == {"drone"}
        # Drone's catalog is at least 11 (DR-001..DR-011).
        assert out["count"] >= 11

    def test_unknown_provider_raises_valueerror(self):
        with pytest.raises(ValueError, match="unknown provider"):
            _tools.list_checks(provider="not-real")


class TestToolExplainCheck:
    def test_known_check_returns_full_record(self):
        out = _tools.explain_check("GHA-001")
        assert out["id"] == "GHA-001"
        assert out["provider"] == "github"
        assert out["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        # Every rule must carry a recommendation + docs_note.
        assert out["recommendation"]
        assert out["docs_note"]

    def test_lowercase_id_is_accepted(self):
        out = _tools.explain_check("gha-001")
        assert out["id"] == "GHA-001"

    def test_unknown_id_raises(self):
        with pytest.raises(ValueError, match="unknown check id"):
            _tools.explain_check("NOPE-999")


class TestToolListChains:
    def test_returns_chain_summaries(self):
        out = _tools.list_chains()
        assert out["count"] >= 1
        for c in out["chains"]:
            assert c["id"]
            assert c["title"]
            assert c["severity"] in (
                "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
            )


class TestToolExplainChain:
    def test_returns_full_chain_metadata(self):
        out = _tools.explain_chain("AC-001")
        assert out["id"] == "AC-001"
        assert out["mitre_attack"], "AC-001 should carry MITRE techniques"
        assert out["triggering_check_ids"]
        assert out["recommendation"]

    def test_unknown_chain_raises(self):
        with pytest.raises(ValueError, match="unknown chain id"):
            _tools.explain_chain("XX-999")


class TestToolListStandards:
    def test_returns_every_registered_standard(self):
        out = _tools.list_standards()
        names = {s["name"] for s in out["standards"]}
        for required in (
            "owasp_cicd_top_10", "slsa", "nist_ssdf", "soc2",
            "pci_dss_v4", "openssf_scorecard",
        ):
            assert required in names


class TestToolScan:
    def test_scan_emits_findings_with_stride_codes(self):
        out = _tools.scan(
            provider="gitlab", path=str(GITLAB_FIXTURE),
        )
        assert out["provider"] == "gitlab"
        assert out["summary"]["total"] > 0
        assert out["summary"]["failed"] > 0
        # Each finding gets at least one STRIDE code attached.
        sample = out["findings"][0]
        assert sample["stride"]
        assert sample["stride"][0] in ("S", "T", "R", "I", "D", "E")

    def test_scan_score_field_shape(self):
        out = _tools.scan(
            provider="gitlab", path=str(GITLAB_FIXTURE),
        )
        score = out["score"]
        assert "grade" in score
        assert "score" in score

    def test_scan_severity_threshold_filter(self):
        unfiltered = _tools.scan(
            provider="gitlab", path=str(GITLAB_FIXTURE),
        )
        high_only = _tools.scan(
            provider="gitlab", path=str(GITLAB_FIXTURE),
            severity_threshold="HIGH",
        )
        assert high_only["summary"]["total"] < unfiltered["summary"]["total"]
        # Every kept finding must be at least HIGH severity.
        for f in high_only["findings"]:
            assert f["severity"] in ("CRITICAL", "HIGH")

    def test_scan_check_filter(self):
        out = _tools.scan(
            provider="gitlab", path=str(GITLAB_FIXTURE),
            checks=["GL-001"],
        )
        # Only GL-001 should fire when the check filter is set.
        ids = {f["check_id"] for f in out["findings"]}
        assert ids == {"GL-001"}

    def test_scan_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="unknown provider"):
            _tools.scan(provider="bogus", path=str(GITLAB_FIXTURE))

    def test_scan_missing_path_raises(self):
        with pytest.raises(ValueError, match="requires a path"):
            _tools.scan(provider="gitlab", path=None)

    def test_scan_nonexistent_path_raises(self, tmp_path, monkeypatch):
        # Whitelist tmp_path so the scan-root guard doesn't intercept
        # first. The point of this test is the ``path does not exist``
        # arm of ``_provider_kwarg``.
        monkeypatch.setenv("PIPELINE_CHECK_MCP_SCAN_ROOTS", str(tmp_path))
        missing = tmp_path / "missing.yml"
        with pytest.raises(ValueError, match="path does not exist"):
            _tools.scan(provider="gitlab", path=str(missing))

    def test_scan_path_outside_scan_root_raises(self, tmp_path, monkeypatch):
        # An untrusted MCP client can pass any path. The server bounds
        # paths to its configured scan root(s) (cwd by default; opt-in
        # widening via PIPELINE_CHECK_MCP_SCAN_ROOTS) so a request
        # for ``/etc/passwd`` or a sibling repo gets rejected.
        monkeypatch.setenv("PIPELINE_CHECK_MCP_SCAN_ROOTS", str(tmp_path))
        outside = tmp_path.parent / "elsewhere.yml"
        with pytest.raises(ValueError, match="outside the MCP server"):
            _tools.scan(provider="gitlab", path=str(outside))


class TestToolScanSCM:
    def test_scm_missing_platform_raises(self):
        with pytest.raises(ValueError, match="requires scm_platform"):
            _tools.scan(provider="scm")

    def test_scm_missing_repo_raises(self):
        with pytest.raises(ValueError, match="requires scm_repo"):
            _tools.scan(provider="scm", scm_platform="github")

    def test_scm_malformed_repo_raises(self):
        with pytest.raises(ValueError, match="owner/name"):
            _tools.scan(
                provider="scm",
                scm_platform="github",
                scm_repo="just-a-name-no-slash",
            )


class TestToolScanPRDiff:
    def test_aws_rejected(self):
        with pytest.raises(ValueError, match="no local BASE ref"):
            _tools.scan_pr_diff(provider="aws", base_ref="HEAD~1")

    def test_scm_rejected(self):
        with pytest.raises(ValueError, match="no local BASE ref"):
            _tools.scan_pr_diff(provider="scm", base_ref="HEAD~1")

    def test_unresolvable_ref_degrades_gracefully(self):
        # An unresolvable base ref must produce *some* output (every
        # HEAD finding shows up as ``introduced``) plus a warning,
        # mirroring the CLI ``--pr-diff`` contract. We deliberately
        # don't spin up a real git repo here, the goal is to verify
        # the MCP wrapper preserves the degraded-mode contract from
        # ``run_pr_diff`` rather than re-test pr_diff itself. The
        # default scan root is cwd (the project root under pytest), so
        # the GITLAB_FIXTURE under tests/ resolves cleanly.
        out = _tools.scan_pr_diff(
            provider="gitlab",
            base_ref="refs/heads/nonexistent-base-ref-for-mcp-test",
            path=str(GITLAB_FIXTURE),
        )
        assert out["provider"] == "gitlab"
        # Markdown is always populated.
        assert out["markdown"]
        # The base ref didn't resolve, so every HEAD finding is
        # introduced and there's at least one warning explaining why.
        assert out["warnings"]
        assert out["summary"]["resolved"] == 0
        assert out["summary"]["preserved"] == 0


class TestToolInventory:
    def test_returns_components(self):
        out = _tools.inventory(
            provider="gitlab", path=str(GITLAB_FIXTURE),
        )
        assert out["provider"] == "gitlab"
        assert out["count"] >= 1
        assert out["components"][0]["provider"] == "gitlab"


class TestToolThreatModel:
    def test_returns_markdown_document(self):
        out = _tools.threat_model(
            provider="gitlab", path=str(GITLAB_FIXTURE),
        )
        # The markdown reporter always emits these section headers.
        assert "# Threat Model" in out["markdown"]
        assert "## STRIDE analysis" in out["markdown"]
        assert out["summary"]["grade"] in ("A", "B", "C", "D")


class TestToolScanMarkdown:
    def test_returns_markdown_summary(self):
        out = _tools.scan_markdown(
            provider="gitlab", path=str(GITLAB_FIXTURE),
        )
        # Markdown reporter always emits the H1.
        assert "# Pipeline Security Report" in out["markdown"]
        # Summary block includes total / failed / passed counts.
        assert out["summary"]["total"] > 0
        assert out["summary"]["failed"] >= 0

    def test_carries_attack_chains_when_present(self):
        # The GitLab insecure fixture matches at least one
        # AC- chain; scan_markdown should carry it into the
        # rendered output so PR comments don't hide the chain
        # narrative.
        out = _tools.scan_markdown(
            provider="gitlab", path=str(GITLAB_FIXTURE),
        )
        # Existence of an Attack Chains section is conditional on
        # whether any chain matched. Either it's there with the
        # chain header, or the fixture currently doesn't trip a
        # GitLab chain. Both are valid.
        if "Attack Chains" in out["markdown"]:
            assert "AC-" in out["markdown"] or "XPC-" in out["markdown"]


class TestToolRegistry:
    def test_get_tool_fn_resolves_known_name(self):
        fn = _tools.get_tool_fn("list_providers")
        assert callable(fn)

    def test_get_tool_fn_unknown_raises(self):
        with pytest.raises(KeyError):
            _tools.get_tool_fn("nope")

    def test_every_spec_carries_required_fields(self):
        for spec in _tools.TOOL_SPECS:
            assert spec["name"]
            assert spec["description"]
            assert spec["input_schema"]["type"] == "object"
            assert callable(spec["fn"])


# ── analyze_manifest (snippet-in-text) ──────────────────────────────

_GHA_SNIPPET = (
    "name: x\n"
    "on: pull_request_target\n"
    "jobs:\n"
    "  a:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: echo ${{ github.event.pull_request.title }}\n"
)
_DOCKERFILE_SNIPPET = "FROM ubuntu:latest\nRUN curl http://x | bash\n"


class TestAnalyzeManifest:
    def test_explicit_provider_scans_text(self):
        out = _tools.analyze_manifest(_GHA_SNIPPET, provider="github")
        assert out["provider"] == "github"
        assert out["detected"] is False
        assert out["summary"]["failed"] > 0

    def test_temp_path_is_stripped_from_resource(self):
        out = _tools.analyze_manifest(_GHA_SNIPPET, provider="github")
        # No throwaway temp prefix leaks into the reported resource.
        for f in out["findings"]:
            assert "pc-snippet-" not in f["resource"]
            assert not f["resource"].startswith("/")
        assert out["findings"][0]["resource"] == ".github/workflows/snippet.yml"

    def test_sniffs_dockerfile_from_content(self):
        out = _tools.analyze_manifest(_DOCKERFILE_SNIPPET)
        assert out["provider"] == "dockerfile"
        assert out["detected"] is True

    def test_sniffs_kubernetes_from_content(self):
        k8s = (
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n"
            "    - name: c\n      image: nginx\n"
            "      securityContext:\n        privileged: true\n"
        )
        out = _tools.analyze_manifest(k8s)
        assert out["provider"] == "kubernetes"

    def test_filename_hint_selects_provider(self):
        out = _tools.analyze_manifest(
            "build:\n  script:\n    - echo hi\n", filename=".gitlab-ci.yml",
        )
        assert out["provider"] == "gitlab"

    def test_ambiguous_snippet_raises_with_provider_list(self):
        with pytest.raises(ValueError, match="could not determine the provider"):
            _tools.analyze_manifest("foo:\n  bar: baz\n")

    def test_empty_content_raises(self):
        with pytest.raises(ValueError, match="empty"):
            _tools.analyze_manifest("   ")

    def test_live_provider_not_snippet_analyzable(self):
        # ``aws`` / ``scm`` have no single-file form and aren't offered.
        assert "aws" not in _tools.SNIPPET_PROVIDERS
        assert "scm" not in _tools.SNIPPET_PROVIDERS
        with pytest.raises(ValueError, match="does not support snippet"):
            _tools.analyze_manifest("x: 1\n", provider="aws")

    def test_severity_threshold_filters(self):
        full = _tools.analyze_manifest(_GHA_SNIPPET, provider="github")
        high = _tools.analyze_manifest(
            _GHA_SNIPPET, provider="github", severity_threshold="HIGH",
        )
        assert high["summary"]["total"] <= full["summary"]["total"]
        for f in high["findings"]:
            assert f["severity"] in ("CRITICAL", "HIGH")

    def test_registered_as_a_tool(self):
        names = {s["name"] for s in _tools.TOOL_SPECS}
        assert "analyze_manifest" in names
        fn = _tools.get_tool_fn("analyze_manifest")
        out = fn(content=_DOCKERFILE_SNIPPET)
        assert out["provider"] == "dockerfile"


# ── server harness layer ────────────────────────────────────────────


def _drive(handler, request):
    """Run an MCP handler synchronously for test convenience.

    Always uses a fresh event loop, ``asyncio.get_event_loop()``
    on Python 3.12+ raises when no loop is running, and pytest-
    sync test functions never have one.
    """
    return asyncio.new_event_loop().run_until_complete(handler(request))


@pytest.mark.skipif(not _HAS_MCP, reason="mcp SDK not installed")
class TestServerRegistration:
    def test_list_tools_handler_returns_every_spec(self):
        server = server_app()
        handler = server.request_handlers[mcp_types.ListToolsRequest]
        req = mcp_types.ListToolsRequest(method="tools/list")
        result = _drive(handler, req)
        names = {t.name for t in result.root.tools}
        assert names == {spec["name"] for spec in _tools.TOOL_SPECS}

    def test_call_tool_list_providers(self):
        server = server_app()
        handler = server.request_handlers[mcp_types.CallToolRequest]
        req = mcp_types.CallToolRequest(
            method="tools/call",
            params=mcp_types.CallToolRequestParams(
                name="list_providers", arguments={},
            ),
        )
        result = _drive(handler, req)
        payload = json.loads(result.root.content[0].text)
        assert payload["providers"]

    def test_call_tool_unknown_returns_error_payload(self):
        server = server_app()
        handler = server.request_handlers[mcp_types.CallToolRequest]
        req = mcp_types.CallToolRequest(
            method="tools/call",
            params=mcp_types.CallToolRequestParams(
                name="explain_check",
                arguments={"check_id": "NOPE-999"},
            ),
        )
        result = _drive(handler, req)
        payload = json.loads(result.root.content[0].text)
        assert "error" in payload
        assert "unknown check id" in payload["error"]

    def test_call_tool_scan_returns_findings(self):
        server = server_app()
        handler = server.request_handlers[mcp_types.CallToolRequest]
        req = mcp_types.CallToolRequest(
            method="tools/call",
            params=mcp_types.CallToolRequestParams(
                name="scan",
                arguments={
                    "provider": "gitlab",
                    "path": str(GITLAB_FIXTURE),
                    "severity_threshold": "CRITICAL",
                },
            ),
        )
        result = _drive(handler, req)
        payload = json.loads(result.root.content[0].text)
        # Only CRITICAL findings should survive the threshold.
        for f in payload["findings"]:
            assert f["severity"] == "CRITICAL"
        assert payload["score"]["grade"] in ("A", "B", "C", "D")
