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

# The harness import is conditional, the suite still passes on a
# bare install that doesn't have ``mcp`` available.
mcp = pytest.importorskip("mcp", reason="mcp SDK not installed")
import mcp.types as mcp_types  # noqa: E402

from pipeline_check.mcp_server.server import server_app  # noqa: E402

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
            "github", "gitlab", "drone", "argo", "tekton",
            "buildkite", "kubernetes", "aws", "oci",
        ):
            assert required in names

    def test_aws_has_no_path_kwarg(self):
        out = _tools.list_providers()
        aws = next(p for p in out["providers"] if p["name"] == "aws")
        assert aws["requires_path"] is False
        assert aws["path_kwarg"] is None

    def test_path_providers_advertise_correct_kwarg(self):
        out = _tools.list_providers()
        gha = next(p for p in out["providers"] if p["name"] == "github")
        assert gha["requires_path"] is True
        assert gha["path_kwarg"] == "gha_path"


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

    def test_scan_nonexistent_path_raises(self):
        with pytest.raises(ValueError, match="path does not exist"):
            _tools.scan(provider="gitlab", path="/nope/missing.yml")


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


# ── server harness layer ────────────────────────────────────────────


def _drive(handler, request):
    """Run an MCP handler synchronously for test convenience.

    Always uses a fresh event loop, ``asyncio.get_event_loop()``
    on Python 3.12+ raises when no loop is running, and pytest-
    sync test functions never have one.
    """
    return asyncio.new_event_loop().run_until_complete(handler(request))


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
